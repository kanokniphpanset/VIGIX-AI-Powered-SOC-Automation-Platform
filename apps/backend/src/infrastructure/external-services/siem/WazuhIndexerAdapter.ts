import https from "node:https";
import fs from "node:fs";
import { URL } from "node:url";
import {
  ISiemRehuntPort,
  RehuntError,
  RehuntEvent,
  RehuntHealth,
  RehuntQuery,
  RehuntResult,
} from "../../../application/verification/ports/ISiemRehuntPort";

export interface WazuhIndexerConfig {
  /** e.g. https://localhost:9200 from the host, https://wazuh.indexer:9200 from inside the Wazuh docker network. */
  url?: string;
  username?: string;
  password?: string;
  /** PEM root CA that signed the indexer certificate (wazuh_indexer_ssl_certs/root-ca.pem). */
  caPath?: string;
  /** Hostname the indexer certificate was issued for, when the connect host differs (e.g. localhost vs wazuh.indexer). */
  tlsServername?: string;
  /** Dev-only escape hatch: skip certificate verification. Prefer caPath. */
  insecureTls?: boolean;
  indexPattern?: string;
  timeoutMs?: number;
  timestampField?: string;
}

export interface IndexerResponse {
  status: number;
  body: unknown;
}

/** Sends one request to the indexer. Injectable so the query/normalization logic is testable without a live cluster. */
export type IndexerTransport = (method: "GET" | "POST", path: string, body?: unknown) => Promise<IndexerResponse>;

const DEFAULT_INDEX_PATTERN = "wazuh-alerts-4.x-*";
const MAX_EVENTS = 20;
const MAX_HOSTS = 100;

const IOC_FIELDS = [
  "full_log",
  "data.srcip",
  "data.dstip",
  "data.url",
  "data.hash",
  "data.md5",
  "data.sha1",
  "data.sha256",
  "data.dns.question.name",
];

/**
 * buildRehuntDsl — turns a RehuntQuery into the indexer search body.
 * A document matches if it EITHER contains one of the IOCs, OR was raised by the
 * original detection's rule — on any host. Both are limited to the post-containment
 * time range. Matches on the incident's own hosts are recurrence; matches on any
 * OTHER host are spread (decided when the result is normalized). Named clauses let
 * the response say which kind of match each event was.
 */
export function buildRehuntDsl(query: RehuntQuery): Record<string, unknown> | null {
  const should: unknown[] = [];

  const iocs = query.iocs.filter((i) => i.value.trim());
  const iocMatches = iocs.map((i) => ({ multi_match: { query: i.value, type: "phrase", fields: IOC_FIELDS, lenient: true } }));
  if (iocs.length > 0) {
    should.push({ bool: { _name: "ioc", should: iocMatches, minimum_should_match: 1 } });
  }

  const ruleClause = query.rule?.id
    ? { term: { "rule.id": query.rule.id } }
    : query.rule?.description
      ? { match_phrase: { "rule.description": query.rule.description } }
      : null;
  if (ruleClause) {
    should.push({ bool: { _name: "rule", filter: [ruleClause] } });
  }

  if (should.length === 0) return null;

  return {
    size: MAX_EVENTS,
    track_total_hits: true,
    sort: [{ "@timestamp": "desc" }],
    _source: ["@timestamp", "agent.name", "agent.id", "rule.id", "rule.level", "rule.description"],
    query: {
      bool: {
        filter: [{ range: { "@timestamp": { gte: query.timeRange.start.toISOString(), lte: query.timeRange.end.toISOString() } } }],
        should,
        minimum_should_match: 1,
      },
    },
    aggs: {
      hosts: { terms: { field: "agent.name", size: MAX_HOSTS } },
      ioc_events: { filter: iocMatches.length > 0 ? { bool: { should: iocMatches, minimum_should_match: 1 } } : { match_none: {} } },
    },
  };
}

interface SearchHit {
  _id: string;
  _source?: {
    [field: string]: unknown;
    "@timestamp"?: string;
    agent?: { name?: string; id?: string };
    rule?: { id?: string; level?: number; description?: string };
  };
  matched_queries?: string[];
}

interface SearchBody {
  hits?: { total?: { value?: number }; hits?: SearchHit[] };
  aggregations?: { hosts?: { buckets?: { key: string }[] }; ioc_events?: { doc_count?: number } };
}

/** An incomplete or failed search is never evidence of containment. */
export function validateSearchResponse(value: unknown): void {
  const b = value as any;
  if (b?.timed_out === true) throw new RehuntError("TIMEOUT", "Wazuh Indexer search timed out.");
  if (!b || b.error || b.timed_out !== false || !Number.isInteger(b._shards?.total) || b._shards.total < 1 ||
      b._shards.failed !== 0 || b._shards.successful !== b._shards.total ||
      !Array.isArray(b.hits?.hits) || !Number.isSafeInteger(b.hits?.total?.value) || b.hits.total.value < 0 ||
      b.hits.total.relation !== "eq" || b.hits.hits.length > b.hits.total.value ||
      (b.hits.total.value > 0 && b.hits.hits.length === 0) ||
      !Array.isArray(b.aggregations?.hosts?.buckets) ||
      !Number.isSafeInteger(b.aggregations?.ioc_events?.doc_count) || b.aggregations.ioc_events.doc_count < 0 ||
      b.aggregations.ioc_events.doc_count > b.hits.total.value ||
      b.aggregations.hosts.buckets.some((h: any) => typeof h?.key !== "string") ||
      b.hits.hits.some((h: any) => typeof h?._id !== "string" || !h._source ||
        (h.matched_queries !== undefined && (!Array.isArray(h.matched_queries) || h.matched_queries.some((q: unknown) => typeof q !== "string"))))) {
    throw new RehuntError("QUERY_FAILED", "Wazuh Indexer returned incomplete or invalid search evidence.");
  }
}

/**
 * WazuhIndexerAdapter — infrastructure. Reads (never writes) the Wazuh Indexer
 * to gather re-hunt EVIDENCE and normalizes it into RehuntResult. Credentials
 * come only from configuration, are sent only as an Authorization header to the
 * configured indexer, and are stripped from any error surfaced to callers.
 */
export class WazuhIndexerAdapter implements ISiemRehuntPort {
  protected readonly indexPattern: string;
  protected readonly transport: IndexerTransport;
  protected readonly timestampField: string;

  constructor(
    private readonly config: WazuhIndexerConfig,
    transport?: IndexerTransport
  ) {
    this.indexPattern = config.indexPattern || DEFAULT_INDEX_PATTERN;
    this.timestampField = config.timestampField || "@timestamp";
    this.transport = transport ?? this.httpsTransport.bind(this);
  }

  isConfigured(): boolean {
    return !!(this.config.url && this.config.username && this.config.password);
  }

  protected buildQuery(query: RehuntQuery): Record<string, unknown> | null {
    return buildRehuntDsl(query);
  }

  protected async prepareQuery(query: RehuntQuery): Promise<Record<string, unknown> | null> {
    return this.buildQuery(query);
  }

  protected eventTimestamp(source: Record<string, unknown>): string {
    return typeof source[this.timestampField] === "string" ? source[this.timestampField] as string : "";
  }

  async health(): Promise<RehuntHealth> {
    const base: RehuntHealth = { configured: this.isConfigured(), reachable: false, indexPattern: this.indexPattern };
    if (!base.configured) return { ...base, error: "Wazuh Indexer is not configured (WAZUH_INDEXER_URL/USERNAME/PASSWORD)." };
    try {
      const cluster = await this.transport("GET", "/_cluster/health");
      if (cluster.status !== 200) return { ...base, error: `Indexer responded ${cluster.status}` };
      const indices = await this.transport("GET", `/_cat/indices/${encodeURIComponent(this.indexPattern)}?format=json&h=index`);
      if (indices.status !== 200 || !Array.isArray(indices.body) || indices.body.length === 0) {
        return { ...base, error: "Wazuh alert indices are unavailable." };
      }
      const list = indices.body;
      const probe = await this.transport("POST", `/${encodeURIComponent(this.indexPattern)}/_search?allow_no_indices=false&ignore_unavailable=false&allow_partial_search_results=false`, {
        size: 0, track_total_hits: true, query: { match_none: {} },
        aggs: { hosts: { terms: { field: "agent.name", size: 1 } }, ioc_events: { filter: { match_none: {} } } },
      });
      if (probe.status !== 200) return { ...base, error: `Indexer search responded ${probe.status}` };
      validateSearchResponse(probe.body);
      return {
        ...base,
        reachable: true,
        clusterStatus: (cluster.body as { status?: string }).status,
        alertIndices: list.length,
      };
    } catch (err) {
      return { ...base, error: "Wazuh Indexer health query failed." };
    }
  }

  async rehunt(query: RehuntQuery): Promise<RehuntResult> {
    if (!this.isConfigured()) throw new RehuntError("NOT_CONFIGURED", "Wazuh Indexer is not configured.");

    const dsl = await this.prepareQuery(query);
    if (!dsl) {
      throw new RehuntError("INSUFFICIENT_CRITERIA", "No IOC and no detection rule are known for this incident — there is nothing to hunt for.");
    }

    let res: IndexerResponse;
    try {
      res = await this.transport("POST", `/${encodeURIComponent(this.indexPattern)}/_search?allow_no_indices=false&ignore_unavailable=false&allow_partial_search_results=false`, dsl);
    } catch (err) {
      if (err instanceof RehuntError) throw err;
      const code = (err as NodeJS.ErrnoException)?.code;
      throw new RehuntError(code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT" ? "TIMEOUT" : "UNREACHABLE", "Wazuh Indexer request failed.");
    }
    if (res.status !== 200) {
      throw new RehuntError("QUERY_FAILED", `Wazuh Indexer responded ${res.status} to the re-hunt query.`);
    }

    validateSearchResponse(res.body);
    const missingTime = (res.body as any)?.aggregations?.missing_timestamp;
    if (dsl.aggs && Object.prototype.hasOwnProperty.call(dsl.aggs, "missing_timestamp") &&
        (!missingTime || missingTime.doc_count !== 0)) {
      throw new RehuntError("QUERY_FAILED", "Matching IOC evidence has missing or unverified timestamps.");
    }
    const body = res.body as SearchBody;
    const hits = body.hits?.hits ?? [];
    const matchingEvents = body.hits?.total?.value ?? hits.length;

    const events: RehuntEvent[] = hits.map((h) => ({
      id: h._id,
      timestamp: this.eventTimestamp(h._source ?? {}),
      host: h._source?.agent?.name ?? null,
      agentId: h._source?.agent?.id ?? null,
      ruleId: h._source?.rule?.id ?? null,
      ruleLevel: h._source?.rule?.level ?? null,
      ruleDescription: h._source?.rule?.description ?? null,
      matchedIoc: (h.matched_queries ?? []).some(n => n === "ioc" || /^ioc_\d+$/.test(n)),
      matchedIocValues: query.iocs.filter((_, i) => (h.matched_queries ?? []).includes(`ioc_${i}`)).map(i => i.value),
    }));

    const affectedHosts = (body.aggregations?.hosts?.buckets ?? []).map((b) => b.key);
    const known = new Set(query.hosts.map((h) => h.toLowerCase()));
    const spreadDetected = affectedHosts.some((h) => !known.has(h.toLowerCase()));
    const iocRecurrence = (body.aggregations?.ioc_events?.doc_count ?? 0) > 0;

    return {
      source: "WAZUH_INDEXER",
      index: this.indexPattern,
      query: JSON.stringify(dsl),
      timeRange: { start: query.timeRange.start.toISOString(), end: query.timeRange.end.toISOString() },
      matchingEvents,
      affectedHosts,
      iocRecurrence,
      spreadDetected,
      threatContained: matchingEvents === 0,
      events,
      truncated: matchingEvents > events.length,
    };
  }

  private httpsTransport(method: "GET" | "POST", path: string, body?: unknown): Promise<IndexerResponse> {
    return new Promise((resolve, reject) => {
      const url = new URL(path, this.config.url);
      const payload = body === undefined ? undefined : JSON.stringify(body);
      const auth = Buffer.from(`${this.config.username}:${this.config.password}`).toString("base64");

      const req = https.request(
        {
          method,
          hostname: url.hostname,
          port: url.port || 443,
          path: url.pathname + url.search,
          headers: {
            Authorization: `Basic ${auth}`,
            Accept: "application/json",
            ...(payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {}),
          },
          ca: this.config.caPath ? fs.readFileSync(this.config.caPath) : undefined,
          servername: this.config.tlsServername || undefined,
          rejectUnauthorized: !this.config.insecureTls,
          timeout: this.config.timeoutMs ?? 15000,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("error", reject);
          res.on("aborted", () => reject(new RehuntError("QUERY_FAILED", "Wazuh Indexer response interrupted.")));
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            try {
              resolve({ status: res.statusCode ?? 0, body: text ? JSON.parse(text) : null });
            } catch {
              resolve({ status: res.statusCode ?? 0, body: null });
            }
          });
        }
      );
      const deadline = setTimeout(() => req.destroy(new RehuntError("TIMEOUT", "Wazuh Indexer request timed out")), this.config.timeoutMs ?? 15000);
      req.on("close", () => clearTimeout(deadline));
      req.on("timeout", () => req.destroy(new RehuntError("TIMEOUT", "Wazuh Indexer request timed out")));
      req.on("error", (err) => reject(err));
      if (payload) req.write(payload);
      req.end();
    });
  }

}
