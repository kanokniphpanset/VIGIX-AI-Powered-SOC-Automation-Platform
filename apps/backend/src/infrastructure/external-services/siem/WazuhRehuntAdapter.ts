import { ISiemRehuntPort, RehuntError, RehuntQuery, RehuntResult } from "../../../application/verification/ports/ISiemRehuntPort";
import { IndexerTransport, WazuhIndexerAdapter, WazuhIndexerConfig } from "./WazuhIndexerAdapter";

export type IocFieldMapping = Record<"ip" | "domain" | "url" | "hash", string[]>;
// Wazuh 4.x decoder fields. Deployments must verify these against their index mapping;
// keyword/ip fields use exact terms, never the query_string parser or full_log text.
export const DEFAULT_IOC_FIELDS: IocFieldMapping = {
  ip: ["data.srcip", "data.dstip", "data.win.eventdata.sourceIp", "data.win.eventdata.destinationIp"],
  domain: ["data.dns.question.name", "data.domain", "data.win.eventdata.queryName"],
  url: ["data.url", "data.http.url"],
  hash: ["data.md5", "data.sha1", "data.sha256", "data.hash", "syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after"],
};

export interface WazuhRehuntConfig extends WazuhIndexerConfig { fields?: IocFieldMapping }

/**
 * VIGIX IOC types (as stored in threat_intel_iocs, e.g. IPV4 / SHA256) -> the adapter's search categories.
 * The lowercase category names themselves are accepted too (RunRehuntVerification adds the response target as
 * "ip"/"hash"/"url"). Anything else is unsupported and simply not searched; if nothing searchable remains the
 * re-hunt fails with INSUFFICIENT_CRITERIA (never a silent NO_MATCH).
 */
const IOC_CATEGORY: Record<string, keyof IocFieldMapping> = {
  ip: "ip", ipv4: "ip", ipv6: "ip",
  hash: "hash", md5: "hash", sha1: "hash", sha256: "hash",
  domain: "domain",
  url: "url",
};

export function iocSearchCategory(type: string): keyof IocFieldMapping | null {
  const key = type.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(IOC_CATEGORY, key) ? IOC_CATEGORY[key] : null;
}

export function parseIocFields(json?: string): IocFieldMapping {
  if (!json) return DEFAULT_IOC_FIELDS;
  try {
    const value = JSON.parse(json);
    if (!value || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).some(k => !(k in DEFAULT_IOC_FIELDS))) throw new Error();
    const fields = { ...DEFAULT_IOC_FIELDS, ...value };
    for (const list of Object.values(fields)) {
      if (!Array.isArray(list) || !list.length || list.length > 30 ||
          list.some(f => typeof f !== "string" || !/^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*$/.test(f))) throw new Error();
    }
    return fields;
  } catch { throw new Error("WAZUH_REHUNT_IOC_FIELDS must map supported IOC types to nonempty field-name arrays."); }
}

/** Read-only IOC evidence adapter. Investigation number stays on the existing request;
 * it never selects fixtures or changes the caller's time window. */
export class WazuhRehuntAdapter extends WazuhIndexerAdapter implements ISiemRehuntPort {
  private readonly fields: IocFieldMapping;
  protected readonly timestampFields: string[];
  /** Per re-hunt call: IOC categories prepareQuery skipped (no field present in the index), read back in rehunt(). */
  private readonly skippedByQuery = new WeakMap<RehuntQuery, (keyof IocFieldMapping)[]>();
  constructor(config: WazuhRehuntConfig, transport?: IndexerTransport) {
    super({ ...config, timestampField: config.timestampField || "timestamp" }, transport);
    this.fields = parseIocFields(config.fields ? JSON.stringify(config.fields) : undefined);
    this.timestampFields = config.timestampField ? [config.timestampField] : ["timestamp", "@timestamp"];
    if (!/^[a-zA-Z0-9_@]+(?:\.[a-zA-Z0-9_]+)*$/.test(this.timestampField)) throw new Error("Invalid Wazuh timestamp field.");
    if (config.url) {
      const url = new URL(config.url);
      if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
        throw new Error("WAZUH_INDEXER_URL must be an HTTPS origin without embedded credentials.");
      }
    }
    if (config.timeoutMs !== undefined && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs <= 0)) {
      throw new Error("WAZUH_REHUNT_TIMEOUT_MS must be a positive integer.");
    }
    if (config.indexPattern && !/^[a-z0-9_*.,-]+$/.test(config.indexPattern)) throw new Error("Invalid Wazuh index pattern.");
  }

  protected async prepareQuery(query: RehuntQuery): Promise<Record<string, unknown>> {
    if (!this.isConfigured()) throw new RehuntError("NOT_CONFIGURED", "Wazuh Indexer is not configured.");
    this.buildQuery(query); // Reject unsupported/empty criteria before any network request.
    // Only categories of IOCs that are actually queried (non-empty value), so field checks match buildQuery.
    const types = [...new Set(query.iocs.filter(i => i.value.trim()).map(i => iocSearchCategory(i.type)).filter((t): t is keyof IocFieldMapping => !!t))];
    const fields = [...types.flatMap(t => this.fields[t])];
    let response;
    try {
      response = await this.transport("GET", `/${encodeURIComponent(this.indexPattern)}/_field_caps?fields=${encodeURIComponent(fields.join(","))}&allow_no_indices=false&ignore_unavailable=false`);
    } catch (error) {
      if (error instanceof RehuntError) throw error;
      const code = (error as NodeJS.ErrnoException)?.code;
      throw new RehuntError(code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT" ? "TIMEOUT" : "UNREACHABLE", "Wazuh Indexer field mapping request failed.");
    }
    const mapping = (response.body as any)?.fields;
    if (response.status !== 200 || !mapping || typeof mapping !== "object") throw new RehuntError("QUERY_FAILED", "Wazuh Indexer field mapping is unavailable.");
    // A category none of whose fields exist in any selected index (e.g. no DNS data at all) cannot match anything
    // there: it is skipped and reported, never turned into NO_MATCH. A field that EXISTS but is unsearchable or of the
    // wrong type is a real misconfiguration and fails the re-hunt.
    const skipped: (keyof IocFieldMapping)[] = [];
    for (const type of types) {
      const mapped = this.fields[type as keyof IocFieldMapping].filter(f => mapping[f] && Object.keys(mapping[f]).length);
      if (!mapped.length) {
        skipped.push(type);
        continue;
      }
      if (mapped.some(f => Object.entries(mapping[f]).some(([kind, cap]: [string, any]) =>
        !["keyword", "ip", "constant_keyword"].includes(kind) || cap.searchable !== true || cap.non_searchable_indices?.length))) {
        throw new RehuntError("QUERY_FAILED", "IOC fields must have searchable keyword/IP mappings. Configure WAZUH_REHUNT_IOC_FIELDS for this deployment.");
      }
    }
    if (skipped.length === types.length) {
      throw new RehuntError("INSUFFICIENT_CRITERIA", "None of the IOC types has a searchable field in the current Wazuh index.");
    }
    this.skippedByQuery.set(query, skipped);
    // Wildcard field_caps merges indices: a mapping in one index proves nothing
    // about another. Validate each concrete index, including mixed date formats.
    let times;
    try {
      times = await this.transport("GET", `/${encodeURIComponent(this.indexPattern)}/_mapping/field/${this.timestampFields.map(encodeURIComponent).join(",")}?allow_no_indices=false&ignore_unavailable=false`);
    } catch (error) {
      if (error instanceof RehuntError) throw error;
      const code = (error as NodeJS.ErrnoException)?.code;
      throw new RehuntError(code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT" ? "TIMEOUT" : "UNREACHABLE", "Wazuh timestamp mapping request failed.");
    }
    const indices = times.body as Record<string, { mappings?: Record<string, { mapping?: Record<string, { type?: string; index?: boolean }> }> }>;
    if (times.status !== 200 || !indices || typeof indices !== "object" || Array.isArray(indices) || !Object.keys(indices).length) {
      throw new RehuntError("QUERY_FAILED", "Wazuh per-index timestamp mappings are unavailable.");
    }
    for (const index of Object.values(indices)) {
      let supported = 0;
      for (const field of this.timestampFields) {
        const entry = index?.mappings?.[field];
        if (!entry) continue;
        const definition = entry.mapping?.[field.split(".").pop()!];
        if (!definition || !["date", "date_nanos"].includes(definition.type ?? "") || definition.index === false) {
          throw new RehuntError("QUERY_FAILED", "Conflicting or unsearchable Wazuh timestamp mapping.");
        }
        supported++;
      }
      if (!supported) throw new RehuntError("QUERY_FAILED", "A selected Wazuh index has no supported event timestamp mapping.");
    }
    return this.buildQuery(query, new Set(skipped));
  }

  protected eventTimestamp(source: Record<string, unknown>): string {
    for (const field of this.timestampFields) {
      const value = field.split(".").reduce<unknown>((v, key) => (v as Record<string, unknown>)?.[key], source);
      if (value !== undefined && value !== null) return typeof value === "string" ? value : "";
    }
    return "";
  }

  async rehunt(query: RehuntQuery): Promise<RehuntResult> {
    const result = await super.rehunt(query);
    if (result.events.some(e => !e.matchedIocValues?.length || !e.timestamp || !Number.isFinite(Date.parse(e.timestamp)))) {
      throw new RehuntError("QUERY_FAILED", "Wazuh event evidence is missing its timestamp or matching IOC identity.");
    }
    const skipped = new Set(this.skippedByQuery.get(query) ?? []);
    const queried = query.iocs.filter(i => i.value.trim() && iocSearchCategory(i.type));
    return {
      ...result,
      skippedIocTypes: [...skipped].map(t => t.toUpperCase()),
      searchedIocs: queried.filter(i => !skipped.has(iocSearchCategory(i.type)!)).map(i => ({ type: i.type, value: i.value })),
      skippedIocs: queried
        .filter(i => skipped.has(iocSearchCategory(i.type)!))
        .map(i => ({ type: i.type, value: i.value, reason: `No searchable ${iocSearchCategory(i.type)!.toUpperCase()} field in current Wazuh index` })),
    };
  }

  protected buildQuery(query: RehuntQuery, skip: ReadonlySet<keyof IocFieldMapping> = new Set()): Record<string, unknown> {
    const start = query.timeRange.start.getTime(), end = query.timeRange.end.getTime();
    if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) {
      throw new RehuntError("INSUFFICIENT_CRITERIA", "A valid, increasing re-hunt time range is required.");
    }
    const clauses = query.iocs.flatMap((ioc, index) => {
      const type = iocSearchCategory(ioc.type);
      if (!type || !ioc.value.trim() || skip.has(type)) return [];
      return [{ bool: { _name: `ioc_${index}`, minimum_should_match: 1,
        should: this.fields[type].map(field => ({ term: { [field]: { value: ioc.value } } })),
      } }];
    });
    if (!clauses.length) throw new RehuntError("INSUFFICIENT_CRITERIA", "No supported IOC is available to query.");
    const missingTime = { bool: { must_not: this.timestampFields.map(field => ({ exists: { field } })) } };
    const bounds = { gte: query.timeRange.start.toISOString(), lte: query.timeRange.end.toISOString() };
    const timeClauses = this.timestampFields.map((field, i) => ({ bool: {
      filter: [{ range: { [field]: bounds } }],
      must_not: this.timestampFields.slice(0, i).map(prior => ({ exists: { field: prior } })),
    } }));
    return {
      size: 20, track_total_hits: true,
      sort: this.timestampFields.map(field => ({ [field]: { order: "desc", unmapped_type: "date", missing: "_last" } })),
      _source: [...this.timestampFields, "agent.name", "agent.id", "rule.id", "rule.level", "rule.description"],
      query: { bool: { filter: [{ bool: { should: [...timeClauses, missingTime], minimum_should_match: 1 } }],
        should: clauses, minimum_should_match: 1 } },
      aggs: { missing_timestamp: { filter: missingTime }, hosts: { terms: { field: "agent.name", size: 100 } },
        ioc_events: { filter: { bool: { should: clauses.map(c => ({ bool: { should: c.bool.should, minimum_should_match: 1 } })), minimum_should_match: 1 } } } },
    };
  }
}
