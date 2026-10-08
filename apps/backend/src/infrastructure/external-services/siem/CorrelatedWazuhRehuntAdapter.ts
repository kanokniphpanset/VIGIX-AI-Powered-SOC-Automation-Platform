import { RehuntCoverage, RehuntError, RehuntEvent, RehuntQuery, RehuntResult } from "../../../application/verification/ports/ISiemRehuntPort";
import { classifyRehunt } from "../../../application/verification/services/classifyRehunt";
import { classifyProvenance } from "../../../domain/investigation/evidenceV2/classifyProvenance";
import { SearchHit } from "./WazuhIndexerAdapter";
import { IocFieldMapping, WazuhRehuntAdapter, WazuhRehuntConfig } from "./WazuhRehuntAdapter";

export interface CorrelatedRehuntConfig extends WazuhRehuntConfig {
  /** Hourly agent-status snapshots written by the Wazuh manager. */
  monitoringIndexPattern?: string;
  archivesIndexPattern?: string;
  pageSize?: number;
  /** Most matching documents fetched in total; beyond it the result is flagged incomplete, never silently cut. */
  resultCap?: number;
  /** When true (default) an in-scope agent that was disconnected, or has no status snapshot, makes a "not seen" result INCOMPLETE. */
  requireAgentCoverage?: boolean;
}

type Src = Record<string, any>;
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : typeof v === "number" ? String(v) : null);

/**
 * CorrelatedWazuhRehuntAdapter - WazuhRehuntAdapter plus the Phase 2D semantics. It runs the same validated IOC search (so every
 * existing safety check still applies), then, read-only:
 *   - pages through ALL matches (search_after, capped) and keeps the full document reference (index, alert id, agent id);
 *   - classifies each event: in/out of scope, ACTIVITY vs CLEANUP, and the stated reasons that tie it to the original incident;
 *   - probes coverage: alert-index time range, archives availability, and per-agent status from wazuh-monitoring-*;
 *   - derives spreadDetected / iocRecurrence / threatContained from the classification (classifyRehunt) instead of from
 *     "an IOC value appeared on another agent".
 * It never writes to the Indexer and never decides RESOLVED / NOT_RESOLVED.
 */
export class CorrelatedWazuhRehuntAdapter extends WazuhRehuntAdapter {
  private readonly monitoringPattern: string;
  private readonly archivesPattern: string;
  private readonly pageSize: number;
  private readonly resultCap: number;
  private readonly requireAgentCoverage: boolean;

  constructor(config: CorrelatedRehuntConfig, transport?: ConstructorParameters<typeof WazuhRehuntAdapter>[1]) {
    super(config, transport);
    this.monitoringPattern = config.monitoringIndexPattern || "wazuh-monitoring-*";
    this.archivesPattern = config.archivesIndexPattern || "wazuh-archives-*";
    this.pageSize = config.pageSize ?? 100;
    this.resultCap = config.resultCap ?? 1000;
    this.requireAgentCoverage = config.requireAgentCoverage ?? true;
    if (!Number.isSafeInteger(this.pageSize) || this.pageSize < 1 || this.pageSize > 1000) throw new Error("Re-hunt pageSize must be 1-1000.");
    if (!Number.isSafeInteger(this.resultCap) || this.resultCap < this.pageSize) throw new Error("Re-hunt resultCap must be >= pageSize.");
    for (const p of [this.monitoringPattern, this.archivesPattern]) if (!/^[a-z0-9_*.,-]+$/.test(p)) throw new Error("Invalid Wazuh index pattern.");
  }

  protected buildQuery(query: RehuntQuery, skip: ReadonlySet<keyof IocFieldMapping> = new Set()): Record<string, unknown> {
    const dsl = super.buildQuery(query, skip) as Record<string, any>;
    dsl.size = this.pageSize;
    dsl._source = [...new Set([...(dsl._source as string[]), "id", "location", "rule.groups", "syscheck.path", "syscheck.event", "data.file", "data.vigix.event_type", "data.win.eventdata.processGuid"])];
    // Wazuh's alert id is unique per alert: a stable tiebreaker so search_after never skips or repeats a document.
    dsl.sort = [...(dsl.sort as unknown[]), { id: { order: "asc", unmapped_type: "keyword", missing: "_last" } }];
    return dsl;
  }

  protected mapHit(h: SearchHit, query: RehuntQuery): RehuntEvent {
    const e = super.mapHit(h, query);
    const src = (h._source ?? {}) as Src;
    const groups: string[] = Array.isArray(src.rule?.groups) ? src.rule.groups.map(String) : [];
    const prov = classifyProvenance({ rule: { groups }, location: src.location, data: src.data?.vigix ? { vigix: src.data.vigix } : {}, id: src.id }, str(src.id));
    return {
      ...e,
      index: h._index,
      alertId: str(src.id),
      ruleGroups: groups,
      provenanceClass: prov.class,
      processGuid: str(src.data?.win?.eventdata?.processGuid),
      filePath: str(src.syscheck?.path) ?? str(src.data?.file),
      fileOperation: str(src.syscheck?.event),
      sortValues: h.sort,
    };
  }

  async rehunt(query: RehuntQuery): Promise<RehuntResult> {
    const first = await super.rehunt(query); // validated first page + totals + aggregations
    const dsl = JSON.parse(first.query) as Record<string, any>;
    const total = first.matchingEvents;
    const events: RehuntEvent[] = [...first.events];
    let pages = 1;
    while (events.length < Math.min(total, this.resultCap)) {
      const cursor = events[events.length - 1]?.sortValues;
      if (!cursor) break;
      const page = await this.nextPage(dsl, cursor, query);
      if (page.length === 0) break;
      events.push(...page);
      pages++;
    }
    const complete = events.length >= total;

    const coverage = await this.probeCoverage(query);
    const c = classifyRehunt({ query, events, totalMatched: total, complete, skippedIocTypes: first.skippedIocTypes ?? [], coverage });
    const noMatch = c.classification === "NO_MATCH_COVERED";
    return {
      ...first,
      events: c.events.slice(0, 100),
      matchingEvents: noMatch ? 0 : c.activityCount,
      affectedHosts: c.matchedHosts,
      iocRecurrence: c.classification === "IN_SCOPE_ACTIVITY" || c.classification === "NEW_SCOPE_ACTIVITY",
      spreadDetected: c.classification === "NEW_SCOPE_ACTIVITY",
      threatContained: noMatch,
      truncated: !complete,
      classification: c.classification,
      totalMatched: total,
      ignoredEvents: c.ignoredEvents,
      correlationReasons: c.correlationReasons,
      matchedHosts: c.matchedHosts,
      coverage,
      pagination: { pageSize: this.pageSize, pagesFetched: pages, fetched: events.length, total, cap: this.resultCap, complete },
    };
  }

  private async nextPage(dsl: Record<string, any>, searchAfter: unknown[], query: RehuntQuery): Promise<RehuntEvent[]> {
    const { aggs: _aggs, ...rest } = dsl;
    const body = { ...rest, search_after: searchAfter, track_total_hits: false };
    let res;
    try {
      res = await this.transport("POST", `/${encodeURIComponent(this.indexPattern)}/_search?allow_no_indices=false&ignore_unavailable=false&allow_partial_search_results=false`, body);
    } catch (err) {
      if (err instanceof RehuntError) throw err;
      const code = (err as NodeJS.ErrnoException)?.code;
      throw new RehuntError(code === "ETIMEDOUT" || code === "ESOCKETTIMEDOUT" ? "TIMEOUT" : "UNREACHABLE", "Wazuh Indexer request failed.");
    }
    const b = res.body as Src;
    if (res.status !== 200 || !b || b.error || b.timed_out !== false || b._shards?.failed !== 0 || b._shards?.successful !== b._shards?.total || !Array.isArray(b.hits?.hits)) {
      throw new RehuntError("QUERY_FAILED", "Wazuh Indexer returned an incomplete result page.");
    }
    const events = (b.hits.hits as SearchHit[]).map((h) => this.mapHit(h, query));
    if (events.some((e) => !e.matchedIocValues?.length || !e.timestamp || !Number.isFinite(Date.parse(e.timestamp)))) {
      throw new RehuntError("QUERY_FAILED", "Wazuh event evidence is missing its timestamp or matching IOC identity.");
    }
    return events;
  }

  /** Read-only: what the search could see. Anything that cannot be determined is reported as a gap, never assumed fine. */
  protected async probeCoverage(query: RehuntQuery): Promise<RehuntCoverage> {
    const gaps: string[] = [];
    const limitations: string[] = [];
    const start = query.timeRange.start.getTime();

    let archives: RehuntCoverage["sources"]["archives"] = "UNKNOWN";
    try {
      const r = await this.transport("GET", `/_cat/indices/${encodeURIComponent(this.archivesPattern)}?format=json&h=index`);
      archives = r.status === 200 && Array.isArray(r.body) && r.body.length > 0 ? "AVAILABLE" : r.status === 200 || r.status === 404 ? "NOT_AVAILABLE" : "UNKNOWN";
    } catch {
      archives = "UNKNOWN";
    }
    if (archives !== "AVAILABLE") limitations.push("archives are not indexed: only events that raised a Wazuh rule (alert level >= the manager's log_alert_level) can be found");

    let indexRange: RehuntCoverage["indexRange"] = null;
    let windowCovered: boolean | null = null;
    try {
      const field = this.timestampFields[0];
      const r = await this.transport("POST", `/${encodeURIComponent(this.indexPattern)}/_search?allow_no_indices=true`, {
        size: 0, aggs: { min_t: { min: { field } }, max_t: { max: { field } } },
      });
      const a = (r.body as Src)?.aggregations;
      if (r.status === 200 && a) {
        indexRange = { min: str(a.min_t?.value_as_string), max: str(a.max_t?.value_as_string) };
        windowCovered = indexRange.min !== null ? Date.parse(indexRange.min) <= start : null;
      }
    } catch {
      indexRange = null;
    }
    if (windowCovered === null) gaps.push("the alert index time range could not be determined");
    else if (!windowCovered) gaps.push(`the window starts before the oldest indexed alert (${indexRange!.min})`);

    const agents = await this.probeAgents(query);
    const required = new Set((query.scopeAgents ?? query.hosts).map((h) => h.trim().toLowerCase()).filter(Boolean));
    if (this.requireAgentCoverage) {
      if (required.size === 0) gaps.push("no in-scope agent is known, so agent connectivity cannot be checked");
      for (const a of agents) {
        if (a.status === "DISCONNECTED_IN_WINDOW") gaps.push(`agent ${a.name} was not active in ${a.nonActiveSnapshots} status snapshot(s) inside or just before the window`);
        // A host that is not a required agent and has no snapshots is not an agent at all (e.g. a response target): nothing to check.
        else if (a.status === "UNKNOWN" && required.has(a.name.toLowerCase())) gaps.push(`no agent status snapshot is available for ${a.name}`);
      }
    } else {
      limitations.push("agent connectivity is not required for completeness (WAZUH_REHUNT_REQUIRE_AGENT_COVERAGE=false)");
    }
    limitations.push("agent status comes from periodic manager snapshots: a disconnection shorter than the snapshot interval is not visible");

    return { sources: { alerts: "AVAILABLE", archives }, indexRange, windowCoveredByIndex: windowCovered, agents, complete: gaps.length === 0, gaps, limitations };
  }

  /**
   * Agent connectivity over the window, from the manager's periodic status snapshots. Only what matters to the window counts:
   * the snapshots inside it plus the LATEST snapshot before it (the state when the window opened). An older disconnection that
   * ended before then is history, not a gap. A snapshot interval longer than the window means a short disconnection between two
   * snapshots stays invisible - stated in coverage.limitations.
   */
  private async probeAgents(query: RehuntQuery): Promise<RehuntCoverage["agents"]> {
    const names = [...new Set([...query.hosts, ...(query.scopeAgents ?? [])].map((h) => h.trim()).filter(Boolean))];
    if (names.length === 0) return [];
    const unknown = (): RehuntCoverage["agents"] => names.map((name) => ({ name, status: "UNKNOWN", nonActiveSnapshots: 0, lastSnapshotAt: null }));
    try {
      const startIso = query.timeRange.start.toISOString();
      const lookback = new Date(query.timeRange.start.getTime() - 3 * 3600 * 1000).toISOString();
      const r = await this.transport("POST", `/${encodeURIComponent(this.monitoringPattern)}/_search?allow_no_indices=true`, {
        size: 0,
        query: { bool: { filter: [{ terms: { name: names } }, { range: { timestamp: { gte: lookback, lte: query.timeRange.end.toISOString() } } }] } },
        aggs: {
          a: {
            terms: { field: "name", size: 100 },
            aggs: {
              in_window: {
                filter: { range: { timestamp: { gte: startIso, lte: query.timeRange.end.toISOString() } } },
                aggs: { non_active: { filter: { bool: { must_not: [{ term: { status: "active" } }] } } }, last: { max: { field: "timestamp" } } },
              },
              before: {
                filter: { range: { timestamp: { lt: startIso } } },
                aggs: { latest: { top_hits: { size: 1, sort: [{ timestamp: "desc" }], _source: ["status", "timestamp"] } } },
              },
            },
          },
        },
      });
      const buckets = (r.body as Src)?.aggregations?.a?.buckets;
      if (r.status !== 200 || !Array.isArray(buckets)) return unknown();
      return names.map((name) => {
        const b = buckets.find((x: Src) => x.key === name);
        const inWindow = Number(b?.in_window?.doc_count ?? 0);
        const prior = b?.before?.latest?.hits?.hits?.[0]?._source as Src | undefined;
        if (!b || (inWindow === 0 && !prior)) return { name, status: "UNKNOWN" as const, nonActiveSnapshots: 0, lastSnapshotAt: null };
        const nonActive = Number(b.in_window?.non_active?.doc_count ?? 0) + (prior && prior.status !== "active" ? 1 : 0);
        return {
          name,
          status: nonActive > 0 ? ("DISCONNECTED_IN_WINDOW" as const) : ("ACTIVE_THROUGHOUT" as const),
          nonActiveSnapshots: nonActive,
          lastSnapshotAt: str(b.in_window?.last?.value_as_string) ?? str(prior?.timestamp),
        };
      });
    } catch {
      return unknown();
    }
  }
}
