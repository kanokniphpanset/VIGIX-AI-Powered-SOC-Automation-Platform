import { RehuntQuery } from "../src/application/verification/ports/ISiemRehuntPort";
import { CorrelatedWazuhRehuntAdapter } from "../src/infrastructure/external-services/siem/CorrelatedWazuhRehuntAdapter";
import { DEFAULT_IOC_FIELDS } from "../src/infrastructure/external-services/siem/WazuhRehuntAdapter";
import { createRehuntProvider } from "../src/infrastructure/external-services/siem/createRehuntProvider";

/** Phase 2D adapter behaviour against a scripted Indexer (no network). Real-Indexer results are recorded in the design doc. */
const config = { url: "https://indexer.example:9200", username: "test-user", password: "test-secret" };
const T0 = new Date("2026-10-03T12:00:00.000Z");
const query: RehuntQuery = {
  incidentId: "i", responseId: "r", hosts: ["attack-endpoint"], agentIds: ["009"], iocs: [{ type: "IPV4", value: "172.19.0.3" }],
  rule: { id: "5712", groups: ["syslog", "sshd", "authentication_failures"] }, timeRange: { start: T0, end: new Date("2026-10-08T00:00:00.000Z") },
};
const mapping = { fields: { ...Object.fromEntries(Object.values(DEFAULT_IOC_FIELDS).flat().map((f) => [f, { keyword: { searchable: true } }])), timestamp: { date: { searchable: true } } } };
const timeMapping = { "wazuh-alerts-4.x-2026.10.03": { mappings: { timestamp: { mapping: { timestamp: { type: "date" } } }, "@timestamp": { mapping: { "@timestamp": { type: "date" } } } } } };

interface Doc { id: string; agent: string; agentId: string; rule: string; groups: string[]; extra?: Record<string, unknown> }
const hit = (d: Doc, i: number) => ({
  _id: `doc-${d.id}`, _index: "wazuh-alerts-4.x-2026.10.03", matched_queries: ["ioc_0"], sort: [Date.parse("2026-10-03T13:00:00Z") - i * 1000, i, d.id],
  _source: { timestamp: new Date(Date.parse("2026-10-03T13:00:00Z") - i * 1000).toISOString(), id: d.id, agent: { name: d.agent, id: d.agentId }, rule: { id: d.rule, level: 5, description: "x", groups: d.groups }, ...d.extra },
});
const docs = (n: number, over: Partial<Doc> = {}): Doc[] => Array.from({ length: n }, (_, i) => ({ id: `1790000000.${i + 1}`, agent: "attack-endpoint", agentId: "009", rule: "5712", groups: ["syslog", "sshd", "authentication_failures"], ...over }));

interface Scenario {
  docs?: Doc[]; archives?: unknown[]; archivesStatus?: number; indexMin?: string | null;
  monitoring?: { name: string; non: number; prior?: "active" | "disconnected" | null; inWindow?: number }[] | "fail"; failPage?: number; shardFail?: boolean;
}
function indexer(s: Scenario = {}) {
  const all = s.docs ?? [];
  const calls: { method: string; path: string; body?: any }[] = [];
  const transport = jest.fn(async (method: string, path: string, body?: any) => {
    calls.push({ method, path, body });
    if (method === "GET") {
      if (path.includes("/_field_caps")) return { status: 200, body: mapping };
      if (path.includes("/_mapping/")) return { status: 200, body: timeMapping };
      if (path.includes("_cat/indices")) return { status: s.archivesStatus ?? 200, body: s.archives ?? [] };
      throw new Error(`unexpected GET ${path}`);
    }
    if (path.startsWith("/wazuh-monitoring")) {
      if (s.monitoring === "fail") return { status: 500, body: {} };
      const buckets = (s.monitoring ?? [{ name: "attack-endpoint", non: 0 }]).map((m) => ({
        key: m.name,
        in_window: { doc_count: m.inWindow ?? Math.max(m.non, 1), non_active: { doc_count: m.non }, last: { value_as_string: "2026-10-08T00:00:00.000Z" } },
        before: { latest: { hits: { hits: m.prior === null ? [] : [{ _source: { status: m.prior ?? "active", timestamp: "2026-10-03T11:45:00.000Z" } }] } } },
      }));
      return { status: 200, body: { aggregations: { a: { buckets } } } };
    }
    if (body?.aggs?.min_t) {
      const min = s.indexMin === undefined ? "2026-09-29T00:00:00.000Z" : s.indexMin;
      return { status: 200, body: { aggregations: { min_t: { value_as_string: min }, max_t: { value_as_string: "2026-10-08T03:00:00.000Z" } } } };
    }
    // alert search (first page has aggs, later pages carry search_after)
    const page = calls.filter((c) => c.method === "POST" && c.body?.query && !c.path.startsWith("/wazuh-monitoring")).length;
    if (s.failPage && page === s.failPage) return { status: 200, body: { timed_out: false, _shards: { total: 3, successful: 2, failed: 1 }, hits: { hits: [] } } };
    const after = body.search_after ? all.findIndex((d) => d.id === body.search_after[2]) + 1 : 0;
    const size = body.size as number;
    const slice = all.slice(after, after + size);
    const hostCounts = [...new Set(all.map((d) => d.agent))].map((key) => ({ key }));
    return {
      status: 200,
      body: {
        timed_out: false, _shards: { total: 3, successful: 3, failed: 0 },
        hits: { total: { value: all.length, relation: "eq" }, hits: slice.map((d, i) => hit(d, after + i)) },
        aggregations: body.aggs ? { missing_timestamp: { doc_count: 0 }, hosts: { buckets: hostCounts }, ioc_events: { doc_count: all.length } } : undefined,
      },
    };
  });
  return { transport, calls };
}
const make = (s: Scenario = {}, cfg: Record<string, unknown> = {}) => {
  const i = indexer(s);
  return { adapter: new CorrelatedWazuhRehuntAdapter({ ...config, ...cfg }, i.transport as any), ...i };
};

describe("pagination and document references", () => {
  it("fetches every match with search_after, keeps index + alert id + agent id, and runs aggregations only once", async () => {
    const { adapter, calls } = make({ docs: docs(250) });
    const r = await adapter.rehunt(query);
    expect(r.pagination).toEqual({ pageSize: 100, pagesFetched: 3, fetched: 250, total: 250, cap: 1000, complete: true });
    const searches = calls.filter((c) => c.method === "POST" && c.body?.query && c.path.startsWith("/wazuh-alerts"));
    expect(searches).toHaveLength(3);
    expect(searches[0].body.aggs).toBeDefined();
    expect(searches[1].body.aggs).toBeUndefined();
    expect(searches[1].body.search_after).toHaveLength(3);
    expect(searches[0].body.sort.at(-1)).toEqual({ id: { order: "asc", unmapped_type: "keyword", missing: "_last" } });
    expect(searches[0].body._source).toEqual(expect.arrayContaining(["id", "rule.groups", "syscheck.path", "syscheck.event", "data.win.eventdata.processGuid", "agent.id"]));
    expect(r.events[0]).toMatchObject({ index: "wazuh-alerts-4.x-2026.10.03", alertId: "1790000000.1", agentId: "009", ruleGroups: ["syslog", "sshd", "authentication_failures"] });
    expect(r.truncated).toBe(false);
    expect(r.matchingEvents).toBe(250);
  });

  it("stops at the result cap and says so: an absence claim is then impossible", async () => {
    const { adapter } = make({ docs: docs(250, { rule: "9", groups: ["x"], agent: "other", agentId: "010" }) }, { pageSize: 100, resultCap: 200 });
    const r = await adapter.rehunt(query);
    expect(r.pagination).toMatchObject({ fetched: 200, total: 250, cap: 200, complete: false });
    expect(r.truncated).toBe(true);
    expect(r.matchingEvents).toBe(250);
  });

  it("a failed or partial later page is QUERY_FAILED, never a smaller clean result", async () => {
    const { adapter } = make({ docs: docs(250), failPage: 2 });
    await expect(adapter.rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });

  it("validates page size and cap", () => {
    expect(() => new CorrelatedWazuhRehuntAdapter({ ...config, pageSize: 0 })).toThrow();
    expect(() => new CorrelatedWazuhRehuntAdapter({ ...config, pageSize: 100, resultCap: 50 })).toThrow();
  });
});

describe("provenance and file facts carried per event", () => {
  it("classifies each event as REAL_TELEMETRY / HARNESS_GENERATED / MOCK_FIXTURE from the same markers as Evidence Contract v2", async () => {
    const d = [
      ...docs(1, { id: "1790000000.1" }),
      ...docs(1, { id: "1790000000.2", rule: "100320", groups: ["vigix_eval", "c2"], extra: { location: "/var/log/vigix-eval/events.json" } }),
      ...docs(1, { id: "1790000000.3", groups: ["syslog", "vigix_custom"] }),
    ];
    const r = await make({ docs: d }).adapter.rehunt(query);
    expect(r.events.map((e) => e.provenanceClass)).toEqual(["REAL_TELEMETRY", "HARNESS_GENERATED", "MOCK_FIXTURE"]);
  });

  it("reads the FIM path, operation and process guid", async () => {
    const d = docs(2, { rule: "553", groups: ["syscheck"] });
    d[0].extra = { syscheck: { path: "/etc/x", event: "deleted" } };
    d[1].extra = { data: { win: { eventdata: { processGuid: "{G}" } } } };
    const r = await make({ docs: d }).adapter.rehunt(query);
    expect(r.events[0]).toMatchObject({ filePath: "/etc/x", fileOperation: "deleted", kind: "CLEANUP" });
    expect(r.events[1].processGuid).toBe("{G}");
  });
});

describe("classification and the verdict inputs", () => {
  it("IOC on another agent with nothing tying it to the incident: UNCORROBORATED_MATCH, spreadDetected false", async () => {
    const r = await make({ docs: docs(3, { agent: "vigix-lab-agent", agentId: "004", rule: "5710", groups: ["syslog", "pam"] }) }).adapter.rehunt({ ...query, rule: { id: "100340", groups: ["vigix_eval", "exfiltration"] } });
    expect(r).toMatchObject({ classification: "UNCORROBORATED_MATCH", spreadDetected: false, iocRecurrence: false, threatContained: false, affectedHosts: [], totalMatched: 3 });
  });

  it("same detection on another agent: NEW_SCOPE_ACTIVITY, spreadDetected true, reasons stated", async () => {
    const r = await make({ docs: docs(3, { agent: "vigix-lab-agent", agentId: "004" }) }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "NEW_SCOPE_ACTIVITY", spreadDetected: true, iocRecurrence: true, threatContained: false, affectedHosts: ["vigix-lab-agent"] });
    expect(r.correlationReasons?.SAME_RULE).toBe(3);
  });

  it("same detection on the original agent: IN_SCOPE_ACTIVITY (recurrence, no spread)", async () => {
    const r = await make({ docs: docs(2) }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "IN_SCOPE_ACTIVITY", spreadDetected: false, iocRecurrence: true, threatContained: false, affectedHosts: ["attack-endpoint"] });
  });

  it("a deleted-file match is cleanup: ignored, not activity, and the verdict inputs stay clean", async () => {
    const d = docs(1, { rule: "553", groups: ["syscheck"], extra: { syscheck: { path: "/f", event: "deleted" } } });
    const r = await make({ docs: d }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "NO_MATCH_COVERED", ignoredEvents: 1, matchingEvents: 0, threatContained: true, iocRecurrence: false, spreadDetected: false, totalMatched: 1 });
  });

  it("zero matches with full coverage is NO_MATCH_COVERED and records what could not be seen", async () => {
    const r = await make({ docs: [] }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "NO_MATCH_COVERED", threatContained: true, matchingEvents: 0 });
    expect(r.coverage).toMatchObject({ complete: true, gaps: [], sources: { alerts: "AVAILABLE", archives: "NOT_AVAILABLE" }, windowCoveredByIndex: true });
    expect(r.coverage?.limitations.join(" ")).toMatch(/archives are not indexed/);
    expect(r.coverage?.agents).toEqual([{ name: "attack-endpoint", status: "ACTIVE_THROUGHOUT", nonActiveSnapshots: 0, lastSnapshotAt: "2026-10-08T00:00:00.000Z" }]);
  });

  it("archives that exist are reported as AVAILABLE", async () => {
    const r = await make({ docs: [], archives: [{ index: "wazuh-archives-4.x-2026.10.03" }] }).adapter.rehunt(query);
    expect(r.coverage?.sources.archives).toBe("AVAILABLE");
    expect(r.coverage?.limitations.join(" ")).not.toMatch(/archives are not indexed/);
  });
});

describe("no matching alert != contained (coverage)", () => {
  it("an agent that was disconnected in the window makes an empty result INCOMPLETE", async () => {
    const r = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 2 }] }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "INCOMPLETE", threatContained: false, matchingEvents: 0 });
    expect(r.coverage?.agents[0]).toMatchObject({ status: "DISCONNECTED_IN_WINDOW", nonActiveSnapshots: 2 });
    expect(r.coverage?.gaps.join(" ")).toMatch(/attack-endpoint was not active in 2 status snapshot/);
  });

  it("a disconnection that ended BEFORE the window opened is history, not a gap (agent reconnected, latest earlier snapshot irrelevant)", async () => {
    // snapshots inside the window are all active, the latest snapshot before the window is active: older disconnected ones are not even read
    const r = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 0, prior: "active", inWindow: 1 }] }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "NO_MATCH_COVERED" });
    expect(r.coverage?.agents[0]).toMatchObject({ status: "ACTIVE_THROUGHOUT", nonActiveSnapshots: 0 });
  });

  it("an agent that was disconnected when the window opened is a gap even if no snapshot falls inside the window", async () => {
    const r = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 0, prior: "disconnected", inWindow: 0 }] }).adapter.rehunt(query);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.coverage?.agents[0]).toMatchObject({ status: "DISCONNECTED_IN_WINDOW", nonActiveSnapshots: 1 });
  });

  it("a window with no snapshot inside it relies on the latest earlier snapshot; none at all is UNKNOWN", async () => {
    const ok = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 0, prior: "active", inWindow: 0 }] }).adapter.rehunt(query);
    expect(ok.coverage?.agents[0].status).toBe("ACTIVE_THROUGHOUT");
    const none = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 0, prior: null, inWindow: 0 }] }).adapter.rehunt(query);
    expect(none.coverage?.agents[0].status).toBe("UNKNOWN");
  });

  it("no agent status snapshot at all is UNKNOWN, hence INCOMPLETE", async () => {
    const r = await make({ docs: [], monitoring: [] }).adapter.rehunt(query);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.coverage?.agents[0].status).toBe("UNKNOWN");
  });

  it("a response TARGET that only looks like a host (a file path, an account) is not an agent and never blocks coverage", async () => {
    // live case TC-02: the quarantine target "/root/Downloads/Invoice_Q4_2026.xls.exe" was added to hosts and read as an agent without snapshots
    const q = { ...query, hosts: ["attack-endpoint", "/root/Downloads/Invoice_Q4_2026.xls.exe", "victim"], scopeAgents: ["attack-endpoint"] };
    const r = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 0 }] }).adapter.rehunt(q);
    expect(r.classification).toBe("NO_MATCH_COVERED");
    expect(r.coverage?.gaps).toEqual([]);
    expect(r.coverage?.agents.map((a) => `${a.name}:${a.status}`)).toEqual(["attack-endpoint:ACTIVE_THROUGHOUT", "/root/Downloads/Invoice_Q4_2026.xls.exe:UNKNOWN", "victim:UNKNOWN"]);
  });

  it("a non-required host that IS an agent and was disconnected still counts as a gap", async () => {
    const q = { ...query, hosts: ["attack-endpoint", "second-agent"], scopeAgents: ["attack-endpoint"] };
    const r = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 0 }, { name: "second-agent", non: 2 }] }).adapter.rehunt(q);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.coverage?.gaps.join(" ")).toMatch(/second-agent was not active/);
  });

  it("the alert's own agent without any snapshot is still a gap when it is a required agent", async () => {
    const q = { ...query, hosts: ["attack-endpoint", "/tmp/x"], scopeAgents: ["attack-endpoint"] };
    const r = await make({ docs: [], monitoring: [{ name: "/tmp/x", non: 0 }] }).adapter.rehunt(q);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.coverage?.gaps.join(" ")).toMatch(/no agent status snapshot is available for attack-endpoint/);
  });

  it("a failing monitoring query never counts as coverage", async () => {
    const r = await make({ docs: [], monitoring: "fail" }).adapter.rehunt(query);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.coverage?.agents[0].status).toBe("UNKNOWN");
  });

  it("a window that starts before the oldest indexed alert is INCOMPLETE", async () => {
    const r = await make({ docs: [], indexMin: "2026-10-05T00:00:00.000Z" }).adapter.rehunt(query);
    expect(r).toMatchObject({ classification: "INCOMPLETE", threatContained: false });
    expect(r.coverage?.windowCoveredByIndex).toBe(false);
  });

  it("an undeterminable index range is INCOMPLETE", async () => {
    const r = await make({ docs: [], indexMin: null }).adapter.rehunt(query);
    expect(r.classification).toBe("INCOMPLETE");
    expect(r.coverage?.windowCoveredByIndex).toBeNull();
  });

  it("agent coverage can be relaxed explicitly, and the relaxation is recorded", async () => {
    const r = await make({ docs: [], monitoring: [{ name: "attack-endpoint", non: 5 }] }, { requireAgentCoverage: false }).adapter.rehunt(query);
    expect(r.classification).toBe("NO_MATCH_COVERED");
    expect(r.coverage?.limitations.join(" ")).toMatch(/not required for completeness/);
  });

  it("a positive finding is reported even when coverage is incomplete", async () => {
    const r = await make({ docs: docs(1), monitoring: [{ name: "attack-endpoint", non: 3 }] }).adapter.rehunt(query);
    expect(r.classification).toBe("IN_SCOPE_ACTIVITY");
    expect(r.coverage?.complete).toBe(false);
  });
});

describe("read-only and safe", () => {
  it("only reads: GET (field caps, mappings, _cat) and POST _search against alert / monitoring indices", async () => {
    const { adapter, calls } = make({ docs: docs(120) });
    await adapter.rehunt(query);
    for (const c of calls) {
      if (c.method === "GET") expect(c.path).toMatch(/_field_caps|_mapping\/|_cat\/indices/);
      else expect(c.path).toMatch(/^\/(wazuh-alerts-4\.x-\*|wazuh-monitoring-\*)\/_search/);
    }
    expect(JSON.stringify(calls)).not.toContain("test-secret");
  });

  it("the plain provider selection now yields the correlating adapter, mock is unchanged", () => {
    expect(createRehuntProvider({ REHUNT_PROVIDER: "wazuh", ...({ WAZUH_INDEXER_URL: config.url, WAZUH_INDEXER_USERNAME: "u", WAZUH_INDEXER_PASSWORD: "p" }) })).toBeInstanceOf(CorrelatedWazuhRehuntAdapter);
    expect(createRehuntProvider({ REHUNT_PROVIDER: "mock" }).constructor.name).toBe("MockRehuntAdapter");
  });

  it("still refuses to search without a supported IOC (existing guard)", async () => {
    const { adapter, transport } = make({ docs: [] });
    await expect(adapter.rehunt({ ...query, iocs: [] })).rejects.toMatchObject({ code: "INSUFFICIENT_CRITERIA" });
    expect(transport).not.toHaveBeenCalled();
  });
});
