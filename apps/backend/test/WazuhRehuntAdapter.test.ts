import { RehuntError, RehuntQuery } from "../src/application/verification/ports/ISiemRehuntPort";
import { DEFAULT_IOC_FIELDS, parseIocFields, WazuhRehuntAdapter } from "../src/infrastructure/external-services/siem/WazuhRehuntAdapter";
import { createRehuntProvider } from "../src/infrastructure/external-services/siem/createRehuntProvider";
import { MockRehuntAdapter } from "../src/infrastructure/external-services/siem/MockRehuntAdapter";

const config = { url: "https://indexer.example:9200", username: "test-user", password: "test-secret" };
const query: RehuntQuery = { incidentId: "incident", responseId: "response", investigationNumber: 3,
  hosts: ["original"], iocs: [{ type: "ip", value: "192.0.2.4" }],
  timeRange: { start: new Date("2026-09-01T00:00:00Z"), end: new Date("2026-09-02T00:00:00Z") } };
const mapping = { fields: { ...Object.fromEntries(Object.values(DEFAULT_IOC_FIELDS).flat().map(f => [f, { keyword: { searchable: true } }])), timestamp: { date: { searchable: true } } } };
function timeMapping(fields = ["timestamp", "@timestamp"]) {
  return { "alerts-test": { mappings: Object.fromEntries(fields.map(f => [f, { mapping: { [f]: { type: "date" } } }])) } };
}
function body(count = 0) {
  return { timed_out: false, _shards: { total: 1, successful: 1, failed: 0 },
    hits: { total: { value: count, relation: "eq" }, hits: count ? [{ _id: "event-1", matched_queries: ["ioc_0", "ioc_1"],
      _source: { timestamp: "2026-09-01T12:00:00Z", agent: { name: "other", id: "1" }, rule: { id: "55", level: 8, description: "event" } } }] : [] },
    aggregations: { missing_timestamp: { doc_count: 0 }, hosts: { buckets: count ? [{ key: "other" }] : [] }, ioc_events: { doc_count: count } } };
}
function setup(result: unknown = body(), status = 200) {
  const transport = jest.fn(async (method: string, path: string) => method === "GET" ? { status: 200, body: path.includes("/_mapping/") ? timeMapping() : mapping } : { status, body: result });
  return { adapter: new WazuhRehuntAdapter(config, transport), transport };
}

test("MATCH preserves evidence, all matched IOC values, source, spread and exact window", async () => {
  const { adapter, transport } = setup(body(2));
  const input = { ...query, iocs: [...query.iocs, { type: "domain", value: "example.test" }] };
  const result = await adapter.rehunt(input);
  expect(result).toMatchObject({ source: "WAZUH_INDEXER", matchingEvents: 2, threatContained: false, iocRecurrence: true, spreadDetected: true, truncated: true,
    timeRange: { start: query.timeRange.start.toISOString(), end: query.timeRange.end.toISOString() },
    events: [{ id: "event-1", matchedIoc: true, matchedIocValues: ["192.0.2.4", "example.test"] }] });
  expect(input.investigationNumber).toBe(3);
  expect(transport).toHaveBeenCalledTimes(3);
  expect(result.query).not.toContain("test-secret");
});
test("NO_MATCH requires a successful complete empty search", async () => {
  expect(await setup().adapter.rehunt(query)).toMatchObject({ matchingEvents: 0, threatContained: true, iocRecurrence: false, events: [] });
});
test.each([["ip", "192.0.2.4"], ["domain", "example.test"], ["url", "https://example.test/path?a=1"], ["hash", "a".repeat(64)]])("%s uses its own exact fields", async (type, value) => {
  const result = await setup().adapter.rehunt({ ...query, iocs: [{ type, value }] });
  const dsl = JSON.parse(result.query);
  const terms = dsl.query.bool.should[0].bool.should;
  expect(terms).toEqual(DEFAULT_IOC_FIELDS[type as keyof typeof DEFAULT_IOC_FIELDS].map(field => ({ term: { [field]: { value } } })));
  const times = dsl.query.bool.filter[0].bool.should;
  for (const [i, field] of ["timestamp", "@timestamp"].entries()) {
    expect(times[i].bool.filter[0].range[field]).toEqual({ gte: query.timeRange.start.toISOString(), lte: query.timeRange.end.toISOString() });
  }
  expect(times[1].bool.must_not).toEqual([{ exists: { field: "timestamp" } }]);
});
test("untrusted syntax stays a literal term, never query syntax", async () => {
  const value = '\" OR *:* {"match_all":{}}';
  const result = await setup().adapter.rehunt({ ...query, iocs: [{ type: "url", value }] });
  expect(JSON.parse(result.query).query.bool.should[0].bool.should[0]).toEqual({ term: { "data.url": { value } } });
  expect(result.query).not.toContain("query_string");
});
test.each([[], [{ type: "file", value: "malware.exe" }], [{ type: "__proto__", value: "x" }], [{ type: "IP", value: " " }]].map(iocs => ({ iocs })))("no supported IOC rejects before searching (even with rule)", async ({ iocs }) => {
  const { adapter, transport } = setup();
  await expect(adapter.rehunt({ ...query, iocs, rule: { id: "55" } })).rejects.toMatchObject({ code: "INSUFFICIENT_CRITERIA" });
  expect(transport).not.toHaveBeenCalled();
});
test("unsupported IOC is skipped while matched IOC indices remain correct", async () => {
  const result = await setup(body(1)).adapter.rehunt({ ...query, iocs: [{ type: "file", value: "skip" }, ...query.iocs] });
  // The server cannot return ioc_0 for this query; normalize only supported named clauses.
  expect(JSON.parse(result.query).query.bool.should.map((c: any) => c.bool._name)).toEqual(["ioc_1"]);
});
test.each(["ETIMEDOUT", "ESOCKETTIMEDOUT", "ECONNREFUSED"])("transport %s remains an error", async code => {
  const transport = jest.fn().mockRejectedValue(Object.assign(new Error("test-secret"), { code }));
  await expect(new WazuhRehuntAdapter(config, transport).rehunt(query)).rejects.toMatchObject({ code: code.includes("TIMEDOUT") ? "TIMEOUT" : "UNREACHABLE" });
});
test.each([401, 403, 404, 429, 500])("HTTP %s is never NO_MATCH", async status => {
  await expect(setup(body(), status).adapter.rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
});
test.each([null, {}, { ...body(), timed_out: true }, { ...body(), _shards: { total: 2, successful: 1, failed: 1 } },
  { ...body(), _shards: { total: 0, successful: 0, failed: 0 } }, { ...body(), aggregations: {} },
  { ...body(), hits: { total: { value: 0, relation: "gte" }, hits: [] } }])("malformed/partial/timed-out searches fail safely", async result => {
  await expect(setup(result).adapter.rehunt(query)).rejects.toBeInstanceOf(RehuntError);
});
test("server timeout is TIMEOUT", async () => {
  await expect(setup({ ...body(), timed_out: true }).adapter.rehunt(query)).rejects.toMatchObject({ code: "TIMEOUT" });
});
test.each([
  // No field of the only IOC category exists anywhere → nothing meaningful to search.
  [{ fields: {} }, "INSUFFICIENT_CRITERIA"],
  // The field exists with an incompatible type → real misconfiguration.
  [{ fields: { "data.srcip": { text: { searchable: true } } } }, "QUERY_FAILED"],
])("missing or incompatible mapping cannot become NO_MATCH (%j → %s)", async (fields, code) => {
  const transport = jest.fn().mockResolvedValue({ status: 200, body: fields });
  await expect(new WazuhRehuntAdapter(config, transport).rehunt(query)).rejects.toMatchObject({ code });
  expect(transport).toHaveBeenCalledTimes(1);
});
test("health verifies authenticated indices and actual search", async () => {
  const transport = jest.fn().mockResolvedValueOnce({ status: 200, body: { status: "green" } })
    .mockResolvedValueOnce({ status: 200, body: [{ index: "wazuh-alerts-4.x-2026.09.01" }] })
    .mockResolvedValueOnce({ status: 200, body: body() });
  expect(await new WazuhRehuntAdapter(config, transport).health()).toMatchObject({ reachable: true, alertIndices: 1 });
  expect(transport.mock.calls[2][0]).toBe("POST");
});
test("health does not claim reachable when authentication fails", async () => {
  const transport = jest.fn().mockResolvedValue({ status: 401, body: null });
  expect(await new WazuhRehuntAdapter(config, transport).health()).toMatchObject({ reachable: false });
});
test("invalid time, URL, timeout and mapping configuration fail safely", async () => {
  await expect(setup().adapter.rehunt({ ...query, timeRange: { start: new Date(0), end: new Date(0) } })).rejects.toMatchObject({ code: "INSUFFICIENT_CRITERIA" });
  expect(() => new WazuhRehuntAdapter({ ...config, url: "http://insecure" })).toThrow();
  expect(() => new WazuhRehuntAdapter({ ...config, timeoutMs: NaN })).toThrow();
  expect(() => parseIocFields('{"ip":["*"]}')).toThrow();
  expect(parseIocFields('{"ip":["source.ip"]}').ip).toEqual(["source.ip"]);
});
test("DI selects mock independently of live configuration, and selects the real adapter explicitly", () => {
  expect(createRehuntProvider({ REHUNT_PROVIDER: "mock", WAZUH_INDEXER_URL: "invalid" })).toBeInstanceOf(MockRehuntAdapter);
  expect(createRehuntProvider({ REHUNT_PROVIDER: "wazuh" })).toBeInstanceOf(WazuhRehuntAdapter);
  expect(createRehuntProvider({})).toBeInstanceOf(WazuhRehuntAdapter);
  expect(() => createRehuntProvider({ REHUNT_PROVIDER: "typo" })).toThrow();
});
test("a search request timeout after mapping succeeds remains TIMEOUT", async () => {
  const transport = jest.fn().mockResolvedValueOnce({ status: 200, body: mapping })
    .mockResolvedValueOnce({ status: 200, body: timeMapping() })
    .mockRejectedValueOnce(new RehuntError("TIMEOUT", "Wazuh Indexer request timed out"));
  await expect(new WazuhRehuntAdapter(config, transport).rehunt(query)).rejects.toMatchObject({ code: "TIMEOUT" });
});
test("date mapping cannot be absent even when IOC mapping is valid", async () => {
  const transport = jest.fn().mockResolvedValue({ status: 200, body: { fields: { "data.srcip": { keyword: { searchable: true } } } } });
  await expect(new WazuhRehuntAdapter(config, transport).rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
});

describe("timestamp coverage", () => {
  function withTimes(times: unknown, source: Record<string, unknown> | null) {
    const result: any = body(source ? 1 : 0);
    if (source) result.hits.hits[0]._source = { ...result.hits.hits[0]._source, timestamp: undefined, ...source };
    const transport = jest.fn(async (method: string, path: string) => ({ status: 200,
      body: method !== "GET" ? result : path.includes("/_mapping/") ? times : mapping }));
    return { adapter: new WazuhRehuntAdapter(config, transport), transport, result };
  }
  test.each(["timestamp", "@timestamp"])("matches and normalizes %s-only events with no override", async field => {
    const value = "2026-09-01T12:00:00.123Z";
    const { adapter } = withTimes(timeMapping([field]), { [field]: value });
    const result = await adapter.rehunt(query);
    expect(result).toMatchObject({ matchingEvents: 1, source: "WAZUH_INDEXER", events: [{ timestamp: value, matchedIocValues: ["192.0.2.4"] }] });
  });
  test("mixed per-index mappings and different per-document timestamps use guarded fallback", async () => {
    const times = { legacy: timeMapping(["timestamp"])["alerts-test"], modern: timeMapping(["@timestamp"])["alerts-test"], both: timeMapping()["alerts-test"] };
    const { adapter } = withTimes(times, { timestamp: "2026-09-01T10:00:00Z", "@timestamp": "2026-09-01T11:00:00Z" });
    const result = await adapter.rehunt(query);
    expect(result.events[0].timestamp).toBe("2026-09-01T10:00:00Z");
    const branches = JSON.parse(result.query).query.bool.filter[0].bool.should;
    expect(branches[1].bool.must_not).toContainEqual({ exists: { field: "timestamp" } });
    expect(branches[0].bool.filter[0].range.timestamp).toEqual({ gte: query.timeRange.start.toISOString(), lte: query.timeRange.end.toISOString() });
    expect(branches[1].bool.filter[0].range["@timestamp"]).toEqual(branches[0].bool.filter[0].range.timestamp);
  });
  test("mixed mappings allow complete NO_MATCH with empty matched IOC evidence", async () => {
    const { adapter } = withTimes({ old: timeMapping(["timestamp"])["alerts-test"], new: timeMapping(["@timestamp"])["alerts-test"] }, null);
    expect(await adapter.rehunt(query)).toMatchObject({ matchingEvents: 0, events: [], threatContained: true });
  });
  test.each([{}, { one: { mappings: {} } }, { one: timeMapping()["alerts-test"], missing: { mappings: {} } },
    { one: { mappings: { timestamp: { mapping: { timestamp: { type: "keyword" } } } } } },
    { one: { mappings: { timestamp: { mapping: { timestamp: { type: "date", index: false } } } } } }])("missing/conflicting mappings fail before search", async times => {
    const { adapter, transport } = withTimes(times, null);
    await expect(adapter.rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
    expect(transport.mock.calls.every(([method]) => method === "GET")).toBe(true);
  });
  test("undated matching IOCs cannot become clean evidence, even outside the returned sample", async () => {
    const { adapter, result } = withTimes(timeMapping(), null);
    result.aggregations.missing_timestamp.doc_count = 1;
    await expect(adapter.rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });
  test("missing coverage aggregation is an incomplete response", async () => {
    const { adapter, result } = withTimes(timeMapping(), null);
    delete result.aggregations.missing_timestamp;
    await expect(adapter.rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });
  test("timestamp mapping HTTP failure cannot become NO_MATCH", async () => {
    const transport = jest.fn().mockResolvedValueOnce({ status: 200, body: mapping }).mockResolvedValueOnce({ status: 401, body: {} });
    await expect(new WazuhRehuntAdapter(config, transport).rehunt(query)).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });
  test("explicit timestamp setting remains supported without fallback", async () => {
    const { transport } = withTimes(timeMapping(["@timestamp"]), { "@timestamp": "2026-09-01T12:00:00Z" });
    const result = await new WazuhRehuntAdapter({ ...config, timestampField: "@timestamp" }, transport).rehunt(query);
    expect(JSON.parse(result.query)._source).not.toContain("timestamp");
    expect(result.events[0].timestamp).toBe("2026-09-01T12:00:00Z");
  });
});

// ---------------------------------------------------------------- VIGIX IOC type normalization
// VIGIX stores IOC types as IPV4 / IPV6 / MD5 / SHA1 / SHA256 / DOMAIN / URL (threat_intel_iocs.ioc_type).
describe("VIGIX IOC type normalization", () => {
  const md5 = "44d88612fea8a8f36de82e1278abb02f";
  const sha1 = "3395856ce81f2b7382dee72602f798b642f14140";
  const sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
  const termsOf = (q: string) => (JSON.parse(q).query.bool.should as { bool: { _name: string; should: unknown[] } }[]).map((c) => c.bool.should);

  test.each([
    ["IPV4", "10.10.10.50", "ip"],
    ["IPV6", "2001:db8::50", "ip"],
    ["MD5", md5, "hash"],
    ["SHA1", sha1, "hash"],
    ["SHA256", sha256, "hash"],
    ["DOMAIN", "vigix-mock-c2.net", "domain"],
    ["URL", "http://vigix-mock-c2.net/stage2.bin", "url"],
  ] as const)("%s is searched as %s on that category's exact fields", async (type, value, category) => {
    const { adapter } = setup();
    const result = await adapter.rehunt({ ...query, iocs: [{ type, value }] });
    expect(termsOf(result.query)).toEqual([DEFAULT_IOC_FIELDS[category].map((field) => ({ term: { [field]: { value } } }))]);
  });

  test("mixed VIGIX types: every supported IOC becomes its own named clause; unsupported ones are skipped", async () => {
    const { adapter, transport } = setup(body(1));
    const iocs = [
      { type: "IPV4", value: "10.10.10.50" },
      { type: "USERNAME", value: "root" },
      { type: "SHA256", value: sha256 },
      { type: "DOMAIN", value: "vigix-mock-c2.net" },
    ];
    const result = await adapter.rehunt({ ...query, iocs });
    const should = JSON.parse(result.query).query.bool.should as { bool: { _name: string; should: { term: Record<string, { value: string }> }[] } }[];
    expect(should.map((c) => c.bool._name)).toEqual(["ioc_0", "ioc_2", "ioc_3"]);
    expect(should.map((c) => Object.values(c.bool.should[0].term)[0].value)).toEqual(["10.10.10.50", sha256, "vigix-mock-c2.net"]);
    // The field-capability check covers exactly the queried categories (ip, hash, domain) — nothing for USERNAME.
    const caps = String(transport.mock.calls[0][1]);
    expect(caps).toContain(encodeURIComponent("data.srcip"));
    expect(caps).toContain(encodeURIComponent("data.sha256"));
    expect(caps).toContain(encodeURIComponent("data.dns.question.name"));
    expect(caps).not.toContain(encodeURIComponent("data.url"));
    expect(result.matchingEvents).toBe(1);
  });

  test.each([
    [[{ type: "USERNAME", value: "root" }]],
    [[{ type: "FILE_PATH", value: "C:/Temp/stage2.exe" }, { type: "REGISTRY_KEY", value: "HKLM/Software/Run" }]],
    [[{ type: "IPV4", value: "   " }]],
    [[]],
  ])("unsupported-only or empty IOC list stays INSUFFICIENT_CRITERIA (an error, never NO_MATCH): %j", async (iocs) => {
    const { adapter, transport } = setup();
    await expect(adapter.rehunt({ ...query, iocs })).rejects.toMatchObject({ code: "INSUFFICIENT_CRITERIA" });
    expect(transport).not.toHaveBeenCalled();
  });

  test("IPV4 keeps the exact time bounds and the complete-search NO_MATCH semantics", async () => {
    const result = await setup().adapter.rehunt({ ...query, iocs: [{ type: "IPV4", value: "203.0.113.254" }] });
    expect(result).toMatchObject({ matchingEvents: 0, threatContained: true, iocRecurrence: false,
      timeRange: { start: query.timeRange.start.toISOString(), end: query.timeRange.end.toISOString() } });
  });

  test("IPV4 with incomplete shards is still rejected, never NO_MATCH", async () => {
    const partial = { ...body(), _shards: { total: 2, successful: 1, failed: 1 } };
    await expect(setup(partial).adapter.rehunt({ ...query, iocs: [{ type: "IPV4", value: "10.10.10.50" }] })).rejects.toBeInstanceOf(RehuntError);
  });
});

// ---------------------------------------------------------------- IOC categories without any field in the index
describe("IOC categories with no field in the index are skipped, never read as NO_MATCH", () => {
  const ipOnly = { fields: { ...Object.fromEntries(DEFAULT_IOC_FIELDS.ip.map(f => [f, { keyword: { searchable: true } }])), timestamp: { date: { searchable: true } } } };
  function lab(caps: unknown, result: unknown = body()) {
    const transport = jest.fn(async (method: string, path: string) =>
      method === "GET" ? { status: 200, body: path.includes("/_mapping/") ? timeMapping() : caps } : { status: 200, body: result });
    return { adapter: new WazuhRehuntAdapter(config, transport), transport };
  }
  const iocs = [{ type: "DOMAIN", value: "evil.example" }, { type: "IPV4", value: "198.51.100.23" }];

  test("D: unmapped DOMAIN + mapped IPV4 → DOMAIN skipped (reported), IPV4 searched", async () => {
    const { adapter } = lab(ipOnly);
    const r = await adapter.rehunt({ ...query, iocs });
    const should = JSON.parse(r.query).query.bool.should as { bool: { _name: string } }[];
    expect(should.map(c => c.bool._name)).toEqual(["ioc_1"]); // only the IPV4 clause; original index kept
    expect(r.query).not.toContain("evil.example");
    expect(r.skippedIocTypes).toEqual(["DOMAIN"]);
    expect(r.searchedIocs).toEqual([{ type: "IPV4", value: "198.51.100.23" }]);
    expect(r.skippedIocs).toEqual([{ type: "DOMAIN", value: "evil.example", reason: "No searchable DOMAIN field in current Wazuh index" }]);
  });

  test("E: only unmapped IOC types → INSUFFICIENT_CRITERIA and no search is run", async () => {
    const { adapter, transport } = lab(ipOnly);
    await expect(adapter.rehunt({ ...query, iocs: [{ type: "DOMAIN", value: "evil.example" }, { type: "SHA256", value: "a".repeat(64) }] }))
      .rejects.toMatchObject({ code: "INSUFFICIENT_CRITERIA" });
    expect(transport.mock.calls.some(([m]) => m === "POST")).toBe(false);
  });

  test("F: a field that exists with the wrong type (text) is still QUERY_FAILED", async () => {
    const textDomain = { fields: { ...ipOnly.fields, "data.domain": { text: { searchable: true } } } };
    await expect(lab(textDomain).adapter.rehunt({ ...query, iocs })).rejects.toMatchObject({ code: "QUERY_FAILED" });
    const notSearchable = { fields: { ...ipOnly.fields, "data.domain": { keyword: { searchable: false } } } };
    await expect(lab(notSearchable).adapter.rehunt({ ...query, iocs })).rejects.toMatchObject({ code: "QUERY_FAILED" });
    const partly = { fields: { ...ipOnly.fields, "data.domain": { keyword: { searchable: true, non_searchable_indices: ["idx-1"] } } } };
    await expect(lab(partly).adapter.rehunt({ ...query, iocs })).rejects.toMatchObject({ code: "QUERY_FAILED" });
  });

  test("G: a successful zero-result search on the searched IOCs → NO_MATCH (with DOMAIN reported as skipped)", async () => {
    const r = await lab(ipOnly, body(0)).adapter.rehunt({ ...query, iocs });
    expect(r).toMatchObject({ matchingEvents: 0, threatContained: true, iocRecurrence: false, skippedIocTypes: ["DOMAIN"] });
  });

  test("H: a successful matching search → MATCH", async () => {
    const r = await lab(ipOnly, body(1)).adapter.rehunt({ ...query, iocs });
    expect(r).toMatchObject({ matchingEvents: 1, threatContained: false, iocRecurrence: true });
  });

  test("I: incomplete shards are never NO_MATCH, even with a skipped category", async () => {
    const partial = { ...body(), _shards: { total: 2, successful: 1, failed: 1 } };
    await expect(lab(ipOnly, partial).adapter.rehunt({ ...query, iocs })).rejects.toBeInstanceOf(RehuntError);
  });

  test("with every category mapped nothing is skipped (existing behaviour)", async () => {
    const r = await setup().adapter.rehunt({ ...query, iocs });
    expect(r.skippedIocTypes).toEqual([]);
    expect(r.searchedIocs).toHaveLength(2);
  });
});
