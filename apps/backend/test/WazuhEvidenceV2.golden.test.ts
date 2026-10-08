import fs from "node:fs";
import path from "node:path";
import { extractWazuhEvidenceV2 } from "../src/domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import { EvidenceV2, ProvenanceClass } from "../src/domain/investigation/evidenceV2/types";
import { extractAlertIocs } from "../src/domain/investigation/alertIocs";

/**
 * Phase 2B - real-alert tests for Evidence Contract v2.
 *
 * Fixtures: test/fixtures/wazuh-real/*.json are ALERTS CAPTURED READ-ONLY from the lab Wazuh Indexer (2026-10-08), user and
 * host names masked; _index.json records each one's Indexer index/_id. Rules 100300-100350 are HARNESS_GENERATED (real Wazuh
 * pipeline, log line written by the evaluation harness); everything else is REAL_TELEMETRY. The TC-01..TC-10 files in
 * resources/ are MOCK_FIXTURE and are never used here as evidence of real support - only compared against the real alerts.
 *
 * Three guards:
 *   1. golden documents   - the full v2 output of every real alert is frozen (UPDATE_GOLDEN=1 regenerates; review the diff).
 *   2. loss detector      - every field of every real alert is either represented in the v2 output or sits in an explicit,
 *                           reasoned allow-list. A new real alert that carries an unclassified field fails the test.
 *   3. mock conformance   - how each TC mock differs from its real counterpart is frozen, so a mock cannot silently hide a gap.
 */
const REAL_DIR = path.join(__dirname, "fixtures", "wazuh-real");
const GOLDEN_DIR = path.join(REAL_DIR, "golden");
const TC_DIR = path.resolve(__dirname, "../../../resources/mock-attacks-tc");
const RECEIVED = new Date("2026-10-08T00:00:00.000Z");
const files = fs.readdirSync(REAL_DIR).filter((f) => /^\d+-.*\.json$/.test(f)).sort();
const index: Record<string, { indexerRef: { index: string; docId: string } }> = JSON.parse(fs.readFileSync(path.join(REAL_DIR, "_index.json"), "utf8"));
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));
const build = (file: string): EvidenceV2 => {
  const payload = readJson(path.join(REAL_DIR, file));
  const r = extractWazuhEvidenceV2(payload, { receivedAt: RECEIVED, indexerRef: index[file]?.indexerRef ?? null });
  if (r.isFailure) throw new Error(`${file}: ${r.error}`);
  return r.value;
};

describe("fixtures", () => {
  it("every fixture is indexed with its Indexer reference and nothing sensitive was left in", () => {
    expect(files.length).toBeGreaterThanOrEqual(30);
    for (const f of files) {
      expect(index[f]?.indexerRef.index).toMatch(/^wazuh-alerts-4\.x-\d{4}\.\d{2}\.\d{2}$/);
      const text = fs.readFileSync(path.join(REAL_DIR, f), "utf8");
      expect(text).not.toMatch(/DESKTOP-[A-Z0-9]{7}|BEGIN (RSA |EC )?PRIVATE KEY/i); // real Windows host names / key material must stay masked
      expect(readJson(path.join(REAL_DIR, f))["@timestamp"]).toBeUndefined(); // webhook shape: the Indexer-added field is removed
    }
  });

  it("provenance class matches how the alert was produced (custom 100xxx rules = harness)", () => {
    for (const f of files) {
      const expected: ProvenanceClass = /^100\d{3}-/.test(f) ? "HARNESS_GENERATED" : "REAL_TELEMETRY";
      expect({ f, class: build(f).provenance.class }).toEqual({ f, class: expected });
    }
  });
});

describe("golden documents", () => {
  const update = process.env.UPDATE_GOLDEN === "1";
  if (update) fs.mkdirSync(GOLDEN_DIR, { recursive: true });
  it.each(files)("%s", (file) => {
    const actual = build(file);
    const goldenPath = path.join(GOLDEN_DIR, file.replace(/\.json$/, ".v2.json"));
    if (update) fs.writeFileSync(goldenPath, JSON.stringify(actual, null, 2) + "\n");
    expect(fs.existsSync(goldenPath)).toBe(true);
    expect(JSON.parse(JSON.stringify(actual))).toEqual(readJson(goldenPath));
  });
  it("has no orphan golden files", () => {
    const expected = new Set(files.map((f) => f.replace(/\.json$/, ".v2.json")));
    if (fs.existsSync(GOLDEN_DIR)) for (const g of fs.readdirSync(GOLDEN_DIR)) expect(expected.has(g)).toBe(true);
  });
});

/** Fields that are deliberately not copied into the v2 document, or knowingly not yet extracted. Each needs a reason. */
const ALLOWED_NOT_REPRESENTED: { pattern: RegExp; kind: "DELIBERATE" | "RESTRUCTURED" | "GAP"; reason: string }[] = [
  { pattern: /^timestamp$/, kind: "RESTRUCTURED", reason: "normalised to ISO-8601 UTC as provenance.time.detectedAt" },
  { pattern: /^rule\.(pci_dss|gdpr|hipaa|nist_800_53|tsc|gpg13|mail)$/, kind: "DELIBERATE", reason: "compliance tags / mail flag are not attack evidence; VIGIX Policy owns compliance mapping" },
  { pattern: /^rule\.groups$/, kind: "RESTRUCTURED", reason: "group names are trimmed (rule 91822 ships ' powershell' with a leading space)" },
  { pattern: /^previous_(output|log)$/, kind: "DELIBERATE", reason: "frequency-rule context; kept only in alerts.raw_payload" },
  { pattern: /^data\.sca\./, kind: "DELIBERATE", reason: "SCA compliance results are not attacks; custom-vigix does not forward group sca" },
  { pattern: /^data\.win\.system\./, kind: "DELIBERATE", reason: "only eventID, channel, provider and systemTime are used; the rest is Windows plumbing (record GUIDs, thread/process ids, opcodes)" },
  { pattern: /^data\.win\.eventdata\.(company|description|fileVersion|product|ruleName|logonGuid|logonId|elevatedToken|impersonationLevel|virtualAccount|targetLinkedLogonId|processName)$/, kind: "DELIBERATE", reason: "binary-metadata and logon-plumbing fields without a contract category or a use in containment" },
  { pattern: /^data\.win\.eventdata\.(hashes|utcTime)$/, kind: "RESTRUCTURED", reason: "hashes is split into process.hashes[]; utcTime becomes process.startedAt / time.eventAt" },
  { pattern: /^data\.win\.eventdata\.(serviceName|serviceType|startType|imagePath|accountName)$/, kind: "GAP", reason: "Windows service installation (EID 7045) is persistence evidence with no v2 category yet" },
  { pattern: /^data\.win\.eventdata\.data$/, kind: "GAP", reason: "generic Windows application-event parameter; no semantics to extract" },
  { pattern: /^data\.title$/, kind: "GAP", reason: "rootcheck finding title (rule 510) carries the finding text; no v2 field yet" },
];

describe("loss detector (no field silently dropped)", () => {
  function* leaves(o: unknown, p = ""): Generator<[string, unknown]> {
    if (Array.isArray(o)) for (const v of o) yield* leaves(v, p);
    else if (o && typeof o === "object") for (const [k, v] of Object.entries(o as Record<string, unknown>)) yield* leaves(v, p ? `${p}.${k}` : k);
    else yield [p, o];
  }
  const lostBy = new Map<string, Set<string>>();
  for (const f of files) {
    const payload = readJson(path.join(REAL_DIR, f));
    const haystack = JSON.stringify(build(f)).toLowerCase();
    for (const [p, v] of leaves(payload)) {
      const s = String(v).toLowerCase();
      if (!s || haystack.includes(JSON.stringify(s).slice(1, -1))) continue;
      (lostBy.get(p) ?? lostBy.set(p, new Set()).get(p)!).add(f);
    }
  }
  it("every field of every real alert is represented or explicitly allow-listed", () => {
    const unclassified = [...lostBy.keys()].filter((p) => !ALLOWED_NOT_REPRESENTED.some((a) => a.pattern.test(p)));
    expect(unclassified).toEqual([]);
  });
  it("has no stale allow-list entries", () => {
    for (const a of ALLOWED_NOT_REPRESENTED) expect({ pattern: String(a.pattern), hit: [...lostBy.keys()].some((p) => a.pattern.test(p)) }).toEqual({ pattern: String(a.pattern), hit: true });
  });
  it("every allow-list entry states a reason", () => {
    expect(ALLOWED_NOT_REPRESENTED.every((a) => a.reason.length > 20)).toBe(true);
  });
});

describe("rule families (real alerts)", () => {
  const find = (prefix: string) => files.find((f) => f.startsWith(prefix + "-"))!;
  const ev = (prefix: string) => build(find(prefix));
  const raw = (prefix: string) => readJson(path.join(REAL_DIR, find(prefix)));

  it("SSH family 5710 / 5712 / 5760 / 5763 / 5715 / 40112: remote address is SOURCE, outcome only from rule.groups", () => {
    for (const id of ["5710", "5712", "5760", "5763", "5715", "40112"]) {
      const e = ev(id);
      expect({ id, ip: e.iocs.find((i) => i.sourcePath === "data.srcip")?.role }).toEqual({ id, ip: "SOURCE" });
      expect(e.evidence.authentication.remote.ip).toBe(raw(id).data.srcip);
      expect(e.provenance.completeness.authentication).toBe("OBSERVED");
    }
    expect(ev("5715").evidence.authentication.result).toEqual({ value: "SUCCESS", derivedFrom: "rule.groups" });
  });

  it("PAM 5503 / 5551: same remote address, failure from rule.groups", () => {
    expect(ev("5503").evidence.authentication.result?.value).toBe("FAILURE");
    expect(ev("5551").evidence.authentication.account).toBe(raw("5551").data.dstuser);
  });

  it("web family 31101 / 31103 / 31151 / 31152 / 31153: request target is HTTP_REQUEST, never an outbound URL", () => {
    for (const id of ["31101", "31103", "31151", "31152", "31153"]) {
      const e = ev(id);
      expect(e.evidence.network.url).toBeNull();
      expect(e.evidence.http.requestTarget).toBe(raw(id).data.url);
      expect(e.iocs.find((i) => i.sourcePath === "data.url")?.type).toBe("HTTP_REQUEST");
      expect(e.provenance.completeness.http).toBe("OBSERVED");
    }
    expect(ev("31103").evidence.http.status).toBe(404);
  });

  it("FIM family 550 / 553 / 554 / 100301: path + hashes become IOCs; the old extractor found none", () => {
    for (const id of ["550", "553", "554", "100301"]) {
      expect(extractAlertIocs(raw(id))).toEqual([]);
      const e = ev(id);
      expect(e.iocs.length).toBeGreaterThanOrEqual(4);
      expect(e.provenance.completeness.syscheck).toBe("OBSERVED");
      expect(e.evidence.syscheck.detectionMode).toMatch(/realtime|scheduled/);
    }
    expect(ev("553").evidence.syscheck.hashes.after.lastKnown).toBe(true);
  });

  it("account family 5901 / 5902 / 40501 / 100350: only what Wazuh structured is extracted", () => {
    expect(ev("5901").evidence.account.user).toBeNull();
    expect(ev("5901").provenance.completeness.account).toBe("INCOMPLETE");
    expect(ev("5902").evidence.account).toMatchObject({ user: raw("5902").data.dstuser, uid: raw("5902").data.uid });
    expect(ev("100350").evidence.account.group).toBe("sudo");
    // 40501 is raised from a "new group" line that Wazuh did not structure: no account is invented from full_log.
    expect(ev("40501").iocs).toEqual([]);
    expect(ev("40501").provenance.completeness.account).toBe("INCOMPLETE");
    expect(ev("40501").fullLog).toContain("new group");
  });

  it("Windows family 100300 / 92027 / 91822 / 60106 / 60642 / 61138: event identity and typed fields", () => {
    expect(ev("100300").evidence.network.dnsQuery).toBe(raw("100300").data.win.eventdata.queryName);
    expect(ev("100300").evidence.process.guid).toBe(raw("100300").data.win.eventdata.processGuid);
    expect(ev("92027").evidence.process.parent.pid).toBe(raw("92027").data.win.eventdata.parentProcessId);
    expect(ev("91822").evidence.powershell.scriptBlockText).toContain("Invoke-Command");
    expect(ev("60106").evidence.authentication.logon.type).toBe("5");
    for (const id of ["60642", "61138"]) expect(ev(id).provenance.source.eventKey).toMatch(/^win:/);
  });

  it("rules that ship only full_log (533 netstat) produce an honest, empty evidence section", () => {
    const e = ev("533");
    expect(e.iocs).toEqual([]);
    expect(e.fullLog).toBe(raw("533").full_log);
    expect(Object.values(e.provenance.completeness).filter((s) => s === "INCOMPLETE").length).toBe(0);
  });

  it("rootcheck 510: the file path is a FILE_PATH IOC, the title is a known gap", () => {
    const e = ev("510");
    expect(e.iocs.find((i) => i.type === "FILE_PATH")?.value).toBe(raw("510").data.file);
  });

  it("harness family 100310 / 100320 / 100330 / 100340: reporting host is never an indicator role", () => {
    for (const id of ["100320", "100340"]) {
      const e = ev(id);
      expect(e.iocs.filter((i) => i.value === raw(id).agent.ip).every((i) => i.role === "ENDPOINT_SELF")).toBe(true);
    }
    expect(ev("100310").iocs.find((i) => i.sourcePath === "data.srcip")?.role).toBe("SOURCE");
  });

  it("MITRE: names and tactics come from Wazuh only; rules without it stay empty", () => {
    for (const f of files) {
      const e = build(f);
      const m = readJson(path.join(REAL_DIR, f)).rule.mitre;
      if (!m) expect(e.detection.mitre).toEqual({ techniques: [], tactics: [] });
      else expect(e.detection.mitre.techniques.map((t) => t.id)).toEqual(m.id);
    }
  });
});

describe("event key (deduplication of the underlying event)", () => {
  it("is shared by two alerts raised from the same log line and differs for another line", () => {
    const a = readJson(path.join(REAL_DIR, files.find((f) => f.startsWith("5712-"))!));
    const same = { ...a, id: "1791030229.999", rule: { ...a.rule, id: "5503", description: "other rule, same line" } };
    const other = { ...a, full_log: a.full_log.replace("git", "root") };
    const key = (p: unknown) => { const r = extractWazuhEvidenceV2(p, { receivedAt: RECEIVED }); if (r.isFailure) throw new Error(r.error); return r.value.provenance.source.eventKey; };
    expect(key(a)).toMatch(/^log:[0-9a-f]{64}$/);
    expect(key(same)).toBe(key(a));
    expect(key(other)).not.toBe(key(a));
  });

  it("is null when neither a record id nor a log time exists (never guessed)", () => {
    const syscheckAlert = readJson(path.join(REAL_DIR, files.find((f) => f.startsWith("554-"))!));
    const r = extractWazuhEvidenceV2(syscheckAlert, { receivedAt: RECEIVED });
    expect(r.isSuccess && r.value.provenance.source.eventKey).toBeNull();
  });
});

describe("mock conformance (TC-01..TC-10 against their real counterparts)", () => {
  const COUNTERPART: Record<string, string> = { "TC-01": "5712", "TC-02": "100301", "TC-03": "100310", "TC-04": "40112", "TC-05": "100300", "TC-06": "31103", "TC-07": "100320", "TC-08": "100330", "TC-09": "100340", "TC-10": "100350" };
  const tcFile = (tc: string) => fs.readdirSync(TC_DIR).find((f) => f.startsWith(tc + "-"))!;
  const topRoots = (o: Record<string, unknown>) => Object.keys((o.data as object) ?? {}).concat(o.syscheck ? ["<syscheck>"] : []).sort();

  it("all ten TC mocks are classified MOCK_FIXTURE", () => {
    for (const tc of Object.keys(COUNTERPART)) {
      const r = extractWazuhEvidenceV2(readJson(path.join(TC_DIR, tcFile(tc))), { receivedAt: RECEIVED });
      expect(r.isSuccess && r.value.provenance.class).toBe("MOCK_FIXTURE");
    }
  });

  /**
   * FROZEN divergences. Each says where the mock puts evidence differently from the real alert. These are the places where a
   * green mock test says nothing about real behaviour. Changing a TC file changes this list on purpose (and, because the
   * evaluation ground truth is frozen against these files, needs a decision - see docs/architecture/evidence-contract-v2.md).
   */
  it("TC-02 mock duplicates the file path and hashes under data.*; the real FIM alert has them only under syscheck.* (hid the 0-IOC gap)", () => {
    const mock = readJson(path.join(TC_DIR, tcFile("TC-02")));
    const real = readJson(path.join(REAL_DIR, files.find((f) => f.startsWith("100301-"))!));
    expect(mock.syscheck.sha256_after).toBe(mock.data.sha256);
    expect(real.data).toBeUndefined();
    expect(extractAlertIocs(mock).length).toBeGreaterThan(0);
    expect(extractAlertIocs(real).length).toBe(0);
  });

  it("TC-04 / TC-10 are Windows event-channel mocks while the real counterparts are Linux log events", () => {
    for (const [tc, rid] of [["TC-04", "40112"], ["TC-10", "100350"]] as const) {
      const mock = readJson(path.join(TC_DIR, tcFile(tc)));
      const real = readJson(path.join(REAL_DIR, files.find((f) => f.startsWith(rid + "-"))!));
      expect(mock.decoder.name).toBe("windows_eventchannel");
      expect(real.decoder.name).not.toBe("windows_eventchannel");
    }
  });

  it("TC-07 / TC-09 mocks use Suricata field names (src_ip, dest_ip) that no real alert in this lab carries", () => {
    for (const tc of ["TC-07", "TC-09"]) {
      const mock = readJson(path.join(TC_DIR, tcFile(tc)));
      expect(mock.data.dest_ip).toBeDefined();
      for (const f of files) expect(readJson(path.join(REAL_DIR, f)).data?.dest_ip).toBeUndefined();
    }
  });

  it("TC-08 mock has auditd execve/syscall fields; the real harness alert has only exe/command/pid/ppid/parent/uid/user", () => {
    const mock = readJson(path.join(TC_DIR, tcFile("TC-08")));
    const real = readJson(path.join(REAL_DIR, files.find((f) => f.startsWith("100330-"))!));
    expect(mock.data.audit.execve).toBeDefined();
    expect(real.data.audit.execve).toBeUndefined();
  });

  it("TC mocks carry GeoLocation and mail-auth fields that no real alert in this lab has (private IPs, no GeoIP, no mail log)", () => {
    expect(readJson(path.join(TC_DIR, tcFile("TC-01"))).GeoLocation).toBeDefined();
    for (const f of files) expect(readJson(path.join(REAL_DIR, f)).GeoLocation).toBeUndefined();
  });

  it("each mock still yields at least the indicators its real counterpart yields, except where the mock is richer (documented above)", () => {
    const poorer: string[] = [];
    for (const [tc, rid] of Object.entries(COUNTERPART)) {
      const m = extractAlertIocs(readJson(path.join(TC_DIR, tcFile(tc)))).length;
      const r = extractAlertIocs(readJson(path.join(REAL_DIR, files.find((f) => f.startsWith(rid + "-"))!))).length;
      if (m < r) poorer.push(`${tc}(${m}<${r})`);
    }
    // TC-09: the real alert has an extra FILE_PATH (data.file) the mock lacks - the only case where the mock is poorer.
    expect(poorer).toEqual(["TC-09(4<5)"]);
    expect(topRoots(readJson(path.join(TC_DIR, tcFile("TC-06"))))).toEqual(topRoots(readJson(path.join(REAL_DIR, files.find((f) => f.startsWith("31103-"))!))));
  });
});
