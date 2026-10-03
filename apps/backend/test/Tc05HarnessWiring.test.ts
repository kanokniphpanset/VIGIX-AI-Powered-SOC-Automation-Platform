/**
 * Tc05HarnessWiring.test.ts - TC-05 (PowerShell, REAL Windows endpoint) is wired into the REAL_WAZUH evaluation harness.
 * Pure tests: no LLM, no database, no Wazuh, no network. They check that the harness configuration is consistent with
 * the evidence collected from the real scenario and that nothing in it fabricates telemetry or results.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { REAL_GROUND_TRUTH } from "../src/evaluation/groundTruthReal";
import { CORRECTNESS_GROUND_TRUTH, correctnessGroundTruthByCase } from "../src/evaluation/groundTruthCorrectness";
import { evaluateCorrectRecommendation } from "../src/evaluation/correctRecommendation";
import { extractAlertIocs, REHUNT_IOC_TYPES } from "../src/domain/investigation/alertIocs";
import { isExpectedIocPresent } from "../src/evaluation/iocRecall";
import { INCIDENT_PLAYBOOKS } from "../prisma/seeds/playbook.seed";
import { ENDPOINT_AGENT, WINDOWS_AGENT, TC05_SCENARIO, agentForCase, alertWaitMsForCase, simulate } from "../scripts/eval/simulations";
import { RunRehuntVerificationUseCase } from "../src/application/verification/use-cases/RunRehuntVerification.usecase";
import { DEFAULT_IOC_FIELDS, WazuhRehuntAdapter } from "../src/infrastructure/external-services/siem/WazuhRehuntAdapter";
import { Result } from "../src/shared/result/Result";

const gt = REAL_GROUND_TRUTH.find((g) => g.caseId === "TC-05")!;
const DOMAIN = "vigix-eval-ps-stager.test";

/** The REAL alert (rule 100300, id 1791021998.1683057, 2026-10-03 10:06:38Z) as the manager produced it and VIGIX stored it. */
const realAlert = {
  agent: { id: "010", name: "vigix-win10-ps", ip: "192.168.239.129" },
  rule: { id: "100300", level: 12, description: "VIGIX-EVAL: PowerShell resolved a lab stager hostname (Sysmon DNS query)", mitre: { id: ["T1059.001"] } },
  data: { win: {
    system: { eventID: "22", channel: "Microsoft-Windows-Sysmon/Operational", providerName: "Microsoft-Windows-Sysmon", computer: "DESKTOP-3MP7GB3" },
    eventdata: { ruleName: "ps-dns", utcTime: "2026-10-03 10:06:35.302", processId: "5976", queryName: DOMAIN, queryStatus: "9003",
      image: "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", user: "DESKTOP-3MP7GB3\\\\kanoknipha" },
  } },
};

describe("TC-05 ground truth in the real-evaluation harness", () => {
  it("is no longer ENVIRONMENT_UNAVAILABLE and describes the real scenario (rule 100300, level 12, T1059.001, DOMAIN IOC)", () => {
    expect(gt.mode).not.toBe("ENVIRONMENT_UNAVAILABLE");
    expect(gt.mode).toBe("CUSTOM_RULE_REAL_ACTION");
    expect(gt.ruleId).toBe("100300");
    expect(gt.expectedWazuh).toEqual({ ruleId: "100300", level: 12, stockRule: false });
    expect(gt.expectedMitre).toEqual(["T1059.001"]);
    expect(gt.expectedSeverity).toBe("high");
    expect(gt.expectedIocs).toEqual([{ type: "domain", value: DOMAIN }]);
    expect(gt.expectedPlaybook).toBe("PB-POWERSHELL");
    expect(gt.environmentNote).toBeUndefined();
  });
  it("expects exactly BLOCK-DOMAIN -> the domain; ISOLATE-ENDPOINT is not expected; the allowed set is unchanged", () => {
    expect(gt.expectedActions).toEqual(["ACT-BLOCK-DOMAIN"]);
    expect(gt.expectedTargets).toEqual([DOMAIN]);
    expect(gt.allowedActions).toEqual(["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH"]);
    expect(gt.knownFindings.join(" ")).toMatch(/ISOLATE-ENDPOINT is not an expected action/);
  });
  it("agrees with Correct Recommendation GT v3.3 for TC-05 (the two sources cannot drift) and the runner will evaluate it", () => {
    const c = correctnessGroundTruthByCase("TC-05")!;
    expect(c.expectedPlaybook).toBe(gt.expectedPlaybook);
    expect(c.expectedRecommendations.map((r) => r.action)).toEqual(gt.expectedActions);
    expect(c.expectedRecommendations.flatMap((r) => r.targets.map((t) => t.value))).toEqual(gt.expectedTargets);
    expect(c.expectedRecommendations.length).toBeGreaterThan(0); // the runner only scores a case whose correctness GT has pairs
  });
  it("strict pair matching applies: TC-05 -> PB-POWERSHELL -> BLOCK-DOMAIN -> the domain is correct; anything extra is not", () => {
    const c = correctnessGroundTruthByCase("TC-05")!;
    const ok = [{ action: "ACT-BLOCK-DOMAIN", target: DOMAIN, targetType: "domain" }];
    expect(evaluateCorrectRecommendation(c, { playbook: "PB-POWERSHELL", steps: ok }).correct).toBe(true);
    expect(evaluateCorrectRecommendation(c, { playbook: "PB-POWERSHELL", steps: [...ok, { action: "ACT-ISOLATE-ENDPOINT", target: "vigix-win10-ps", targetType: "host" }] }).correct).toBe(false);
  });
  it("the other cases keep their correctness GT (TC-02/04/08 untouched by this wiring)", () => {
    expect(CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === "TC-02")!.expectedRecommendations).toHaveLength(3);
    expect(CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === "TC-04")!.expectedRecommendations).toHaveLength(3);
    expect(CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === "TC-08")!.expectedRecommendations).toHaveLength(3);
  });
  it("matches the installed custom rule 100300 (level 12, T1059.001, this exact domain)", () => {
    const xml = fs.readFileSync(path.join(__dirname, "../../../infra/docker/wazuh-manager/vigix_eval_rules.xml"), "utf8");
    const rule = xml.slice(xml.indexOf('<rule id="100300"'), xml.indexOf("</rule>", xml.indexOf('<rule id="100300"')));
    expect(rule).toContain(`level="${gt.expectedWazuh.level}"`);
    expect(rule).toContain("<id>T1059.001</id>");
    expect(rule).toContain(DOMAIN.replace(/\./g, "\\."));
  });
  it("PB-POWERSHELL is the only playbook triggered by T1059.001, and BLOCK-DOMAIN is allowed by it", () => {
    expect(INCIDENT_PLAYBOOKS.filter((p) => p.mitreTechniques.includes("T1059.001")).map((p) => p.code)).toEqual(["PB-POWERSHELL"]);
    expect(INCIDENT_PLAYBOOKS.find((p) => p.code === "PB-POWERSHELL")!.allowedActions).toContain("ACT-BLOCK-DOMAIN");
  });
});

describe("TC-05 simulation/environment definition (trigger only - never telemetry)", () => {
  it("reads TC-05 from the Windows agent and every other case from attack-endpoint", () => {
    expect(WINDOWS_AGENT).toBe("vigix-win10-ps");
    expect(agentForCase("TC-05")).toBe(WINDOWS_AGENT);
    for (const id of ["TC-01", "TC-02", "TC-03", "TC-04", "TC-06", "TC-07", "TC-08", "TC-09", "TC-10"]) expect(agentForCase(id)).toBe(ENDPOINT_AGENT);
  });
  it("the scenario definition names the real command, the domain, the rule and the expected telemetry", () => {
    expect(TC05_SCENARIO.agent).toBe(WINDOWS_AGENT);
    expect(TC05_SCENARIO.domain).toBe(DOMAIN);
    expect(TC05_SCENARIO.command).toContain(`GetHostAddresses('${DOMAIN}')`);
    expect(TC05_SCENARIO.expectedRule).toEqual({ id: "100300", level: 12, mitre: "T1059.001" });
    expect(TC05_SCENARIO.expectedTelemetry).toMatch(/Sysmon event 22/);
  });
  it("an operator-triggered case waits longer for the alert than a scripted one", () => {
    expect(alertWaitMsForCase("TC-01")).toBe(150000);
    expect(alertWaitMsForCase("TC-05")).toBeGreaterThan(150000);
  });
  it("simulate(TC-05) reports REAL Windows telemetry, not ENVIRONMENT_UNAVAILABLE, and does not generate an alert", async () => {
    const r = await simulate("TC-05", {});
    expect(r.telemetry).toBe("REAL_WINDOWS_SYSMON_CUSTOM_RULE");
    expect(r.facts).toMatchObject({ windowsAgent: WINDOWS_AGENT, domain: DOMAIN, triggerMode: "manual" });
    expect(r.notes.join(" ")).toMatch(/Nothing is simulated by the harness/);
  });
  it("the harness has no code path that writes an alert or event for TC-05 (no indexer write, no mock payload)", () => {
    const src = fs.readFileSync(path.join(__dirname, "../scripts/eval/simulations.ts"), "utf8");
    const tc05 = src.slice(src.indexOf('case "TC-05"'), src.indexOf("default:", src.indexOf('case "TC-05"')));
    expect(tc05).not.toMatch(/appendTelemetry|events\.json|_bulk|_doc|resources\/mock-attacks/);
    expect(fs.readFileSync(path.join(__dirname, "../scripts/eval/indexerClient.ts"), "utf8")).not.toMatch(/"PUT"|"DELETE"/); // read-only indexer client
  });
});

describe("TC-05 IOC -> verification/re-hunt path (REAL alert payload, REAL adapter, fake transport only)", () => {
  const iocs = extractAlertIocs(realAlert);

  it("the extractor reads the DOMAIN from the real alert and the expected IOC is present (recall 1/1)", () => {
    expect(iocs.find((i) => i.iocType === "DOMAIN")).toMatchObject({ value: DOMAIN, path: "data.win.eventdata.queryName" });
    expect(gt.expectedIocs.every((e) => isExpectedIocPresent(e, iocs.map((i) => ({ iocValue: i.value }))))).toBe(true);
    expect(REHUNT_IOC_TYPES).toContain("DOMAIN");
  });

  it("RunRehuntVerification sends that DOMAIN to the Wazuh adapter, which searches data.win.eventdata.queryName for it", async () => {
    const mapping = { fields: { ...Object.fromEntries(Object.values(DEFAULT_IOC_FIELDS).flat().map((f) => [f, { keyword: { searchable: true } }])), timestamp: { date: { searchable: true } } } };
    const searches: any[] = [];
    const transport = jest.fn(async (method: string, p: string, b?: unknown) => {
      if (method === "GET") return { status: 200, body: p.includes("/_mapping/") ? { idx: { mappings: { timestamp: { mapping: { timestamp: { type: "date" } } }, "@timestamp": { mapping: { "@timestamp": { type: "date" } } } } } } : mapping };
      searches.push(b);
      return { status: 200, body: { timed_out: false, _shards: { total: 1, successful: 1, failed: 0 }, hits: { total: { value: 0, relation: "eq" }, hits: [] }, aggregations: { missing_timestamp: { doc_count: 0 }, hosts: { buckets: [] }, ioc_events: { doc_count: 0 } } } };
    });
    const adapter = new WazuhRehuntAdapter({ url: "https://indexer.example:9200", username: "u", password: "p" }, transport as any);
    const spy = jest.spyOn(adapter, "rehunt");
    const created = jest.fn().mockResolvedValue(Result.ok({ id: "v1", result: "RESOLVED" }));
    const useCase = new RunRehuntVerificationUseCase(
      adapter,
      { execute: created } as any,
      { findById: jest.fn().mockResolvedValue({ id: "i1", tenantId: "t", alertId: "a1", investigationNumber: 1 }), incrementInvestigationNumber: jest.fn(), updateStatus: jest.fn() } as any,
      { findById: jest.fn().mockResolvedValue({ id: "a1", rawPayload: realAlert }) } as any,
      { findById: jest.fn().mockResolvedValue({ id: "r1", tenantId: "t", incidentId: "i1", status: "COMPLETED", target: DOMAIN, completedAt: new Date("2026-10-03T10:20:00Z"), updatedAt: new Date("2026-10-03T10:20:00Z") }) } as any,
      { findAllByIncident: jest.fn().mockResolvedValue([]) } as any,
      { getIocs: jest.fn().mockResolvedValue(iocs.map((i) => ({ iocType: i.iocType, iocValue: i.value }))) } as any,
      { listByIncident: jest.fn().mockResolvedValue([]), createEvidence: jest.fn().mockResolvedValue(undefined) } as any
    );
    const res = await useCase.execute({ incidentId: "i1", responseId: "r1", tenantId: "t", verifiedBy: "ir" });
    expect(res.isSuccess).toBe(true);
    expect(searches).toHaveLength(1);
    const dsl = JSON.stringify(searches[0]);
    expect(dsl).toContain(`{"term":{"data.win.eventdata.queryName":{"value":"${DOMAIN}"}}}`); // the IOC is searched in the field the Sysmon event carries
    // WazuhRehuntAdapter searches by IOC only (the detection-rule signature is passed along but is not part of its query),
    // so the verification of TC-05 rests entirely on this DOMAIN IOC.
    expect(dsl).not.toContain("rule.id\":\"100300");
    // what the use case handed to the adapter: the DOMAIN IOC, the alerting agent as the incident host, the rule signature
    const q = spy.mock.calls[0][0];
    expect(q.iocs).toEqual([{ type: "DOMAIN", value: DOMAIN }]);   // process / user are host facts and are not hunted
    expect(q.hosts).toContain("vigix-win10-ps");
    expect(q.rule).toMatchObject({ id: "100300" });
    // the verification result is whatever the evidence says: nothing in this harness sets it
    const recorded = created.mock.calls[0][0];
    expect(recorded.afterState.searchedIocs).toEqual([{ type: "DOMAIN", value: DOMAIN }]);  // the verification records what was actually searched
    expect(recorded.afterState.excludedIocs).toEqual([]);                                   // the domain is not mistaken for the endpoint's identity
  });
});
