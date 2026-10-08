import { SCENARIOS, Scenario, TENANT, buildContext, generate, validator } from "./helpers/containmentScenarios";
import { IRetrievedKnowledgePort } from "../src/application/recommendation/ports/IRetrievedKnowledgePort";
import { RecommendationContextRetrievedKnowledge } from "../src/application/recommendation/dto/RecommendationContextDto";
import { deriveEvidenceSignals } from "../src/domain/knowledge/evidenceSignals";
import { ContainmentProcedureLoader, ContainmentProcedureError } from "../src/infrastructure/knowledge/ContainmentProcedureLoader";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/**
 * The Recommendation Agent is NOT a universal response template. Each attack type has its own response; steps are
 * offered only when the incident's evidence supports them; an unknown incident is investigation-first. The
 * validator rejects prose that assumes facts, irrelevant phases and controls copied from another attack's playbook.
 */
const base = (id: string, over: Partial<Scenario> = {}): Scenario => ({ ...SCENARIOS.find((s) => s.caseId === id)!, ...over });

type Rec = Awaited<ReturnType<typeof generate>>["created"][number];
const run = async (s: Scenario, retriever?: IRetrievedKnowledgePort) => {
  const out = await generate(s, undefined, retriever);
  return { ok: out.result.isSuccess, rec: out.created[0] as Rec | undefined, audit: out.audit };
};
const actions = (rec?: Rec) => (rec?.steps ?? []).filter((s) => s.stepType === "ACTION").map((s) => String(s.actionId).replace("action-", ""));
const allText = (rec?: Rec) => JSON.stringify(rec?.steps ?? []) + (rec?.summary ?? "");

describe("1-2. attack-specific responses", () => {
  it("TEST 1 SQL injection: application / WAF / database-specific response", async () => {
    const { ok, rec } = await run(base("TC-06"));
    expect(ok).toBe(true);
    expect(actions(rec)).toContain("ACT-BLOCK-SOURCE-IP");
    const manual = rec!.steps.filter((s) => s.stepType === "MANUAL").map((s) => s.objective).join(" | ");
    expect(manual).toMatch(/WAF rule/);
    expect(manual).toMatch(/restrict the affected endpoint/i);
    expect(allText(rec)).toMatch(/database/i);
  });

  it("TEST 2 Malware: endpoint / process / persistence response, no SQL injection actions", async () => {
    const { ok, rec } = await run(base("TC-02"));
    expect(ok).toBe(true);
    expect(actions(rec).some((a) => ["ACT-ISOLATE-ENDPOINT", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH"].includes(a))).toBe(true);
    expect(allText(rec)).toMatch(/persist/i);
    expect(allText(rec)).not.toMatch(/WAF rule|parameteri[sz]ed|prepared statement|vulnerable (web )?(parameter|endpoint)/i);
  });
});

describe("3-4. brute force: failures only vs suspicious success", () => {
  it("TEST 3 failures only: no session revocation, credential reset or account disabling", async () => {
    const ctx = await buildContext(base("TC-01"));
    expect(ctx.signals).not.toContain("SUCCESSFUL_LOGIN");
    expect(ctx.containmentProcedure!.steps.map((s) => s.title)).not.toContain("Protect Targeted Account");
    const { ok, rec } = await run(base("TC-01"));
    expect(ok).toBe(true);
    expect(actions(rec)).toContain("ACT-BLOCK-SOURCE-IP");
    expect(actions(rec).filter((a) => ["ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION", "ACT-DISABLE-ACCOUNT"].includes(a))).toEqual([]);
    expect(ctx.transitions).toEqual([]);
  });

  it("TEST 4 brute force + suspicious successful login: expands into the Account Compromise response", async () => {
    const s = base("TC-01", { facts: ["Successful SSH login for root from 185.220.101.45 after repeated failures"] });
    const ctx = await buildContext(s);
    expect(ctx.signals).toContain("SUCCESSFUL_LOGIN");
    expect(ctx.transitions).toEqual([{ from: "BRUTE_FORCE", to: "ACCOUNT_COMPROMISE", stepOrder: 4, because: ["SUCCESSFUL_LOGIN"] }]);
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(actions(rec)).toEqual(expect.arrayContaining(["ACT-BLOCK-SOURCE-IP", "ACT-REVOKE-SESSION"]));
    expect(allText(rec)).toMatch(/Account Compromise/);
    // The reset stays a conditional action carrying its human-confirmed precondition.
    const revoke = rec!.steps.find((st) => st.actionId === "action-ACT-REVOKE-SESSION")!;
    expect(revoke.precondition).toBeTruthy();
  });
});

describe("5-7. phishing branches", () => {
  const received = { title: "Phishing e-mail delivered to the HR mailbox hr.clerk", facts: [] as string[] };

  it("TEST 5 phishing received only: no credential reset, session revocation or isolation", async () => {
    const s = base("TC-03", received);
    const ctx = await buildContext(s);
    expect(ctx.signals).not.toEqual(expect.arrayContaining(["USER_CLICKED"]));
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(actions(rec).filter((a) => ["ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION", "ACT-DISABLE-ACCOUNT", "ACT-ISOLATE-ENDPOINT"].includes(a))).toEqual([]);
    expect(actions(rec).length).toBeGreaterThan(0);
  });

  it("TEST 6 phishing + credential submission: credential / session response appears (conditional)", async () => {
    const s = base("TC-03", { ...received, facts: ["hr.clerk submitted credentials on the fake Office 365 page"] });
    const ctx = await buildContext(s);
    expect(ctx.signals).toContain("CREDENTIAL_SUBMITTED");
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(actions(rec)).toContain("ACT-RESET-CREDENTIAL");
    expect(rec!.steps.find((st) => st.actionId === "action-ACT-RESET-CREDENTIAL")!.precondition).toBeTruthy();
  });

  it("TEST 7 phishing + malicious payload execution: the Malware branch appears", async () => {
    const s = base("TC-03", { ...received, facts: ["The attachment was executed on HR-WS-03"] });
    const ctx = await buildContext(s);
    expect(ctx.signals).toContain("PAYLOAD_EXECUTED");
    expect(ctx.transitions).toEqual([{ from: "PHISHING", to: "MALWARE", stepOrder: 5, because: ["PAYLOAD_EXECUTED"] }]);
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(allText(rec)).toMatch(/Malware/);
    expect(actions(rec)).toContain("ACT-ISOLATE-ENDPOINT");
  });
});

describe("8-9. PowerShell", () => {
  it("TEST 8 legitimate administration: validate only, no containment or isolation", async () => {
    const s = base("TC-05", {
      title: "PowerShell script executed by IT administrator for scheduled maintenance", host: "ADM-WS-01",
      iocs: [{ iocType: "USERNAME", iocValue: "it.admin" }], evidenceIocs: ["it.admin"],
    });
    const ctx = await buildContext(s);
    expect(ctx.signals).not.toContain("MALICIOUS_EXECUTION");
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(actions(rec)).toEqual([]);
    expect(rec!.steps.every((st) => st.stepType === "CHECK")).toBe(true);
  });

  it("TEST 9 malicious execution: containment and investigation appear", async () => {
    const ctx = await buildContext(base("TC-05"));
    expect(ctx.signals).toContain("MALICIOUS_EXECUTION");
    const { ok, rec } = await run(base("TC-05"));
    expect(ok).toBe(true);
    expect(actions(rec).length).toBeGreaterThan(0);
    expect(rec!.steps.some((st) => st.stepType === "CHECK")).toBe(true);
  });
});

describe("10-13. C2, suspicious process, data exfiltration, privilege escalation", () => {
  it("TEST 10 C2: host / C2-infrastructure containment, no WAF SQL injection actions", async () => {
    const { ok, rec } = await run(base("TC-07"));
    expect(ok).toBe(true);
    expect(actions(rec)).toEqual(expect.arrayContaining(["ACT-BLOCK-DESTINATION-IP"]));
    expect(allText(rec)).not.toMatch(/WAF rule|parameteri[sz]ed|prepared statement/i);
  });

  it("TEST 11 suspicious process with insufficient evidence: investigation first, no kill / isolation", async () => {
    const s = base("TC-08", {
      title: "Unrecognised process updater started from /tmp/.cache", iocs: [{ iocType: "PROCESS", iocValue: "/tmp/.cache/updater" }], evidenceIocs: ["/tmp/.cache/updater"],
    });
    const ctx = await buildContext(s);
    expect(ctx.signals).not.toContain("MALICIOUS_EXECUTION");
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(actions(rec)).toEqual([]);
    expect(rec!.steps.every((st) => st.stepType === "CHECK")).toBe(true);
  });

  it("TEST 12 data exfiltration: destination / source / exposure investigation, no breach claimed without evidence", async () => {
    const { ok, rec } = await run(base("TC-09"));
    expect(ok).toBe(true);
    expect(actions(rec)).toContain("ACT-BLOCK-DESTINATION-IP");
    expect(allText(rec)).toMatch(/data/i);
    expect(allText(rec)).not.toMatch(/breach (is |was )?confirmed|confirmed (data )?breach/i);
  });

  it("TEST 13 privilege escalation: privilege-specific response", async () => {
    const s = base("TC-10");
    const ctx = await buildContext(s);
    expect(ctx.attackType).not.toBeNull();
    const { ok, rec } = await run(s);
    expect(ok).toBe(true);
    expect(allText(rec)).toMatch(/privilege|account/i);
    expect(allText(rec)).not.toMatch(/WAF rule|parameteri[sz]ed/i);
  });
});

describe("14-15. unknown incident", () => {
  const unknown = (over: Partial<Scenario> = {}): Scenario =>
    base("TC-06", { caseId: "TC-UNK", attackType: "UNKNOWN", mitre: "T9999", techniques: ["T9999"], title: "Unusual outbound connection pattern from the kiosk", host: "KIOSK-01", iocs: [{ iocType: "IPV4", iocValue: "203.0.113.50", networkRole: "destination" }], evidenceIocs: ["203.0.113.50"], ...over });

  it("TEST 14 limited evidence: investigation and missing-evidence steps only, no manufactured lifecycle", async () => {
    const ctx = await buildContext(unknown());
    expect(ctx.playbook).toBeNull();
    expect(ctx.investigationOnly).toBe(true);
    const { ok, rec } = await run(unknown());
    expect(ok).toBe(true);
    expect(rec!.steps.map((s) => s.stepType)).toEqual(["CHECK", "CHECK", "CHECK"]);
    expect(actions(rec)).toEqual([]);
    expect(allText(rec)).toMatch(/missing evidence/i);
    expect(allText(rec)).not.toMatch(/credential|rotate|reimage|restore|WAF|isolate/i);
  });

  const knowledge: RecommendationContextRetrievedKnowledge[] = [
    { ref: "K1", source: "IR_KNOWLEDGE", title: "Contain a suspected beaconing kiosk", phase: "SELECT_ACTION", guidance: "Move the kiosk to a quarantine VLAN while the beaconing is analysed", kind: "MANUAL", requiresApproval: true },
    { ref: "K2", source: "CASE_KNOWLEDGE", title: "Beaconing triage case", phase: "ASSESS", guidance: "Review proxy and DNS logs of the kiosk for periodic connections to the destination", kind: "CHECK", requiresApproval: false },
  ];
  const retriever: IRetrievedKnowledgePort = { retrieve: async () => knowledge };

  it("TEST 15 strong evidence + retrieved knowledge: a dynamic response grounded in that knowledge", async () => {
    const { ok, rec } = await run(unknown({ facts: ["Periodic beaconing to 203.0.113.50 every 60 seconds"] }), retriever);
    expect(ok).toBe(true);
    const manual = rec!.steps.find((s) => s.stepType === "MANUAL")!;
    expect(manual.objective).toMatch(/quarantine VLAN/);
    expect(manual.requiresApproval).toBe(true);
    expect(actions(rec)).toEqual([]);
    expect(rec!.steps.length).toBe(5); // 3 investigation + the 2 retrieved items — nothing else is invented
  });

  it("a dynamic step must cite knowledge that was actually retrieved", async () => {
    const ctx = await buildContext(unknown(), true, retriever);
    const step = (extra: Record<string, unknown>) => ({
      stepOrder: 1, type: "MANUAL", phase: "SELECT_ACTION", action: null, runbook: null, procedureStep: null, target: null, responsibleRole: "IR_TEAM",
      objective: "Move the kiosk to a quarantine VLAN while the beaconing is analysed", reason: "Retrieved IR knowledge.", evidenceRefs: ["T9999"],
      instructions: [{ order: 1, instruction: "Move the kiosk to a quarantine VLAN.", target: null, expectedResult: null }], verificationCriteria: "Kiosk isolated.", requiresApprovalSuggested: true,
      knowledgeRefs: ["K1"], ...extra,
    });
    const ok = await validator.validate({ summary: "Investigate the kiosk.", steps: [step({})] }, ctx, TENANT);
    expect(ok.violations).toEqual([]);
    expect((await validator.validate({ summary: "Investigate the kiosk.", steps: [step({ knowledgeRefs: ["K99"] })] }, ctx, TENANT)).violations.join("\n")).toMatch(/INVENTED_EVIDENCE|UNGROUNDED_STEP/);
    expect((await validator.validate({ summary: "Investigate the kiosk.", steps: [step({ knowledgeRefs: [] })] }, ctx, TENANT)).violations.join("\n")).toMatch(/UNGROUNDED_STEP/);
  });
});

describe("16. validation rejects what the evidence does not support", () => {
  const check = (stepOrder: number, procedureStep: number, extra: Record<string, unknown> = {}) => ({
    stepOrder, type: "CHECK", action: null, runbook: null, procedureStep, target: null, responsibleRole: "IR_TEAM", playbook: null,
    objective: "Determine what the observed behaviour is.", reason: "The behaviour has to be understood first.", evidenceRefs: ["T9999"],
    instructions: [{ order: 1, instruction: "Review the alert and the recorded evidence.", target: null, expectedResult: null }], verificationCriteria: "Behaviour classified.", ...extra,
  });
  const codes = (o: { violations: string[] }) => o.violations.map((v) => v.split(":")[0]);
  const unknownScenario = base("TC-06", { caseId: "TC-UNK", attackType: "UNKNOWN", mitre: "T9999", techniques: ["T9999"], title: "Unusual outbound connection pattern from the kiosk", host: "KIOSK-01", iocs: [{ iocType: "IPV4", iocValue: "203.0.113.50", networkRole: "destination" }], evidenceIocs: ["203.0.113.50"] });

  it("a containment phase on an investigation-only step is IRRELEVANT_PHASE", async () => {
    const ctx = await buildContext(unknownScenario);
    expect(codes(await validator.validate({ summary: "Investigate.", steps: [check(1, 1, { phase: "SELECT_ACTION" })] }, ctx, TENANT))).toContain("IRRELEVANT_PHASE");
    expect((await validator.validate({ summary: "Investigate.", steps: [check(1, 1, { phase: "VALIDATE" })] }, ctx, TENANT)).violations).toEqual([]);
  });

  it("a catalog Action is rejected for an unknown incident", async () => {
    const ctx = await buildContext(unknownScenario);
    const action = { ...check(2, 1), type: "ACTION", action: "ACT-BLOCK-DESTINATION-IP", runbook: "RB-BLOCK-DESTINATION-IP", target: "203.0.113.50", playbook: "PB-C2" };
    expect(codes(await validator.validate({ summary: "Block it.", steps: [check(1, 1), action] }, ctx, TENANT))).toContain("NO_PLAYBOOK");
  });

  it("UNSUPPORTED_ASSUMPTION: failed logins presented as a compromised account", async () => {
    const ctx = await buildContext(base("TC-01"));
    const step = { ...check(1, 1, { playbook: "PB-SSH-BRUTEFORCE", evidenceRefs: ["E1", "T1110"], reason: "The account root was compromised by the attacker." }) };
    expect(codes(await validator.validate({ summary: "Brute force against root.", steps: [step] }, ctx, TENANT))).toContain("UNSUPPORTED_ASSUMPTION");
    const hedged = { ...step, reason: "Determine whether the account root was compromised." };
    expect(codes(await validator.validate({ summary: "Brute force against root.", steps: [hedged, { ...hedged, stepOrder: 2 }] }, ctx, TENANT))).not.toContain("UNSUPPORTED_ASSUMPTION");
  });

  it("UNSUPPORTED_ASSUMPTION: a data breach claimed from an exfiltration alert without evidence of the transfer is not needed for the exfiltration incident type", async () => {
    const ctx = await buildContext(base("TC-07")); // C2 incident, no transfer evidence
    const step = check(1, 1, { playbook: "PB-C2", evidenceRefs: ["E1"], reason: "A confirmed data breach has occurred." });
    expect(codes(await validator.validate({ summary: "C2.", steps: [step] }, ctx, TENANT))).toContain("UNSUPPORTED_ASSUMPTION");
  });

  it("UNRELATED_ATTACK_CONTROL: a WAF SQL-injection control copied into a malware response", async () => {
    const ctx = await buildContext(base("TC-02"));
    const manual = { ...check(1, 1, { playbook: "PB-MALWARE", evidenceRefs: ["E1"], type: "MANUAL", objective: "Add a WAF rule that blocks the payload pattern", instructions: [{ order: 1, instruction: "Add a WAF rule for the payload.", target: null, expectedResult: null }] }) };
    expect(codes(await validator.validate({ summary: "Malware.", steps: [manual] }, ctx, TENANT))).toContain("UNRELATED_ATTACK_CONTROL");
  });

  it("STATUS_MISMATCH: CONFIRMED needs evidence and no open condition; CONDITIONAL needs its condition", async () => {
    const ctx = await buildContext(unknownScenario);
    expect(codes(await validator.validate({ summary: "Investigate.", steps: [check(1, 1, { status: "CONFIRMED", evidenceRefs: [] })] }, ctx, TENANT))).toContain("STATUS_MISMATCH");
    expect(codes(await validator.validate({ summary: "Investigate.", steps: [check(1, 1, { status: "CONDITIONAL" })] }, ctx, TENANT))).toContain("CONDITION_MISSING");
  });
});

describe("evidence signals and gated knowledge", () => {
  it("signals come only from recorded evidence, hedged or absent evidence gives none", () => {
    const sig = (title: string, techniques: string[] = []) => [...deriveEvidenceSignals({ mitreMappings: techniques.map((techniqueId) => ({ techniqueId })), evidence: [{ title }] })];
    expect(sig("sshd: authentication failed for root")).toEqual([]);
    expect(sig("Successful SSH login for root")).toContain("SUCCESSFUL_LOGIN");
    expect(sig("Possible valid account use", ["T1078"])).toContain("SUCCESSFUL_LOGIN");
    expect(sig("Non-malicious PowerShell maintenance script")).not.toContain("MALICIOUS_EXECUTION");
    expect(sig("Phishing credential harvesting page")).not.toContain("CREDENTIAL_SUBMITTED");
  });

  it("a procedure that names an unknown signal is rejected, never half-loaded", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vigix-sig-"));
    const src = path.resolve(__dirname, "../../knowledge/playbooks/PB-STC-001");
    fs.cpSync(path.join(src, "procedures", "BRUTE_FORCE"), path.join(dir, "procedures", "BRUTE_FORCE"), { recursive: true });
    const steps = path.join(dir, "procedures", "BRUTE_FORCE", "steps.yaml");
    fs.writeFileSync(steps, fs.readFileSync(steps, "utf8").replace("appliesWhenSignals: [SUCCESSFUL_LOGIN]", "appliesWhenSignals: [NOT_A_SIGNAL]"));
    expect(() => new ContainmentProcedureLoader(dir).read("BRUTE_FORCE")).toThrow(ContainmentProcedureError);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("response plans differ per attack type: no two attack types share the same step sequence", async () => {
    const shapes = new Set<string>();
    for (const id of ["TC-01", "TC-02", "TC-03", "TC-05", "TC-06", "TC-07", "TC-09"]) {
      const { rec } = await run(base(id));
      shapes.add(rec!.steps.map((s) => `${s.stepType}:${s.actionId ?? s.title}`).join(">"));
    }
    expect(shapes.size).toBe(7);
  });
});

describe("re-hunt round 2: the new recommendation follows the new evidence", () => {
  const round1 = [
    { recommendationNumber: 1, investigationNumber: 1, actionCode: "ACT-BLOCK-SOURCE-IP", target: "185.220.101.45" },
    { recommendationNumber: 1, investigationNumber: 1, actionCode: "ACT-RATE-LIMIT-SOURCE", target: "185.220.101.45" },
  ];
  const round2 = (over: Partial<Scenario> = {}) => base("TC-01", { investigationNumber: 2, previousSteps: round1, ...over });

  it("nothing new in the evidence: no repeated recommendation is created", async () => {
    const { ok, audit } = await run(round2());
    expect(ok).toBe(false);
    expect(audit.map((a) => (a.metadata as { reason?: string })?.reason)).toContain("DUPLICATE_RECOMMENDATION");
  });

  it("attacker returns from a new source: the new recommendation targets the new IP, not the old one", async () => {
    const { ok, rec } = await run(round2({ title: "sshd: brute force continued after containment from a new source", iocs: [{ iocType: "IPV4", iocValue: "185.220.101.99", networkRole: "source" }, { iocType: "USERNAME", iocValue: "root" }], evidenceIocs: ["185.220.101.99", "root"] }));
    expect(ok).toBe(true);
    const targets = rec!.steps.filter((s) => s.stepType === "ACTION").map((s) => s.target);
    expect(targets).toEqual(["185.220.101.99", "185.220.101.99"]);
    expect(allText(rec)).not.toContain("185.220.101.45");
  });

  it("re-hunt finds a successful login: the response expands to session / credential handling", async () => {
    const { ok, rec } = await run(round2({ facts: ["Successful SSH login for root from 185.220.101.45 after repeated failures"] }));
    expect(ok).toBe(true);
    expect(actions(rec)).toEqual(expect.arrayContaining(["ACT-REVOKE-SESSION", "ACT-RESET-CREDENTIAL"]));
  });
});
