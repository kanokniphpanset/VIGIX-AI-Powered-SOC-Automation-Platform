/**
 * EvaluationCompliance.test.ts — unit tests for the DETERMINISTIC evaluation scoring (§17).
 * Pure functions only (no DB, no LLM): the AI output is the subject being scored, never the scorer.
 */
import { evaluateCompliance, investigationSeconds, decisionSeconds, verificationModeOf, ComplianceInput } from "../src/evaluation/EvaluationService";

/** A fully-compliant baseline; each test mutates exactly one thing to force NON_COMPLIANT. */
function base(): ComplianceInput {
  return {
    steps: [
      { actionCode: "ACT-BLOCK-SOURCE-IP", target: "185.220.101.45", requiresApproval: true },
      { actionCode: "ACT-DISABLE-ACCOUNT", target: "root", requiresApproval: true },
    ],
    allowedActions: ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"],
    knownActionCodes: new Set(["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT", "ACT-ISOLATE-ENDPOINT"]),
    targetableValues: new Set(["185.220.101.45", "root"]),
    playbookCode: "PB-SSH-BRUTEFORCE",
    expectedPlaybook: "PB-SSH-BRUTEFORCE",
    playbookAllowedActions: ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"],
    policyByAction: {
      "ACT-BLOCK-SOURCE-IP": { approvalRequired: true, responsibleRole: "IR_TEAM", approvalRole: "IR_TEAM" },
      "ACT-DISABLE-ACCOUNT": { approvalRequired: true, responsibleRole: "IR_TEAM", approvalRole: "IR_TEAM" },
    },
    approvalRoleUsed: "IR_TEAM",
    approvalDecided: true,
  };
}

describe("Recommendation Compliance (deterministic)", () => {
  it("all checks pass -> COMPLIANT", () => {
    const r = evaluateCompliance(base());
    expect(r.compliant).toBe(true);
    expect(r.failedChecks).toHaveLength(0);
  });

  it("wrong Action -> NON_COMPLIANT (attackAlignment)", () => {
    const i = base();
    i.steps[0].actionCode = "ACT-REIMAGE-HOST"; // not in allowedActions
    i.knownActionCodes.add("ACT-REIMAGE-HOST");
    i.playbookAllowedActions.push("ACT-REIMAGE-HOST");
    i.policyByAction["ACT-REIMAGE-HOST"] = { approvalRequired: true, responsibleRole: "IR_TEAM", approvalRole: "IR_TEAM" };
    i.targetableValues.add("185.220.101.45");
    const r = evaluateCompliance(i);
    expect(r.attackAlignment).toBe(false);
    expect(r.compliant).toBe(false);
  });

  it("missing Evidence -> NON_COMPLIANT (evidenceSupport)", () => {
    const i = base();
    i.steps[0].target = "10.10.10.10"; // not a targetable value
    const r = evaluateCompliance(i);
    expect(r.evidenceSupport).toBe(false);
    expect(r.compliant).toBe(false);
  });

  it("unknown Action -> NON_COMPLIANT (knowledgeValidity)", () => {
    const i = base();
    i.steps[0].actionCode = "ACT-DOES-NOT-EXIST";
    i.allowedActions.push("ACT-DOES-NOT-EXIST");
    i.playbookAllowedActions.push("ACT-DOES-NOT-EXIST");
    i.policyByAction["ACT-DOES-NOT-EXIST"] = { approvalRequired: true, responsibleRole: "IR_TEAM", approvalRole: "IR_TEAM" };
    i.targetableValues.add("185.220.101.45");
    const r = evaluateCompliance(i);
    expect(r.knowledgeValidity).toBe(false);
    expect(r.compliant).toBe(false);
  });

  it("Policy violation -> NON_COMPLIANT (policyCompliance)", () => {
    const i = base();
    i.steps[0].requiresApproval = false; // Policy says approval IS required
    const r = evaluateCompliance(i);
    expect(r.policyCompliance).toBe(false);
    expect(r.compliant).toBe(false);
  });

  it("Playbook mismatch -> NON_COMPLIANT (playbookAlignment)", () => {
    const i = base();
    i.playbookCode = "PB-MALWARE"; // != expected PB-SSH-BRUTEFORCE
    const r = evaluateCompliance(i);
    expect(r.playbookAlignment).toBe(false);
    expect(r.compliant).toBe(false);
  });

  it("incorrect Approval -> NON_COMPLIANT (approvalCorrectness)", () => {
    const i = base();
    i.approvalRoleUsed = "SOC"; // Policy requires IR_TEAM
    const r = evaluateCompliance(i);
    expect(r.approvalCorrectness).toBe(false);
    expect(r.compliant).toBe(false);
  });

  it("a syntactically-valid but wrong-target recommendation is still NON_COMPLIANT", () => {
    // guards §3: compliance is NOT merely 'was it VALIDATED'
    const i = base();
    i.steps = [{ actionCode: "ACT-BLOCK-SOURCE-IP", target: "8.8.8.8", requiresApproval: true }];
    const r = evaluateCompliance(i);
    expect(r.compliant).toBe(false);
  });

  it("BLOCK-DESTINATION-IP aimed at the alert's source (endpoint) -> NON_COMPLIANT (targetRole)", () => {
    // TC-07/TC-09: endpoint .5 is the SOURCE, lab server .7 the destination
    const i = base();
    i.steps = [{ actionCode: "ACT-BLOCK-DESTINATION-IP", target: "172.19.0.5", requiresApproval: true }];
    i.allowedActions.push("ACT-BLOCK-DESTINATION-IP");
    i.playbookAllowedActions.push("ACT-BLOCK-DESTINATION-IP");
    i.policyByAction["ACT-BLOCK-DESTINATION-IP"] = { approvalRequired: true, responsibleRole: "IR_TEAM", approvalRole: "IR_TEAM" };
    i.knownActionCodes.add("ACT-BLOCK-DESTINATION-IP");
    i.targetableValues.add("172.19.0.5").add("172.19.0.7");
    i.alertSrcIp = "172.19.0.5";
    i.alertDstIp = "172.19.0.7";
    const wrong = evaluateCompliance(i);
    expect(wrong.evidenceSupport).toBe(true);
    expect(wrong.targetRole).toBe(false);
    expect(wrong.compliant).toBe(false);
    i.steps[0].target = "172.19.0.7";
    const right = evaluateCompliance(i);
    expect(right.targetRole).toBe(true);
    expect(right.compliant).toBe(true);
  });
});

describe("KPI timing (real timestamps)", () => {
  it("Investigation Time = T_Recommendation - T_InvestigationStart", () => {
    const start = new Date("2026-09-30T10:00:00.000Z");
    const rec = new Date("2026-09-30T10:00:45.000Z");
    expect(investigationSeconds(start, rec)).toBe(45);
  });

  it("Time-to-Decision = T_Decision - T_Recommendation", () => {
    const rec = new Date("2026-09-30T10:00:45.000Z");
    const dec = new Date("2026-09-30T10:02:15.000Z");
    expect(decisionSeconds(rec, dec)).toBe(90);
  });

  it("missing timestamp -> null (never fabricated)", () => {
    expect(investigationSeconds(null, new Date())).toBeNull();
    expect(decisionSeconds(new Date(), null)).toBeNull();
  });
});

describe("Verification mode labelling (§8)", () => {
  it("CleanRehuntAdapter re-hunt is labelled MOCK, never REAL_WAZUH", () => {
    expect(verificationModeOf("clean-rehunt/no-match#round-1", "MOCK_REHUNT")).toBe("MOCK");
    expect(verificationModeOf("mock-attacks/x#round-1", "MOCK_REHUNT")).toBe("MOCK");
  });
  it("a live Wazuh indexer re-hunt is REAL_WAZUH", () => {
    expect(verificationModeOf("wazuh-alerts-4.x-2026.09.30", "WAZUH_INDEXER")).toBe("REAL_WAZUH");
  });
  it("no verification -> NONE", () => {
    expect(verificationModeOf(null, null)).toBe("NONE");
  });
});
