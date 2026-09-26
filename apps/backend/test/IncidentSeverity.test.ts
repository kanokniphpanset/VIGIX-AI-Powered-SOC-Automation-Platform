import { GetIncidentSeverityUseCase, IncidentSeverityFacts } from "../src/application/triage/IncidentSeverity.usecase";

/** One severity source: the Wazuh rule level. The SOC may override it with a reason; AI never produces a value. */
const reader = (facts: IncidentSeverityFacts | null) => ({ read: async () => facts });
const base: IncidentSeverityFacts = { incidentSeverity: "critical", alertSeverity: "critical", ruleLevel: 13, ruleId: "5712", latestValidation: null };

describe("Incident severity read model (Wazuh severity / SOC-validated severity / override reason)", () => {
  it("unvalidated incident: severity = Wazuh severity, source = Wazuh rule level, not overridden", async () => {
    const r = await new GetIncidentSeverityUseCase(reader(base)).execute({ tenantId: "t", incidentId: "i" });
    expect(r.value).toEqual({ source: "WAZUH_RULE_LEVEL", wazuhSeverity: "CRITICAL", wazuhRuleLevel: 13, wazuhRuleId: "5712", severity: "CRITICAL", overridden: false, override: null });
  });

  it("SOC override: both values kept separately, with the SOC's reason, actor and time", async () => {
    const at = new Date("2026-09-26T01:00:00Z");
    const r = await new GetIncidentSeverityUseCase(reader({ ...base, incidentSeverity: "high", latestValidation: { severity: "HIGH", reason: "lab host, contained", actor: "soc-1", at } })).execute({ tenantId: "t", incidentId: "i" });
    expect(r.value).toMatchObject({ wazuhSeverity: "CRITICAL", severity: "HIGH", overridden: true, override: { reason: "lab host, contained", actor: "soc-1", at: at.toISOString() } });
  });

  it("a validation that confirmed the Wazuh value is not an override", async () => {
    const r = await new GetIncidentSeverityUseCase(reader({ ...base, latestValidation: { severity: "CRITICAL", reason: null, actor: "soc-1", at: new Date() } })).execute({ tenantId: "t", incidentId: "i" });
    expect(r.value).toMatchObject({ overridden: false, override: null });
  });

  it("the view carries no AI field of any kind", async () => {
    const r = await new GetIncidentSeverityUseCase(reader(base)).execute({ tenantId: "t", incidentId: "i" });
    expect(JSON.stringify(r.value)).not.toMatch(/ai|suggest|predict/i);
  });

  it("unknown incident -> INCIDENT_NOT_FOUND", async () => {
    expect((await new GetIncidentSeverityUseCase(reader(null)).execute({ tenantId: "t", incidentId: "x" })).error).toBe("INCIDENT_NOT_FOUND");
  });
});

import { stripAiSeverity } from "../src/domain/ai/aiGrounding";

describe("Legacy AI output: a stored model severity suggestion is never served", () => {
  it("removes the ML severity sentence from a stored summary, keeps the Wazuh severity and everything else", () => {
    const stored = "Alert severity: medium. The available evidence does not support a more specific classification. ML severity suggestion: MEDIUM (to be validated by an analyst). 3 evidence-backed finding(s) were identified.";
    const r = stripAiSeverity(stored);
    expect(r.removed).toBe(true);
    expect(r.text).toBe("Alert severity: medium. The available evidence does not support a more specific classification. 3 evidence-backed finding(s) were identified.");
  });

  it("drops a stored ML severity key finding entirely; unrelated findings are untouched", () => {
    expect(stripAiSeverity("ML severity classification suggests MEDIUM (advisory; an analyst validates severity).")).toEqual({ text: "", removed: true });
    const mitre = "Observed behavior maps to MITRE ATT&CK technique T1098 (Account Manipulation) under the Persistence tactic.";
    expect(stripAiSeverity(mitre)).toEqual({ text: mitre, removed: false });
    expect(stripAiSeverity("Repeated failed SSH logins from 203.0.113.9; alert severity high.").removed).toBe(false);
  });

  it("removes the old pipeline's 'suggested severity=…' clause from timeline text, keeps the rest", () => {
    expect(stripAiSeverity("AI pipeline completed: decision=auto_response (advisory), suggested severity=medium")).toEqual({ text: "AI pipeline completed: decision=auto_response (advisory)", removed: true });
    const wazuh = "AI pipeline completed: decision=human_approval (advisory). Severity stays the Wazuh severity (high).";
    expect(stripAiSeverity(wazuh)).toEqual({ text: wazuh, removed: false });
  });
});
