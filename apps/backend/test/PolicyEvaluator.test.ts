import { POLICIES, RISK_SCORE_RETIRED_CODES } from "../prisma/seeds/policy.seed";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { matchesCondition } from "../src/infrastructure/policy-engine/PolicyMatcher";
import { evaluatePolicySchema } from "../src/application/policy/dto/EvaluatePolicyDto";
import { createPolicySchema } from "../src/application/policy/dto/CreatePolicyDto";
import { incidentSeverity, toSeverity } from "../src/domain/incident/severity";

/**
 * Severity is the primary classification. The REAL PolicyEvaluator over the canonical rule set
 * (prisma/seeds/policy.seed.ts POLICIES) — Risk Score is not a Policy input any more.
 */
const build = (seeds: { code: string; name: string; description: string; type: string; precedence: number; rules: { condition: unknown; result: unknown }[] }[]) =>
  seeds.map((p, i) =>
    Policy.create({
      id: `pol-${i}`, tenantId: "t", code: p.code, name: p.name, description: p.description, type: p.type as never, enabled: true, version: 1,
      precedence: p.precedence, createdAt: new Date(), updatedAt: new Date(),
      rules: p.rules.map((r, j) => PolicyRule.create({ id: `r-${i}-${j}`, policyId: `pol-${i}`, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })),
    })
  );
const engine = (policies: Policy[]) => new PolicyEvaluator({ findAllEnabled: async () => policies } as unknown as IPolicyRepository);
const canonical = engine(build(POLICIES));

describe("Severity-based Policy (canonical rules)", () => {
  it("LOW -> SOC, no approval", async () => {
    const r = await canonical.evaluate("t", { severity: "LOW" });
    expect(r).toMatchObject({ responsibleRole: "SOC", approvalRequired: false, approvalChain: [], priority: "P3" });
  });

  it("MEDIUM -> SOC, no approval", async () => {
    const r = await canonical.evaluate("t", { severity: "MEDIUM" });
    expect(r).toMatchObject({ responsibleRole: "SOC", approvalRequired: false, approvalChain: [], priority: "P2" });
  });

  it("HIGH -> SOC investigates, IR_TEAM approves and executes", async () => {
    const r = await canonical.evaluate("t", { severity: "HIGH" });
    expect(r).toMatchObject({ responsibleRole: "SOC", executorRole: "IR_TEAM", approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], reviewRequired: true, reviewRole: "IR_TEAM", priority: "P1" });
  });

  it("CRITICAL -> SOC investigates, IR_TEAM is the only approver (no Manager step)", async () => {
    const r = await canonical.evaluate("t", { severity: "CRITICAL" });
    expect(r).toMatchObject({ responsibleRole: "SOC", executorRole: "IR_TEAM", approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], priority: "P0" });
    expect(r.approvalReason).toContain("CRITICAL_SEVERITY");
  });

  it("critical asset + high-impact action still names IR_TEAM only (reason tags kept)", async () => {
    const r = await canonical.evaluate("t", { severity: "MEDIUM", assetCriticality: "CRITICAL", actionImpactLevel: "HIGH" });
    expect(r).toMatchObject({ approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"] });
    expect(r.approvalReason).toEqual(expect.arrayContaining(["CRITICAL_ASSET", "HIGH_IMPACT_ACTION"]));
  });

  it("two roles only: no seeded rule names a Manager; the policy DTO rejects MANAGER", () => {
    expect(JSON.stringify(POLICIES)).not.toContain("MANAGER");
    const withManager = { code: "X-1", name: "x", type: "APPROVAL", precedence: 1, rules: [{ condition: { field: "severity", operator: "eq", value: "HIGH" }, result: { approvalRole: "MANAGER" } }] };
    expect(createPolicySchema.safeParse(withManager).success).toBe(false);
    expect(createPolicySchema.safeParse({ ...withManager, rules: [{ ...withManager.rules[0], result: { approvalRole: "IR_TEAM" } }] }).success).toBe(true);
  });

  it("intake: HIGH / CRITICAL open an incident automatically; MEDIUM / LOW do not", async () => {
    for (const [severity, auto] of [["LOW", false], ["MEDIUM", false], ["HIGH", true], ["CRITICAL", true]] as const) {
      expect((await canonical.evaluate("t", { severity })).autoCreateIncident).toBe(auto);
    }
  });

  it("the result carries no risk score / risk level", async () => {
    const r = (await canonical.evaluate("t", { severity: "HIGH" })) as unknown as Record<string, unknown>;
    expect(r).not.toHaveProperty("riskScore");
    expect(r).not.toHaveProperty("riskLevel");
  });
});

describe("Risk Score has no effect on the Policy decision", () => {
  const strip = (r: Record<string, unknown>) => JSON.stringify(r);

  it.each(["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const)("severity %s: riskScore 10 / 50 / 90 (legacy field) give the identical decision", async (severity) => {
    const base = strip((await canonical.evaluate("t", { severity })) as never);
    for (const riskScore of [10, 50, 90]) {
      const withRisk = await canonical.evaluate("t", { severity, riskScore } as never);
      expect(strip(withRisk as never)).toBe(base);
    }
  });

  it("even the retired risk rules, if a row were re-enabled, never match (riskScore is a retired condition field)", async () => {
    const legacy = engine(
      build([
        { code: "RULE-R01", name: "legacy", description: "", type: "PRIORITY", precedence: 1, rules: [{ condition: { field: "riskScore", operator: "gte", value: 75 }, result: { priority: "P0", responsibleRole: "IR_TEAM" } }] },
        { code: "RULE-P10", name: "legacy", description: "", type: "APPROVAL", precedence: 2, rules: [{ condition: { field: "riskScore", operator: "gte", value: 75 }, result: { approvalRequired: true, approvalRole: "MANAGER" } }] },
      ])
    );
    const r = await legacy.evaluate("t", { severity: "LOW", riskScore: 99 } as never);
    expect(r).toMatchObject({ matchedPolicies: [], approvalRequired: false, responsibleRole: null, priority: null });
    expect(matchesCondition({ field: "riskScore" as never, operator: "gte", value: 0 }, { riskScore: 50 } as never)).toBe(false);
  });

  it("the canonical rule set has no riskScore condition and the retired risk rules are not in it", () => {
    expect(JSON.stringify(POLICIES)).not.toContain("riskScore");
    expect(POLICIES.map((p) => p.code).filter((c) => RISK_SCORE_RETIRED_CODES.includes(c))).toEqual([]);
    expect(RISK_SCORE_RETIRED_CODES).toEqual(["RULE-R01", "RULE-R02", "RULE-R03", "RULE-R04", "RULE-P08", "RULE-P10"]);
  });

  it("API: /policies/evaluate still accepts a legacy riskScore (no 400 for old clients); new rules cannot key on riskScore", () => {
    expect(evaluatePolicySchema.safeParse({ severity: "HIGH", riskScore: 80 }).success).toBe(true);
    const bad = createPolicySchema.safeParse({
      code: "X", name: "x", type: "APPROVAL", rules: [{ condition: { field: "riskScore", operator: "gte", value: 50 }, result: { approvalRequired: true } }],
    });
    expect(bad.success).toBe(false);
  });
});

describe("incident severity used by Policy", () => {
  it("prefers the incident's (analyst-validated) severity, then the alert severity, else MEDIUM", () => {
    expect(incidentSeverity({ priority: "critical", alertSeverity: "low" })).toBe("CRITICAL");
    expect(incidentSeverity({ priority: "p1", alertSeverity: "high" })).toBe("HIGH");
    expect(incidentSeverity({ priority: null, alertSeverity: null })).toBe("MEDIUM");
    expect(toSeverity("Low")).toBe("LOW");
    expect(toSeverity("82")).toBeNull();
  });
});
