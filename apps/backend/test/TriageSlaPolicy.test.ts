import { POLICIES } from "../prisma/seeds/policy.seed";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { createPolicySchema } from "../src/application/policy/dto/CreatePolicyDto";

/**
 * Alert Inbox triage SLA targets are Policy DATA (type TRIAGE_SLA, result.triageSlaMinutes) — editable like any other
 * policy, never hardcoded — and they must not change any existing Policy evaluation (intake / assignment / approval).
 */
const build = (seeds: typeof POLICIES) =>
  seeds.map((p, i) =>
    Policy.create({
      id: `pol-${i}`, tenantId: "t", code: p.code, name: p.name, description: p.description, type: p.type as never, enabled: true, version: 1,
      precedence: p.precedence, createdAt: new Date(), updatedAt: new Date(),
      rules: p.rules.map((r, j) => PolicyRule.create({ id: `r-${i}-${j}`, policyId: `pol-${i}`, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })),
    })
  );
const engine = (seeds: typeof POLICIES) => new PolicyEvaluator({ findAllEnabled: async () => build(seeds) } as unknown as IPolicyRepository);
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

describe("TRIAGE_SLA policy data", () => {
  const sla = POLICIES.filter((p) => p.type === "TRIAGE_SLA");

  it("seeds one editable triage SLA policy per severity with the approved targets", () => {
    const bySeverity = Object.fromEntries(sla.map((p) => [(p.rules[0].condition as { value: string }).value, (p.rules[0].result as { triageSlaMinutes: number }).triageSlaMinutes]));
    expect(bySeverity).toEqual({ CRITICAL: 15, HIGH: 30, MEDIUM: 240, LOW: 1440 });
    expect(sla.map((p) => p.code).sort()).toEqual(["RULE-T01", "RULE-T02", "RULE-T03", "RULE-T04"]);
  });

  it("does not change any existing Policy result for any severity (never merged into the evaluation)", async () => {
    const withSla = engine(POLICIES);
    const withoutSla = engine(POLICIES.filter((p) => p.type !== "TRIAGE_SLA"));
    for (const severity of SEVERITIES) {
      for (const actionImpactLevel of [undefined, "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const) {
        const input = { severity, ...(actionImpactLevel ? { actionImpactLevel } : {}) };
        const a = await withSla.evaluate("t", input as never);
        const b = await withoutSla.evaluate("t", input as never);
        expect(a).toEqual(b);
        expect(a.matchedPolicies.some((c) => c.startsWith("RULE-T0"))).toBe(false);
      }
    }
  });

  it("a TRIAGE_SLA policy is valid Policy input (admins can edit the targets); invalid minutes are rejected", () => {
    const valid = createPolicySchema.safeParse({ code: "RULE-T09", name: "x", type: "TRIAGE_SLA", precedence: 5, rules: [{ condition: { field: "severity", operator: "eq", value: "HIGH" }, result: { triageSlaMinutes: 45 } }] });
    expect(valid.success).toBe(true);
    for (const bad of [0, -5, 2.5]) {
      const r = createPolicySchema.safeParse({ code: "RULE-T09", name: "x", type: "TRIAGE_SLA", precedence: 5, rules: [{ condition: { field: "severity", operator: "eq", value: "HIGH" }, result: { triageSlaMinutes: bad } }] });
      expect(r.success).toBe(false);
    }
  });
});
