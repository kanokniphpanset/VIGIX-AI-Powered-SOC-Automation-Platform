import { SPREAD_POLICIES } from "../prisma/seeds/policy.seed";
import { spreadPolicyCode } from "../src/domain/knowledge/spreadResponse";
import { INCIDENT_PLAYBOOKS, playbookSeedDefinitions } from "../prisma/seeds/playbook.seed";
import { createPolicySchema } from "../src/application/policy/dto/CreatePolicyDto";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { noveltyHistory, newStepOptions, RecommendationContextDto } from "../src/application/recommendation/dto/RecommendationContextDto";
import { spreadResponseOptions } from "../src/application/recommendation/services/SpreadResponseCoverage";

const policies = SPREAD_POLICIES.map((p, i) => Policy.create({
  id: `p${i}`, tenantId: "t", code: p.code, name: p.name, description: p.description,
  type: p.type, enabled: true, version: 1, precedence: p.precedence, createdAt: new Date(), updatedAt: new Date(),
  rules: p.rules.map((r, j) => PolicyRule.create({ id: `r${i}-${j}`, policyId: `p${i}`, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })),
}));
const engine = new PolicyEvaluator({ findAllEnabled: async () => policies } as never);

test.each(INCIDENT_PLAYBOOKS)("$code spread policy activates only on confirmed spread of this attack", async pb => {
  const base = { incidentType: pb.incidentType, severity: "HIGH" as const };
  expect((await engine.responseGuidance("t", base)).policies).toEqual([]);
  expect((await engine.responseGuidance("t", { ...base, spreadDetected: false, verificationResult: "NOT_RESOLVED" })).policies).toEqual([]);
  expect((await engine.responseGuidance("t", { ...base, spreadDetected: true, verificationResult: "RESOLVED" })).policies).toEqual([]);
  const result = await engine.responseGuidance("t", { ...base, spreadDetected: true, verificationResult: "NOT_RESOLVED" });
  expect(result.policies).toEqual([spreadPolicyCode(pb.incidentType)]);
  expect(result.notes).toHaveLength(1);
  expect(result.allowedActions!.every(a => pb.allowedActions.includes(a))).toBe(true);
  expect(result.allowedActions!.length).toBeGreaterThan(0);
  const seed = SPREAD_POLICIES.find(p => p.code === result.policies[0])!;
  expect(createPolicySchema.safeParse(seed).success).toBe(true);
  const definition = playbookSeedDefinitions().find(p => p.code === pb.code)!;
  expect((definition.triggerConditions as Record<string, unknown>).spreadResponsePolicyCode).toBe(seed.code);
});

test("unknown incident type has no spread policy", async () => {
  expect((await engine.responseGuidance("t", { incidentType: "UNKNOWN", severity: "HIGH", spreadDetected: true, verificationResult: "NOT_RESOLVED" })).policies).toEqual([]);
});

function verification(overrides: Record<string, unknown> = {}) {
  return { id: "v", afterState: { evidenceSource: "WAZUH_INDEXER", verifiedInvestigationNumber: 1, truncated: true },
    beforeState: { criteria: { hosts: ["OLD-01"] } }, affectedHosts: ["OLD-01", "NEW-01", "NEW-01"],
    result: "NOT_RESOLVED", spreadDetected: true, matchingEvents: 3, ...overrides };
}

test("re-hunt context reads only tenant-owned immediately preceding cycle and preserves incomplete scope", async () => {
  const read = jest.fn().mockResolvedValue(verification());
  const repository = new PrismaRecommendationContextRepository({ verification: { findFirst: read } } as never);
  expect(await repository.getRehuntContext("i", "t", 2)).toMatchObject({ newHosts: ["NEW-01"], originalHosts: ["OLD-01"], truncated: true });
  expect(read).toHaveBeenCalledWith(expect.objectContaining({ where: { incidentId: "i", tenantId: "t", incident: { tenantId: "t" }, afterState: { path: ["verifiedInvestigationNumber"], equals: 1 } } }));
  read.mockClear();
  expect(await repository.getRehuntContext("i", "t", 1)).toBeNull();
  expect(read).not.toHaveBeenCalled();
  read.mockResolvedValue(null);
  expect(await repository.getRehuntContext("i", "t", 3)).toBeNull();
});

test("manual verification cannot activate automatic re-hunt spread guidance", async () => {
  const repository = new PrismaRecommendationContextRepository({ verification: { findFirst: async () => verification({ afterState: { evidenceSource: "MANUAL_ENTRY", verifiedInvestigationNumber: 1 } }) } } as never);
  expect(await repository.getRehuntContext("i", "t", 2)).toBeNull();
});

function context(): RecommendationContextDto {
  return {
    investigationNumber: 2,
    rehunt: { verificationId: "v", verifiedInvestigationNumber: 1, source: "WAZUH_INDEXER", result: "NOT_RESOLVED", spreadDetected: true, originalHosts: ["OLD-01"], affectedHosts: ["NEW-01", "NEW-02"], newHosts: ["NEW-01", "NEW-02"], matchingEvents: 2, truncated: false },
    spreadResponse: { policies: ["SPREAD-MALWARE"], instructions: [], allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN"], newHosts: ["NEW-01", "NEW-02"], uncoveredHosts: [] },
    evidence: [{ host: "NEW-01", iocValues: ["bad.example"] }, { host: "NEW-02", iocValues: [] }],
    actionProcedures: [
      { actionCode: "ACT-ISOLATE-ENDPOINT", applicable: true, evidence: { satisfied: true, targets: ["OLD-01", "NEW-01"] } },
      { actionCode: "ACT-BLOCK-DOMAIN", applicable: true, evidence: { satisfied: true, targets: ["bad.example"] } },
    ],
    previousSteps: [{ actionCode: "ACT-BLOCK-DOMAIN", target: "bad.example", investigationNumber: 1, recommendationNumber: 1 }],
  } as unknown as RecommendationContextDto;
}

test("spread coverage uses evidence per host; no action is invented for an uncovered host", () => {
  expect(spreadResponseOptions(context())).toEqual([
    { host: "NEW-01", options: [{ actionCode: "ACT-ISOLATE-ENDPOINT", target: "NEW-01" }, { actionCode: "ACT-BLOCK-DOMAIN", target: "bad.example" }] },
    { host: "NEW-02", options: [] },
  ]);
  const ctx = context(); ctx.actionProcedures![0].evidence!.satisfied = false;
  expect(spreadResponseOptions(ctx)[0].options).toEqual([{ actionCode: "ACT-BLOCK-DOMAIN", target: "bad.example" }]);
});

test("shared IOC may be re-contained for a verified new host scope, never duplicated within the cycle", () => {
  const ctx = context();
  expect(newStepOptions(ctx)).toContainEqual({ actionCode: "ACT-BLOCK-DOMAIN", target: "bad.example" });
  ctx.previousSteps!.push({ actionCode: "ACT-BLOCK-DOMAIN", target: "bad.example", investigationNumber: 2, recommendationNumber: 2 });
  expect(newStepOptions(ctx)).not.toContainEqual({ actionCode: "ACT-BLOCK-DOMAIN", target: "bad.example" });
  expect(noveltyHistory(ctx)).toHaveLength(1);
  ctx.rehunt!.spreadDetected = false;
  expect(noveltyHistory(ctx)).toHaveLength(2);
  ctx.rehunt!.spreadDetected = true; ctx.rehunt!.verifiedInvestigationNumber = 0;
  expect(noveltyHistory(ctx)).toHaveLength(2);
});
