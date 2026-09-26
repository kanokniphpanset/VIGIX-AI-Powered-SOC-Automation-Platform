import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";
import { RecommendationValidator } from "../src/infrastructure/recommendation-validation/RecommendationValidator";
import { RecommendationPromptBuilder } from "../src/infrastructure/ai/RecommendationPromptBuilder";
import { FakeRecommendationAgent } from "../src/infrastructure/ai/FakeRecommendationAgent";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { IRecommendationAgentPort } from "../src/application/recommendation/ports/IRecommendationAgentPort";
import { IRecommendationRepository, CreateRecommendationData } from "../src/domain/recommendation/repositories/IRecommendationRepository";
import { IActionRepository } from "../src/domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../src/domain/runbook/repositories/IRunbookRepository";
import { IPlaybookRepository } from "../src/domain/playbook/repositories/IPlaybookRepository";
import { Runbook } from "../src/domain/runbook/entities/Runbook.entity";
import { Playbook } from "../src/domain/playbook/entities/Playbook.entity";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { RecommendationContextDto } from "../src/application/recommendation/dto/RecommendationContextDto";
import { ACTIONS, ACTION_RUNBOOK_CODES } from "../prisma/seeds/action.seed";
import { RUNBOOKS } from "../prisma/seeds/runbook.seed";
import { INCIDENT_PLAYBOOKS } from "../prisma/seeds/playbook.seed";
import { buildCorrectionPrompt, closestEvidenceValue, shouldRetry } from "../src/application/recommendation/services/RecommendationCorrection";

/**
 * Task 10.3 — Response Process Recommendation v2.
 * Real context builder, playbook selector, prompt builder and validator over the REAL seeded catalogs
 * (Action Catalog, action-level Runbooks, incident-level Playbooks). Only the AI agent, Policy result,
 * repositories and audit log are in-memory fakes. Context = ATK-01 (SSH brute force, WKS-DEV-12).
 */

const TENANT = "tenant-1";
const INCIDENT = "incident-1";
const TITLE = "sshd: brute force trying to get access to the system. Authentication failed.";

const actions = ACTIONS.map((a) => ({
  ...a,
  id: `action-${a.code}`,
  enabled: true,
  runbookId: ACTION_RUNBOOK_CODES[a.code] ? `runbook-${ACTION_RUNBOOK_CODES[a.code]}` : null,
}));
const runbooks = RUNBOOKS.map((r) =>
  Runbook.create({ ...r, id: `runbook-${r.code}`, tenantId: TENANT, version: "1.0", status: "ACTIVE", createdAt: new Date(), updatedAt: new Date() })
);
const playbooks = [
  Playbook.create({ id: "pb-stc", tenantId: TENANT, code: "STC-001", name: "Short-Term Containment", description: null, version: "1.0", status: "ACTIVE", steps: [], triggerConditions: {} }),
  ...INCIDENT_PLAYBOOKS.map((p) =>
    Playbook.create({
      id: `pb-${p.code}`,
      tenantId: TENANT,
      code: p.code,
      name: p.name,
      description: p.description,
      version: "1.0",
      status: "ACTIVE",
      steps: p.steps.map((s) => ({ ...s, id: `${p.code}-${s.stepOrder}` })),
      triggerConditions: { scope: "INCIDENT", incidentType: p.incidentType, mitreTechniques: p.mitreTechniques, allowedActions: p.allowedActions },
    })
  ),
];

const actionRepository = {
  findAll: async () => actions,
  findById: async (id: string) => actions.find((a) => a.id === id) ?? null,
  findByCodes: async (codes: string[]) => actions.filter((a) => codes.includes(a.code)),
} as unknown as IActionRepository;
const runbookRepository = {
  findAll: async () => runbooks,
  findById: async (id: string) => runbooks.find((r) => r.id === id) ?? null,
  findByCodes: async (codes: string[]) => runbooks.filter((r) => codes.includes(r.code)),
} as unknown as IRunbookRepository;
const playbookRepository = { findAll: async () => playbooks } as unknown as IPlaybookRepository;

/** Stand-in for the Policy Engine result per action (ApprovalService.evaluate) — the test checks it is ENFORCED, not how it is computed. */
const POLICY: Record<string, { responsibleRole: string; approvalRequired: boolean; approvalRole: string | null }> = {
  "action-ACT-BLOCK-SOURCE-IP": { responsibleRole: "SOC", approvalRequired: false, approvalRole: null },
  "action-ACT-DISABLE-ACCOUNT": { responsibleRole: "IR_TEAM", approvalRequired: true, approvalRole: "MANAGER" },
};
const policyService = {
  evaluate: jest.fn(async ({ actionId }: { actionId?: string | null }) => ({
    policy: { ...(POLICY[actionId ?? ""] ?? { responsibleRole: "SOC", approvalRequired: false, approvalRole: null }), reviewRequired: false, reviewRole: null, matchedRules: ["RULE-A01"] },
  })),
} as never;

function contextRepository(overrides: Partial<IRecommendationContextRepository> = {}): IRecommendationContextRepository {
  return {
    getIncidentContext: async () => ({ incidentId: INCIDENT, investigationNumber: 1, title: TITLE, status: "investigating", priority: "medium", alertSeverity: "medium" }),
    getIocs: async () => [
      { iocType: "IPV4", iocValue: "185.220.101.45", source: "aggregated", reputationScore: null },
      { iocType: "USERNAME", iocValue: "root", source: "ALERT", reputationScore: null },
      // Extracted by the pipeline (the victim agent's own IP) but NOT linked to any evidence: context, never a target.
      { iocType: "IPV4", iocValue: "10.0.5.44", source: "aggregated", reputationScore: null },
    ],
    getMitreMappings: async () => [{ techniqueId: "T1110", tactic: "Credential Access", confidence: 0.85 }],
    getEvidence: async () => [
      {
        type: "WAZUH_ALERT",
        source: "WAZUH",
        origin: "SYSTEM",
        title: TITLE,
        timestamp: new Date("2026-09-18T10:30:00Z"),
        host: "WKS-DEV-12",
        ruleId: "5712",
        iocValues: ["185.220.101.45", "root"],
      },
    ],
    getLatestAiAnalysis: async () => ({ summary: "Repeated authentication failures may indicate brute-force activity.", keyFindings: ["Maps to T1110"], grounding: { status: "GROUNDED" as const, ungrounded: [] } }),
    ...overrides,
  };
}

const builder = (repo = contextRepository()) => new RecommendationContextBuilder(repo, actionRepository, runbookRepository, playbookRepository, policyService);

const BLOCK_IP_STEP = {
  stepOrder: 1,
  action: "ACT-BLOCK-SOURCE-IP",
  objective: "Prevent further SSH authentication attempts from 185.220.101.45 against WKS-DEV-12.",
  responsibleRole: "SOC",
  target: "185.220.101.45",
  reason: "Repeated failed root logins from 185.220.101.45 against WKS-DEV-12 (T1110).",
  evidenceRefs: ["I1", "T1110"], // stable ids: I1 = 185.220.101.45
  instructions: [
    { order: 1, instruction: "Confirm 185.220.101.45 against the authentication evidence for WKS-DEV-12.", target: "185.220.101.45", expectedResult: "Source confirmed malicious." },
    { order: 2, instruction: "Apply a deny rule for 185.220.101.45 on the perimeter firewall, scoped to WKS-DEV-12.", target: "185.220.101.45", expectedResult: "Deny rule active." },
    { order: 3, instruction: "Record the rule identifier and time applied in the execution result.", target: null, expectedResult: null },
  ],
  playbook: "PB-SSH-BRUTEFORCE",
  runbook: "RB-BLOCK-SOURCE-IP",
  verificationCriteria: "Connection attempts from 185.220.101.45 to WKS-DEV-12 are rejected.",
  expectedResult: "No further attempts from 185.220.101.45.",
  missingEvidence: [],
  confidence: 0.85,
  requiresApprovalSuggested: false,
};
const DISABLE_ROOT_STEP = {
  ...BLOCK_IP_STEP,
  stepOrder: 2,
  action: "ACT-DISABLE-ACCOUNT",
  objective: "Prevent further authentication with the targeted account root on WKS-DEV-12.",
  responsibleRole: "IR_TEAM",
  target: "root",
  reason: "The brute force targets the privileged account root.",
  evidenceRefs: ["I2", "T1110"], // I2 = root
  instructions: [
    { order: 1, instruction: "Disable the account root in the directory that authenticates it on WKS-DEV-12.", target: "root", expectedResult: "Account disabled." },
    { order: 2, instruction: "Terminate active sessions of root.", target: "root", expectedResult: "No active sessions." },
  ],
  runbook: "RB-DISABLE-ACCOUNT",
  verificationCriteria: "Authentication attempts with root fail.",
  requiresApprovalSuggested: true,
};
const candidate = (steps: unknown[], summary = "Block the SSH brute-force source 185.220.101.45.") => ({ summary, steps });

function setup(agentImpl: (ctx: RecommendationContextDto) => Promise<unknown>, opts: { nextNumber?: number; repo?: IRecommendationContextRepository } = {}) {
  const created: CreateRecommendationData[] = [];
  const superseded: string[] = [];
  const audit: Array<{ action: string; metadata?: Record<string, unknown> }> = [];
  const recommendationRepository = {
    getNextRecommendationNumber: async () => opts.nextNumber ?? 1,
    create: async (data: CreateRecommendationData) => {
      created.push(data);
      return { id: `rec-${created.length}`, ...data, snapshotId: "snap-1", steps: data.steps.map((s, i) => ({ ...s, id: `step-${i + 1}` })) };
    },
    supersedePrevious: async (_i: string, _t: string, keep: string) => void superseded.push(keep),
  } as unknown as IRecommendationRepository;
  const auditLogger = { record: async (e: { action: string; metadata?: Record<string, unknown> }) => void audit.push(e) } as unknown as AuditLogger;
  const agent: IRecommendationAgentPort = { generate: jest.fn(agentImpl) };
  const useCase = new GenerateRecommendationUseCase(
    builder(opts.repo),
    agent,
    "LlmRecommendationAgent/v2.0.0",
    new RecommendationValidator(actionRepository, runbookRepository),
    recommendationRepository,
    auditLogger
  );
  return { useCase, agent, created, superseded, audit };
}

const run = (useCase: GenerateRecommendationUseCase) => useCase.execute({ incidentId: INCIDENT, tenantId: TENANT });

describe("Recommendation v2 — valid action-level recommendation (ATK-01)", () => {
  it("persists ONE action-level step with instructions, runbook, playbook snapshot and Policy approval", async () => {
    const { useCase, created, audit } = setup(async () => candidate([BLOCK_IP_STEP]));
    const r = await run(useCase);
    expect(r.isSuccess).toBe(true);
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({ status: "VALIDATED", incidentId: INCIDENT, investigationNumber: 1 });
    expect(created[0].steps).toHaveLength(1);
    expect(created[0].steps[0]).toMatchObject({
      title: "Block Source IP — 185.220.101.45",
      actionId: "action-ACT-BLOCK-SOURCE-IP",
      sourceRunbookId: "runbook-RB-BLOCK-SOURCE-IP",
      target: "185.220.101.45",
      evidence: ["185.220.101.45", "T1110"],
      requiresApproval: false,
      verificationCriteria: "Connection attempts from 185.220.101.45 to WKS-DEV-12 are rejected.",
    });
    expect(created[0].steps[0].instructions.map((i) => i.order)).toEqual([1, 2, 3]);
    expect(created[0].steps[0].instructions[2].target).toBe("185.220.101.45"); // defaults to the step target
    expect(created[0].snapshot).toMatchObject({ playbookCode: "PB-SSH-BRUTEFORCE", procedureCode: "RB-BLOCK-SOURCE-IP", policyResult: { "ACT-BLOCK-SOURCE-IP": { responsibleRole: "SOC" } } });
    expect(audit.map((a) => a.action)).toEqual(["RECOMMENDATION_GENERATED"]);
    expect(audit[0].metadata).toMatchObject({ playbook: "PB-SSH-BRUTEFORCE", stepCount: 1 });
  });

  it("supports multiple actions, each with its own runbook and its own Policy result", async () => {
    const { useCase, created } = setup(async () => candidate([BLOCK_IP_STEP, DISABLE_ROOT_STEP]));
    expect((await run(useCase)).isSuccess).toBe(true);
    expect(created[0].steps.map((s) => [s.stepOrder, s.actionId, s.sourceRunbookId, s.target, s.requiresApproval])).toEqual([
      [1, "action-ACT-BLOCK-SOURCE-IP", "runbook-RB-BLOCK-SOURCE-IP", "185.220.101.45", false],
      [2, "action-ACT-DISABLE-ACCOUNT", "runbook-RB-DISABLE-ACCOUNT", "root", true],
    ]);
    expect(created[0].snapshot?.procedureCode).toBe("RB-BLOCK-SOURCE-IP,RB-DISABLE-ACCOUNT");
  });

  it("takes requiresApproval from Policy, never from the AI hint", async () => {
    const { useCase, created } = setup(async () => candidate([{ ...BLOCK_IP_STEP, requiresApprovalSuggested: true }]));
    await run(useCase);
    expect(created[0].steps[0].requiresApproval).toBe(false);
  });

  it("supersedes the previous recommendation only after a valid one was persisted", async () => {
    const { useCase, superseded } = setup(async () => candidate([BLOCK_IP_STEP]), { nextNumber: 2 });
    await run(useCase);
    expect(superseded).toEqual(["rec-1"]);
  });

  it("an IOC added by an analyst (not linked to alert evidence) is a valid target", async () => {
    const repo = contextRepository({
      getIocs: async () => [
        { iocType: "IPV4", iocValue: "185.220.101.45", source: "aggregated", reputationScore: null },
        { iocType: "IPV4", iocValue: "185.220.101.99", source: "correlated alert", reputationScore: null, manual: true },
      ],
    });
    const { useCase, created } = setup(async () => candidate([BLOCK_IP_STEP, { ...BLOCK_IP_STEP, stepOrder: 2, target: "185.220.101.99", evidenceRefs: ["I2"], instructions: [{ order: 1, instruction: "Apply a deny rule for 185.220.101.99." }] }]), { repo });
    expect((await run(useCase)).isSuccess).toBe(true);
    expect(created[0].steps.map((s) => s.target)).toEqual(["185.220.101.45", "185.220.101.99"]);
  });

  it("evidence is cited by stable id; E<n> resolves to the recorded title (the LLM never reproduces it)", async () => {
    const title = "Rule 87105: VirusTotal: Alert - c:\\users\\fin.analyst\\appdata\\roaming\\svchost32.exe";
    const repo = contextRepository({
      getEvidence: async () => [
        { type: "WAZUH_ALERT", source: "WAZUH", origin: "SYSTEM", title, timestamp: new Date(), host: "WKS-DEV-12", ruleId: "87105", iocValues: ["185.220.101.45"] },
      ],
    });
    const { useCase, created } = setup(async () => candidate([{ ...BLOCK_IP_STEP, evidenceRefs: ["I1", "E1", "T1110"] }]), { repo });
    expect((await run(useCase)).isSuccess).toBe(true);
    expect(created[0].steps[0].evidence).toEqual(["185.220.101.45", title, "T1110"]);
  });

  it("the deterministic FakeRecommendationAgent output passes the same validator", async () => {
    const { useCase, created } = setup((ctx) => new FakeRecommendationAgent().generate(ctx));
    expect((await run(useCase)).isSuccess).toBe(true);
    expect(created[0].steps[0]).toMatchObject({ actionId: "action-ACT-BLOCK-SOURCE-IP", target: "185.220.101.45" });
  });
});

describe("Recommendation v2 — validator rejects the whole candidate (nothing persisted, failure audited)", () => {
  const cases: Array<[string, unknown, string]> = [
    ["invented target", candidate([{ ...BLOCK_IP_STEP, target: "10.9.9.9" }]), "INVENTED_TARGET"],
    ["IOC not linked to evidence (victim agent IP) as target", candidate([{ ...BLOCK_IP_STEP, target: "10.0.5.44" }]), "INVENTED_TARGET"],
    ["invented instruction target", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Apply a deny rule.", target: "WKS-DEV-99" }] }]), "INVENTED_TARGET"],
    ["target of the wrong kind", candidate([{ ...BLOCK_IP_STEP, target: "root" }]), "TARGET_TYPE_MISMATCH"],
    ["invented IOC in instructions", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Also block 45.33.32.156 and 185.220.101.45." }] }]), "INVENTED_IOC"],
    ["invented URL", candidate([{ ...BLOCK_IP_STEP, reason: "Payload came from http://evil.example.net/x.sh." }]), "INVENTED_IOC"],
    ["invented port", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Deny 185.220.101.45 on port 22." }] }]), "INVENTED_IOC"],
    ["invented command", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Run iptables -A INPUT -s 185.220.101.45 -j DROP." }] }]), "INVENTED_COMMAND"],
    ["invented host", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Apply the deny rule on FW-01." }] }]), "INVENTED_HOST"],
    ["invented action", candidate([{ ...BLOCK_IP_STEP, action: "ACT-NUKE-HOST" }]), "INVENTED_ACTION"],
    ["action outside the selected playbook", candidate([{ ...BLOCK_IP_STEP, action: "ACT-ISOLATE-ENDPOINT", target: "WKS-DEV-12", runbook: "RB-ISOLATE-ENDPOINT" }]), "ACTION_NOT_IN_PLAYBOOK"],
    ["invented evidence (unknown technique)", candidate([{ ...BLOCK_IP_STEP, evidenceRefs: ["I1", "T9999"] }]), "INVENTED_EVIDENCE"],
    ["invented evidence id (E9 does not exist)", candidate([{ ...BLOCK_IP_STEP, evidenceRefs: ["I1", "E9"] }]), "INVENTED_EVIDENCE"],
    ["invented evidence id (made-up format)", candidate([{ ...BLOCK_IP_STEP, evidenceRefs: ["EV-1"] }]), "INVENTED_EVIDENCE"],
    ["evidence cited by raw value instead of id", candidate([{ ...BLOCK_IP_STEP, evidenceRefs: ["185.220.101.45"] }]), "INVENTED_EVIDENCE"],
    ["evidence cited by (mutated) title instead of id", candidate([{ ...BLOCK_IP_STEP, evidenceRefs: ["I1", "sshd: brute force trying to get acess to the system."] }]), "INVENTED_EVIDENCE"],
    ["wrong responsible role", candidate([{ ...BLOCK_IP_STEP, responsibleRole: "MANAGER" }]), "WRONG_RESPONSIBLE_ROLE"],
    ["policy bypass (text)", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Block 185.220.101.45 immediately without waiting for approval." }] }]), "POLICY_BYPASS"],
    ["policy bypass (auto-execute)", candidate([BLOCK_IP_STEP], "Auto-execute the block of 185.220.101.45."), "POLICY_BYPASS"],
    ["policy bypass (approval waived where Policy requires it)", candidate([BLOCK_IP_STEP, { ...DISABLE_ROOT_STEP, requiresApprovalSuggested: false }]), "POLICY_BYPASS"],
    ["Core Flow repetition (summary)", candidate([BLOCK_IP_STEP], "Validate the alert, check the host, block the IP, monitor, then re-hunt."), "CORE_FLOW_REPETITION"],
    ["Core Flow repetition (instruction)", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Re-hunt Wazuh for 185.220.101.45." }] }]), "CORE_FLOW_REPETITION"],
    ["Core Flow repetition (monitor)", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Monitor WKS-DEV-12 for further attempts." }] }]), "CORE_FLOW_REPETITION"],
    ["Core Flow repetition (verification action)", candidate([{ ...BLOCK_IP_STEP, action: "ACT-008" }]), "CORE_FLOW_REPETITION"],
    ["runbook not matching the action", candidate([{ ...BLOCK_IP_STEP, runbook: "RB-DISABLE-ACCOUNT" }]), "RUNBOOK_MISMATCH"],
    ["attack-level runbook instead of the action runbook", candidate([{ ...BLOCK_IP_STEP, runbook: "RB-BRUTEFORCE-001" }]), "RUNBOOK_MISMATCH"],
    ["playbook not matching the incident type", candidate([{ ...BLOCK_IP_STEP, playbook: "PB-MALWARE" }]), "PLAYBOOK_MISMATCH"],
    ["generic Core Flow playbook", candidate([{ ...BLOCK_IP_STEP, playbook: "STC-001" }]), "PLAYBOOK_MISMATCH"],
    ["empty instructions", candidate([{ ...BLOCK_IP_STEP, instructions: [] }]), "EMPTY_INSTRUCTIONS"],
    ["blank instruction", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "   " }] }]), "EMPTY_INSTRUCTIONS"],
    ["instruction order gap", candidate([{ ...BLOCK_IP_STEP, instructions: [{ order: 1, instruction: "Apply the deny rule." }, { order: 3, instruction: "Record the rule." }] }]), "INVALID_INSTRUCTIONS"],
    ["duplicate action+target", candidate([BLOCK_IP_STEP, { ...BLOCK_IP_STEP, stepOrder: 2 }]), "DUPLICATE_STEP"],
    ["v1 contract (actionCode/title)", candidate([{ ...BLOCK_IP_STEP, actionCode: "ACT-BLOCK-SOURCE-IP" }]), "SCHEMA"],
    ["empty recommendation", candidate([]), "SCHEMA"],
    ["self-approval key", { ...candidate([BLOCK_IP_STEP]), approved: true }, "SCHEMA"],
  ];

  it.each(cases)("%s", async (_name, raw, code) => {
    const { useCase, created, superseded, audit } = setup(async () => raw, { nextNumber: 2 });
    const r = await run(useCase);
    expect(r.isFailure).toBe(true);
    expect(r.error).toBe("INVALID_AI_OUTPUT");
    expect(created).toEqual([]);
    expect(superseded).toEqual([]);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ action: "RECOMMENDATION_GENERATION_FAILED", metadata: { reason: "INVALID_AI_OUTPUT", incidentId: INCIDENT } });
    const violations = (audit[0].metadata as { violations: string[] }).violations;
    expect(violations.some((v) => v.startsWith(`${code}:`))).toBe(true);
  });

  it("no incident-level playbook for the incident -> nothing can be recommended", async () => {
    const { useCase, created, audit } = setup(async () => candidate([BLOCK_IP_STEP]), { repo: contextRepository({ getMitreMappings: async () => [] }) });
    expect((await run(useCase)).error).toBe("INVALID_AI_OUTPUT");
    expect(created).toEqual([]);
    expect(JSON.stringify(audit[0].metadata)).toContain("NO_PLAYBOOK");
  });
});

describe("Recommendation v2 — AI failure never persists a recommendation", () => {
  const cases: Array<[string, () => Promise<unknown>, string]> = [
    ["AI timeout", async () => { throw new DOMException("The operation was aborted due to timeout", "TimeoutError"); }, "AI_UNAVAILABLE"],
    ["AI error (504/503/502 from orchestrator)", async () => { throw new Error("AI orchestrator responded with 503"); }, "AI_UNAVAILABLE"],
    ["malformed response", async () => "not json at all", "INVALID_AI_OUTPUT"],
    ["null response", async () => null, "INVALID_AI_OUTPUT"],
  ];

  it.each(cases)("%s", async (_name, impl, expected) => {
    const { useCase, created, superseded, audit } = setup(impl, { nextNumber: 2 });
    const r = await run(useCase);
    expect(r.error).toBe(expected);
    expect(created).toEqual([]);
    expect(superseded).toEqual([]);
    expect(audit[0]).toMatchObject({ action: "RECOMMENDATION_GENERATION_FAILED", metadata: { reason: expected } });
  });

  it("returns INCIDENT_NOT_FOUND without calling the AI", async () => {
    const { useCase, agent } = setup(async () => ({}), { repo: contextRepository({ getIncidentContext: async () => null }) });
    expect((await run(useCase)).error).toBe("INCIDENT_NOT_FOUND");
    expect(agent.generate).not.toHaveBeenCalled();
  });
});

describe("Recommendation v2 — context and prompt", () => {
  const build = async () => (await builder().build(INCIDENT, TENANT)).value;

  it("selects the incident-level playbook and attaches each allowed action's runbook and Policy result", async () => {
    const ctx = await build();
    expect(ctx.incidentType).toBe("SSH_BRUTE_FORCE");
    expect(ctx.playbook).toMatchObject({ code: "PB-SSH-BRUTEFORCE", matchedTechniques: ["T1110"], allowedActions: ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"] });
    expect(ctx.actionProcedures?.map((p) => [p.actionCode, p.runbookCode, p.policy.responsibleRole, p.policy.approvalRequired])).toEqual([
      ["ACT-BLOCK-SOURCE-IP", "RB-BLOCK-SOURCE-IP", "SOC", false],
      ["ACT-DISABLE-ACCOUNT", "RB-DISABLE-ACCOUNT", "IR_TEAM", true],
    ]);
    expect(ctx.actionProcedures?.[0].procedure.length).toBeGreaterThan(0);
    expect(ctx.evidence.map((e) => e.ref)).toEqual(["E1"]);
    expect(ctx.iocs.map((i) => [i.ref, i.iocValue])).toEqual([["I1", "185.220.101.45"], ["I2", "root"], ["I3", "10.0.5.44"]]);
    expect(ctx).toMatchObject({ severity: "MEDIUM", affectedHosts: ["WKS-DEV-12"] });
    expect(ctx).not.toHaveProperty("riskScore");
  });

  it("the prompt carries the mandatory v2 statements, the selected playbook, runbooks and Policy roles", async () => {
    const prompt = new RecommendationPromptBuilder().build(await build());
    expect(prompt).toContain("DO NOT repeat the VIGIX Core Flow.");
    expect(prompt).toContain("Expand only the selected response Action into concrete operational instructions for the responsible role.");
    expect(prompt).toContain(
      "Ground every instruction in the incident Evidence, the incident type, the severity and risk, the responsible role, the Action Catalog, the selected Playbook, the action-level Runbook and the Policy constraints given below."
    );
    expect(prompt).toContain("AI does not authorize, approve, execute, or bypass Policy.");
    expect(prompt).toContain("Selected Playbook (chosen by the backend — use exactly this code): PB-SSH-BRUTEFORCE");
    expect(prompt).toContain("action=ACT-BLOCK-SOURCE-IP (Block Source IP, impact=MEDIUM) playbook=PB-SSH-BRUTEFORCE runbook=RB-BLOCK-SOURCE-IP");
    expect(prompt).toContain("Policy: responsibleRole=IR_TEAM, approvalRequired=true (approvalRole=MANAGER)");
    expect(prompt).toContain("AI analysis (automated interpretation — NOT evidence");
    expect(prompt).not.toContain("ACT-008"); // Core Flow actions are never offered for expansion
    expect(prompt).toContain(`[E1] ${TITLE}`);
    expect(prompt).toContain("[I1] type=IPV4 value=185.220.101.45");
    expect(prompt).toContain("evidenceRefs contains ONLY evidence ids");
    expect(prompt).not.toContain("Citable evidence references"); // titles are no longer listed twice for copying
  });
});

describe("PlaybookSelector", () => {
  const select = (t: string[]) => new PlaybookSelector().select(playbooks, t)?.code ?? null;
  it.each([
    [["T1110"], "PB-SSH-BRUTEFORCE"],
    [["T1110.001"], "PB-SSH-BRUTEFORCE"],
    [["T1204.002", "T1105"], "PB-MALWARE"],
    [["T1190"], "PB-SQL-INJECTION"],
    [["T1078"], "PB-ACCOUNT-COMPROMISE"],
    [["T1098", "T1078"], "PB-ACCOUNT-COMPROMISE"],
    [["T1059.001"], "PB-POWERSHELL"],
    [["T1547.001", "T1059.001"], "PB-POWERSHELL"],
    [[], null],
    [["T1486"], null],
  ])("%j -> %s (never STC-001)", (techniques, expected) => {
    expect(select(techniques as string[])).toBe(expected);
  });
});

describe("AI analysis grounding gate (post-generation check)", () => {
  it("a GROUNDED AI analysis is passed to the recommendation context", async () => {
    const ctx = (await builder().build(INCIDENT, TENANT)).value;
    expect(ctx.aiAnalysis).toEqual({ summary: "Repeated authentication failures may indicate brute-force activity.", keyFindings: ["Maps to T1110"] });
  });

  it("an UNGROUNDED AI analysis (names an indicator the incident does not hold) never becomes trusted context", async () => {
    const repo = contextRepository({
      getLatestAiAnalysis: async () => ({
        summary: "Attacker 203.0.113.99 pivoted from WKS-DEV-12.",
        keyFindings: [],
        grounding: { status: "UNGROUNDED" as const, ungrounded: [{ kind: "ip", value: "203.0.113.99" }] },
      }),
    });
    const ctx = (await builder(repo).build(INCIDENT, TENANT)).value;
    expect(ctx.aiAnalysis).toBeNull();
    // Deterministic facts are unaffected: evidence / IOCs still come from the database.
    expect(ctx.evidence.length).toBeGreaterThan(0);
  });
});


describe("Bounded correction — at most ONE retry, carrying only the validator's findings (E2E 2026-09-26)", () => {
  // The real-LLM E2E saw the model write 185.20.101.45 for the evidence value 185.220.101.45.
  const TYPO_STEP = { ...BLOCK_IP_STEP, target: "185.20.101.45" };

  it("a mis-copied target is corrected once: the retry prompt names the invalid value and the exact evidence value", async () => {
    let call = 0;
    const { useCase, agent, created, audit } = setup(async () => (++call === 1 ? candidate([TYPO_STEP]) : candidate([BLOCK_IP_STEP])));
    const r = await run(useCase);
    expect(r.isSuccess).toBe(true);
    expect(agent.generate).toHaveBeenCalledTimes(2);
    const correction = (agent.generate as jest.Mock).mock.calls[1][1] as string;
    expect(correction).toContain("rejected by the deterministic grounding validator");
    expect(correction).toContain("185.20.101.45 -> Expected evidence value: 185.220.101.45");
    expect(correction).toContain("character for character");
    expect(correction).toContain("Do not use any value from memory");
    expect((agent.generate as jest.Mock).mock.calls[0][1]).toBeUndefined(); // first call: no correction
    expect(created).toHaveLength(1);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ action: "RECOMMENDATION_GENERATED", metadata: { attempts: 2 } });
    expect(JSON.stringify(audit[0].metadata?.correctedViolations)).toContain("INVENTED_TARGET");
  });

  it("still invalid after the one retry -> FAILED (no third call), one audit with both attempts", async () => {
    const { useCase, agent, created, audit } = setup(async () => candidate([TYPO_STEP]));
    const r = await run(useCase);
    expect(r.error).toBe("INVALID_AI_OUTPUT");
    expect(agent.generate).toHaveBeenCalledTimes(2);
    expect(created).toEqual([]);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ action: "RECOMMENDATION_GENERATION_FAILED", metadata: { reason: "INVALID_AI_OUTPUT", attempts: 2 } });
    expect(JSON.stringify(audit[0].metadata?.firstAttemptViolations)).toContain("INVENTED_TARGET");
  });

  it("a valid first answer is used as-is (no retry)", async () => {
    const { useCase, agent, audit } = setup(async () => candidate([BLOCK_IP_STEP]));
    expect((await run(useCase)).isSuccess).toBe(true);
    expect(agent.generate).toHaveBeenCalledTimes(1);
    expect(audit[0]).toMatchObject({ action: "RECOMMENDATION_GENERATED", metadata: { attempts: 1 } });
  });

  it("context problems are not retried (NO_PLAYBOOK: a second answer cannot fix the context)", async () => {
    const { useCase, agent } = setup(async () => candidate([BLOCK_IP_STEP]), { repo: contextRepository({ getMitreMappings: async () => [] }) });
    expect((await run(useCase)).error).toBe("INVALID_AI_OUTPUT");
    expect(agent.generate).toHaveBeenCalledTimes(1);
  });

  it("if the retry itself cannot run, the recommendation stays INVALID (first findings kept, nothing persisted)", async () => {
    let call = 0;
    const { useCase, created, audit } = setup(async () => {
      if (++call === 1) return candidate([TYPO_STEP]);
      throw new Error("AI orchestrator responded with 503");
    });
    expect((await run(useCase)).error).toBe("INVALID_AI_OUTPUT");
    expect(created).toEqual([]);
    expect(audit[0]).toMatchObject({ action: "RECOMMENDATION_GENERATION_FAILED", metadata: { attempts: 2, retryError: "AI orchestrator responded with 503" } });
  });

  it("correction helpers: closest exact value only for a plausible typo; unrelated values are just rejected", () => {
    expect(closestEvidenceValue("185.20.101.45", ["185.220.101.45", "root", "WKS-DEV-12"])).toBe("185.220.101.45");
    expect(closestEvidenceValue("203.0.113.99", ["185.220.101.45", "root"])).toBeNull();
    const prompt = buildCorrectionPrompt(['INVENTED_IOC: step 1 (ACT-BLOCK-SOURCE-IP): IP address "203.0.113.99" is not present in the incident evidence'], ["185.220.101.45"]);
    expect(prompt).toContain("Invalid IOC: 203.0.113.99 -> not present in the supplied evidence; do not use it");
    expect(shouldRetry(["NO_PLAYBOOK: none"])).toBe(false);
    expect(shouldRetry(["POLICY_UNAVAILABLE: down"])).toBe(false);
    expect(shouldRetry(["INVENTED_IOC: x", "SCHEMA: y"])).toBe(true);
    expect(shouldRetry([])).toBe(false);
  });
});
