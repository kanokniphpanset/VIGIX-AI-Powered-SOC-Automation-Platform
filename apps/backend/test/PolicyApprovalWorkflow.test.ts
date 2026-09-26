import * as path from "node:path";

import { POLICIES } from "../prisma/seeds/policy.seed";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { ResourceAssetCriticalityProvider } from "../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { DecideApprovalUseCase } from "../src/application/approval/use-cases/DecideApproval.usecase";
import { RequestApprovalUseCase } from "../src/application/approval/use-cases/RequestApproval.usecase";
import { renderEmail } from "../src/application/notification/services/NotificationTemplateRenderer";
import type { NotificationEvent } from "../src/application/notification/events/NotificationEvent";
import { StartResponseUseCase } from "../src/application/response/use-cases/StartResponse.usecase";
import { SendRecommendationToIrUseCase } from "../src/application/response/use-cases/SendRecommendationToIr.usecase";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { IActionRepository } from "../src/domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../src/domain/runbook/repositories/IRunbookRepository";
import { IRecommendationRepository } from "../src/domain/recommendation/repositories/IRecommendationRepository";
import { IApprovalRepository, CreateApprovalData } from "../src/domain/approval/repositories/IApprovalRepository";
import { IResponsePlanRepository, CreateResponsePlanData } from "../src/domain/response/repositories/IResponsePlanRepository";
import { Approval, ApprovalStatus } from "../src/domain/approval/entities/Approval.entity";
import { ResponsePlan } from "../src/domain/response/entities/ResponsePlan.entity";
import { Recommendation } from "../src/domain/recommendation/entities/Recommendation.entity";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { INotificationDispatcherPort } from "../src/application/notification/ports/INotificationDispatcherPort";

/**
 * Two-role workflow — SOC sends a reviewed Recommendation to IR -> Response Ticket (PENDING_IR_DECISION) ->
 * IR APPROVE / REJECT (note mandatory) -> execution allowed / blocked. Policy supplies ownership and reason tags.
 *
 * REAL: PolicyEvaluator over the canonical DB rule set (prisma/seeds/policy.seed.ts POLICIES), the real shared
 * asset catalog (resources/assets/asset-criticality-catalog.yaml), ApprovalService, CreateResponsePlan,
 * RequestApproval, DecideApproval, StartResponse, SendRecommendationToIr. FAKE: persistence, audit sink, notifications.
 * Incident facts per case are those observed live for the mock attack fixtures (resources/mock-attacks/).
 */

const TENANT = "tenant-1";
const ACTIONS: Record<string, { id: string; code: string; impactLevel: string }> = {
  "act-block-ip": { id: "act-block-ip", code: "ACT-BLOCK-SOURCE-IP", impactLevel: "MEDIUM" },
  "act-disable-account": { id: "act-disable-account", code: "ACT-DISABLE-ACCOUNT", impactLevel: "HIGH" },
  "act-isolate": { id: "act-isolate", code: "ACT-ISOLATE-ENDPOINT", impactLevel: "HIGH" },
  "act-low": { id: "act-low", code: "ACT-007", impactLevel: "LOW" },
  "act-critical": { id: "act-critical", code: "ACT-HYPOTHETICAL-CRITICAL", impactLevel: "CRITICAL" },
};

const policies: Policy[] = POLICIES.map((p, i) =>
  Policy.create({
    id: `pol-${i}`,
    tenantId: TENANT,
    code: p.code,
    name: p.name,
    description: p.description,
    type: p.type,
    enabled: true,
    version: 1,
    precedence: p.precedence,
    createdAt: new Date(),
    updatedAt: new Date(),
    rules: p.rules.map((r, j) =>
      PolicyRule.create({ id: `rule-${i}-${j}`, policyId: `pol-${i}`, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })
    ),
  })
);
const policyRepository = { findAllEnabled: async () => policies } as unknown as IPolicyRepository;

interface Facts {
  incidentId: string;
  severity: "low" | "medium" | "high" | "critical";
  /** LEGACY ML risk score kept in the fixtures only to prove it is ignored: Policy never reads it. */
  riskScore: number | null;
  hosts: string[];
}
interface StepSpec {
  actionId: string | null;
  target: string | null;
  requiresApproval: boolean; // the AI's advisory hint (RULE-006) — must never decide anything
}

function world(facts: Facts, steps: StepSpec[], opts: { catalogPath?: string } = {}) {
  const audit: Array<{ action: string; entityId: string; actor: string; metadata?: Record<string, unknown> }> = [];
  const approvals: Approval[] = [];
  const plans: ResponsePlan[] = [];

  const recommendation = Recommendation.create({
    id: `rec-${facts.incidentId}`,
    tenantId: TENANT,
    incidentId: facts.incidentId,
    investigationNumber: 1,
    recommendationNumber: 1,
    status: "VALIDATED",
    summary: "LLM recommendation",
    createdBy: "LlmRecommendationAgent/v2.0.0",
    steps: steps.map((s, i) => ({
      id: `step-${i + 1}`,
      stepOrder: i + 1,
      title: `step ${i + 1}`,
      objective: null,
      actionId: s.actionId,
      target: s.target,
      reason: "evidence-backed",
      evidence: [],
      sourceRunbookId: null,
      precondition: null,
      expectedResult: null,
      requiresApproval: s.requiresApproval,
      status: "PENDING",
      instructions: [{ order: 1, instruction: `apply action to ${s.target}`, target: s.target, expectedResult: null }],
      verificationCriteria: "action confirmed in effect",
    })),
  });

  const contextRepository: IRecommendationContextRepository = {
    getIncidentContext: async (id) =>
      id === facts.incidentId ? { incidentId: id, investigationNumber: 1, title: "incident", status: "investigating", priority: facts.severity, alertSeverity: facts.severity } : null,
    getIocs: async () => [],
    getMitreMappings: async () => [],
    getEvidence: async () =>
      facts.hosts.map((host) => ({ type: "WAZUH_ALERT", source: "WAZUH", origin: "SYSTEM", title: "alert", timestamp: new Date(), host, ruleId: null, iocValues: [] })),
    getLatestAiAnalysis: async () => null,
  };
  const actionRepository = {
    findById: async (id: string) => ACTIONS[id] ?? null,
  } as unknown as IActionRepository;
  const runbookRepository = { findById: async () => null } as unknown as IRunbookRepository;
  const recommendationRepository = {
    findById: async (id: string) => (id === recommendation.id ? recommendation : null),
  } as unknown as IRecommendationRepository;

  const approvalRepository: IApprovalRepository = {
    findById: async (id) => approvals.find((a) => a.id === id) ?? null,
    findByRecommendation: async (rid) => approvals.filter((a) => a.recommendationId === rid),
    findByResponse: async (pid) => approvals.filter((a) => a.responseId === pid),
    create: async (d: CreateApprovalData) => {
      const a = Approval.create({ id: `appr-${approvals.length + 1}`, ...d, stepOrder: d.stepOrder ?? 1, status: d.status ?? "pending", requestedTo: null, decidedBy: null, decidedAt: null, comment: null, createdAt: new Date() });
      approvals.push(a);
      return a;
    },
    activate: async (id) => {
      const i = approvals.findIndex((a) => a.id === id);
      approvals[i] = Approval.create({ ...approvals[i].toJSON(), status: "pending" });
      return approvals[i];
    },
    cancel: async (ids) => {
      for (const id of ids) {
        const i = approvals.findIndex((a) => a.id === id && a.status === "waiting");
        if (i >= 0) approvals[i] = Approval.create({ ...approvals[i].toJSON(), status: "cancelled" });
      }
    },
    decide: async (id, _t, d: { status: ApprovalStatus; decidedBy: string; comment: string | null }) => {
      const i = approvals.findIndex((a) => a.id === id);
      approvals[i] = Approval.create({ ...approvals[i].toJSON(), status: d.status, decidedBy: d.decidedBy, comment: d.comment, decidedAt: new Date() });
      return approvals[i];
    },
  };
  const responsePlanRepository = {
    findById: async (id: string) => plans.find((p) => p.id === id) ?? null,
    findByRecommendation: async (rid: string) => plans.filter((p) => p.recommendationId === rid),
    create: async (d: CreateResponsePlanData) => {
      const p = ResponsePlan.create({ id: `plan-${plans.length + 1}`, ...d, assignedTo: null, executionResult: null, executedAt: null, completedAt: null, createdAt: new Date(), updatedAt: new Date() });
      plans.push(p);
      return p;
    },
    updateStatus: async (id: string, _t: string, d: Record<string, unknown>) => {
      const i = plans.findIndex((p) => p.id === id);
      plans[i] = ResponsePlan.create({ ...plans[i].toJSON(), ...d, updatedAt: new Date() });
      return plans[i];
    },
  } as unknown as IResponsePlanRepository;

  const auditLogger = { record: async (e: (typeof audit)[number]) => void audit.push(e) } as unknown as AuditLogger;
  const events: Array<Record<string, unknown>> = [];
  const notifications = { emit: async (e: Record<string, unknown>) => void events.push(e) } as unknown as INotificationDispatcherPort;
  const approvalService = new ApprovalService(
    contextRepository,
    actionRepository,
    new PolicyEvaluator(policyRepository),
    approvalRepository,
    auditLogger,
    notifications,
    "http://vigix.test",
    new ResourceAssetCriticalityProvider(opts.catalogPath)
  );

  const createPlan = new CreateResponsePlanUseCase(recommendationRepository, actionRepository, runbookRepository, approvalService, responsePlanRepository, auditLogger, notifications, "http://vigix.test");
  return {
    audit,
    events,
    approvals,
    plans,
    recommendation,
    approvalService,
    createPlan,
    sendToIr: new SendRecommendationToIrUseCase(recommendationRepository, responsePlanRepository, createPlan, auditLogger),
    requestApproval: new RequestApprovalUseCase(recommendationRepository, responsePlanRepository, approvalRepository, actionRepository, runbookRepository, approvalService),
    decide: new DecideApprovalUseCase(approvalRepository, auditLogger, recommendationRepository, contextRepository, responsePlanRepository, notifications, "http://vigix.test"),
    start: new StartResponseUseCase(responsePlanRepository, approvalRepository, auditLogger),
  };
}

const ATK01: Facts = { incidentId: "atk-01", severity: "medium", riskScore: 25, hosts: ["WKS-DEV-12"] };
const ATK08: Facts = { incidentId: "atk-08", severity: "critical", riskScore: 39, hosts: ["DC-01"] };
const ATK10: Facts = { incidentId: "atk-10", severity: "critical", riskScore: 39, hosts: ["FILESRV-01"] };

const irDecide = (w: ReturnType<typeof world>, id: string, status: "approved" | "rejected", role = "IR_TEAM", note: string | null = `${status} after review`, by = `${role.toLowerCase()}-1`) =>
  w.decide.execute({ approvalId: id, tenantId: TENANT, status, decidedBy: by, decidedByRole: role, comment: note });

describe("ATK-01 SSH brute force (MEDIUM) — Policy classifies, IR still decides every ticket", () => {
  it("evaluates assignment/review/approval/SLA from policy rules", async () => {
    const w = world(ATK01, [{ actionId: "act-block-ip", target: "185.220.101.45", requiresApproval: true }]);
    const d = await w.approvalService.evaluate({ tenantId: TENANT, incidentId: ATK01.incidentId, actionId: "act-block-ip" });
    expect(d.assets?.criticality).toBe("MEDIUM"); // WKS-DEV-12 = tier3_medium
    expect(d.policy).toMatchObject({ responsibleRole: "SOC", executorRole: "IR_TEAM", reviewRequired: false, approvalRequired: false, approvalRole: null, priority: "P2" });
    expect(d.policy.sla).not.toBeNull();
    expect(d.policy.matchedPolicies).toEqual(expect.arrayContaining(["POL-005", "RULE-A02"]));
    expect(d.policy.matchedPolicies).not.toContain("RULE-R03"); // retired risk-score rule
    const audited = w.audit.find((a) => a.action === "POLICY_EVALUATED");
    expect(audited?.metadata).toMatchObject({ input: { severity: "MEDIUM", assetCriticality: "MEDIUM", actionImpactLevel: "MEDIUM", actionCode: "ACT-BLOCK-SOURCE-IP" } });
    expect((audited?.metadata as { input: Record<string, unknown> }).input).not.toHaveProperty("riskScore");
  });

  it("the AI hint does not decide anything: the ticket waits for the IR decision (one IR_TEAM step), whatever Policy flags", async () => {
    for (const requiresApproval of [true, false]) {
      const w = world(ATK01, [{ actionId: "act-block-ip", target: "185.220.101.45", requiresApproval }]);
      const r = await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-1", tenantId: TENANT });
      expect(r.value).toMatchObject({ status: "PENDING_IR_DECISION", approvalStatus: "PENDING", assignedRole: "IR_TEAM", incidentId: ATK01.incidentId, recommendationId: w.recommendation.id });
      expect(w.approvals.map((a) => [a.approvalRole, a.status, a.stepOrder])).toEqual([["IR_TEAM", "pending", 1]]);
      expect(w.audit.find((a) => a.action === "RESPONSE_PLAN_CREATED")?.metadata).toMatchObject({ responsibleRole: "SOC", decisionRole: "IR_TEAM", policyApprovalRequired: false });
      expect((await w.start.execute({ responseId: r.value.id, tenantId: TENANT, startedBy: "ir-1" })).error).toBe("APPROVAL_PENDING");
    }
  });
});

describe("SOC Send to IR — ticket first, then the notification with the ticket link", () => {
  it("creates one PENDING_IR_DECISION ticket per action step (investigation-only steps get none), then notifies IR", async () => {
    const w = world(ATK01, [
      { actionId: "act-block-ip", target: "185.220.101.45", requiresApproval: false },
      { actionId: null, target: null, requiresApproval: false },
      { actionId: "act-disable-account", target: "j.smith", requiresApproval: false },
    ]);
    const r = await w.sendToIr.execute({ tenantId: TENANT, recommendationId: w.recommendation.id, actor: "soc-1", note: "Reviewed: evidence matches" });
    expect(r.isSuccess).toBe(true);
    expect(w.plans.map((p) => [p.recommendationStepId, p.status, p.assignedRole])).toEqual([
      ["step-1", "PENDING_IR_DECISION", "IR_TEAM"],
      ["step-3", "PENDING_IR_DECISION", "IR_TEAM"],
    ]);
    expect(w.approvals.map((a) => a.approvalRole)).toEqual(["IR_TEAM", "IR_TEAM"]);
    // Exactly one notification per ticket, each carrying its own ticket link; no separate approval email.
    const assigned = w.events.filter((e) => e.eventType === "RESPONSE_ASSIGNED") as unknown as NotificationEvent[];
    expect(assigned.map((e) => e.links.ticket)).toEqual(w.plans.map((p) => `http://vigix.test/tickets/${p.id}`));
    expect(assigned.every((e) => e.recipient.roles.join() === "IR_TEAM" && e.ticket?.status === "PENDING_IR_DECISION")).toBe(true);
    expect(w.events.some((e) => e.eventType === "APPROVAL_REQUIRED")).toBe(false);
    const { subject, body } = renderEmail(assigned[0]);
    expect(subject).toContain("awaiting IR decision");
    expect(body).toContain(`/tickets/${w.plans[0].id}`);
    expect(body).toMatch(/APPROVE or REJECT/);
    // Audit order: the ticket exists before the send is recorded.
    const actions = w.audit.map((a) => a.action);
    expect(actions.indexOf("RESPONSE_PLAN_CREATED")).toBeLessThan(actions.indexOf("RECOMMENDATION_SENT_TO_IR"));
    expect(w.audit.find((a) => a.action === "RECOMMENDATION_SENT_TO_IR")).toMatchObject({ actor: "soc-1", metadata: { note: "Reviewed: evidence matches", ticketIds: w.plans.map((p) => p.id), decisionRole: "IR_TEAM" } });
  });

  it("sending twice creates nothing new; an unvalidated recommendation can never be sent", async () => {
    const w = world(ATK01, [{ actionId: "act-block-ip", target: "185.220.101.45", requiresApproval: false }]);
    await w.sendToIr.execute({ tenantId: TENANT, recommendationId: w.recommendation.id, actor: "soc-1", note: null });
    expect((await w.sendToIr.execute({ tenantId: TENANT, recommendationId: w.recommendation.id, actor: "soc-1", note: null })).error).toBe("NOTHING_TO_SEND");
    expect(w.plans).toHaveLength(1);
    const invalid = world(ATK01, [{ actionId: "act-block-ip", target: "x", requiresApproval: false }]);
    Object.assign((invalid.recommendation as unknown as { props: { status: string } }).props, { status: "INVALID" });
    expect((await invalid.sendToIr.execute({ tenantId: TENANT, recommendationId: invalid.recommendation.id, actor: "soc-1", note: null })).error).toBe("RECOMMENDATION_NOT_VALIDATED");
    expect(invalid.plans).toHaveLength(0);
    expect(invalid.events).toHaveLength(0);
  });
});

describe("IR decision — APPROVE or REJECT, note mandatory, nothing else decides", () => {
  const pending = async (facts: Facts = ATK08) => {
    const w = world(facts, [{ actionId: "act-disable-account", target: "j.smith", requiresApproval: false }]);
    const plan = (await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-1", tenantId: TENANT })).value;
    return { w, plan };
  };

  it("both decisions need a written note (NOTE_REQUIRED, audited); nothing moves without one", async () => {
    const { w, plan } = await pending();
    for (const status of ["approved", "rejected"] as const) {
      for (const note of [null, "", "   "]) expect((await irDecide(w, w.approvals[0].id, status, "IR_TEAM", note)).error).toBe("NOTE_REQUIRED");
    }
    expect(w.approvals[0].status).toBe("pending");
    expect(w.plans[0]).toMatchObject({ id: plan.id, status: "PENDING_IR_DECISION" });
    expect(w.audit.filter((a) => a.action === "APPROVAL_DECISION_DENIED").every((a) => a.metadata?.reason === "NOTE_REQUIRED")).toBe(true);
  });

  it("APPROVE -> READY_FOR_EXECUTION, IR executes; the approval note is stored and audited", async () => {
    const { w, plan } = await pending();
    const r = await irDecide(w, w.approvals[0].id, "approved", "IR_TEAM", "Disable j.smith: 41 failed logons then success from 203.0.113.9");
    expect(r.value).toMatchObject({ status: "approved", decidedBy: "ir_team-1", comment: "Disable j.smith: 41 failed logons then success from 203.0.113.9" });
    expect(w.plans[0]).toMatchObject({ status: "READY_FOR_EXECUTION", approvalStatus: "APPROVED", incidentId: ATK08.incidentId, actionId: "act-disable-account", target: "j.smith" });
    expect(w.audit.find((a) => a.action === "APPROVAL_APPROVED")).toMatchObject({ actor: "ir_team-1", metadata: { note: expect.stringContaining("41 failed logons") } });
    expect((await w.start.execute({ responseId: plan.id, tenantId: TENANT, startedBy: "ir-1" })).value).toMatchObject({ status: "IN_PROGRESS" });
  });

  it("REJECT -> ticket REJECTED with the stored reason; the response can never start; a second decision is refused", async () => {
    const { w, plan } = await pending();
    const r = await irDecide(w, w.approvals[0].id, "rejected", "IR_TEAM", "Account belongs to the backup service; disabling breaks restores");
    expect(r.value).toMatchObject({ status: "rejected", comment: "Account belongs to the backup service; disabling breaks restores" });
    expect(w.plans[0]).toMatchObject({ id: plan.id, status: "REJECTED", approvalStatus: "REJECTED" });
    expect(w.audit.find((a) => a.action === "APPROVAL_REJECTED")).toMatchObject({ actor: "ir_team-1", entityId: w.approvals[0].id, metadata: { comment: expect.stringContaining("backup service") } });
    expect((await w.start.execute({ responseId: plan.id, tenantId: TENANT, startedBy: "ir-1" })).error).toBe("APPROVAL_REJECTED");
    expect((await irDecide(w, w.approvals[0].id, "approved")).error).toBe("ALREADY_DECIDED");
    expect(w.audit.some((a) => a.action === "RESPONSE_STARTED")).toBe(false);
    // The decision notification tells the roles it was rejected; no response process is sent.
    const rejected = w.events.find((e) => e.eventType === "APPROVAL_REJECTED") as unknown as NotificationEvent;
    expect(rejected.recommendation?.responseProcess).toBeUndefined();
  });

  it("APPROVE sends IR the full response process (not just a summary), with a working ticket link", async () => {
    const { w, plan } = await pending(ATK01);
    w.events.length = 0;
    await irDecide(w, w.approvals[0].id, "approved", "IR_TEAM", "Go ahead");
    const approved = w.events.find((e) => e.eventType === "APPROVAL_APPROVED") as unknown as NotificationEvent;
    expect(approved.recipient.roles).toEqual(["IR_TEAM"]);
    expect(approved.links.ticket).toBe(`http://vigix.test/tickets/${plan.id}`);
    expect(approved.recommendation?.responseProcess).toMatchObject({
      severity: "MEDIUM",
      steps: [{ stepOrder: 1, target: "j.smith", instructions: [{ order: 1, instruction: "apply action to j.smith" }] }],
    });
    const { subject, body } = renderEmail(approved);
    expect(subject).toContain("Approved");
    for (const part of ["Response Recommendation Process", "Situation summary", "Recommended response", "1.1 apply action to j.smith", "run Re-hunt", `/tickets/${plan.id}`]) {
      expect(body).toContain(part);
    }
  });

  it("only IR_TEAM decides: AI / SOC / a retired MANAGER token / admin are refused and nothing moves", async () => {
    const { w, plan } = await pending();
    for (const role of ["AI", "ai-orchestrator", "SOC", "MANAGER", "analyst", ""]) {
      expect((await irDecide(w, w.approvals[0].id, "approved", role, "note", "ai-orchestrator")).error).toBe("ROLE_MISMATCH");
    }
    expect((await irDecide(w, w.approvals[0].id, "approved", "admin", "note")).error).toBe("ADMIN_NOT_APPROVER");
    expect(w.approvals.map((a) => a.status)).toEqual(["pending"]);
    expect(w.plans[0]).toMatchObject({ id: plan.id, status: "PENDING_IR_DECISION" });
  });

  it("one live Response Ticket per recommendation step: a duplicate is refused, a rejected one can be replaced", async () => {
    const { w } = await pending(ATK01);
    const again = await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-1", tenantId: TENANT });
    expect(again.error).toBe("TICKET_ALREADY_EXISTS");
    expect(w.plans).toHaveLength(1);
    await irDecide(w, w.approvals[0].id, "rejected", "IR_TEAM", "wrong target");
    const replaced = await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-1", tenantId: TENANT });
    expect(replaced.isSuccess).toBe(true);
    expect(replaced.value.status).toBe("PENDING_IR_DECISION");
  });

  it("a legacy ticket (PENDING_APPROVAL, open step migrated to IR_TEAM) is decided the same way", async () => {
    const { w, plan } = await pending();
    Object.assign((w.plans[0] as unknown as { props: { status: string } }).props, { status: "PENDING_APPROVAL" });
    await irDecide(w, w.approvals[0].id, "approved", "IR_TEAM", "reviewed after migration");
    expect(w.plans[0]).toMatchObject({ id: plan.id, status: "READY_FOR_EXECUTION", approvalStatus: "APPROVED" });
  });
});

describe("Re-opening a missing IR decision (RequestApproval)", () => {
  it("only for a ticket still awaiting the decision and without an open one; always a single IR_TEAM step", async () => {
    const w = world(ATK01, [{ actionId: "act-block-ip", target: "185.220.101.45", requiresApproval: false }]);
    const plan = (await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-1", tenantId: TENANT })).value;
    expect((await w.requestApproval.execute({ recommendationId: w.recommendation.id, responseId: plan.id, tenantId: TENANT })).error).toBe("APPROVAL_ALREADY_EXISTS");
    // Simulate a ticket whose approval could not be opened at creation.
    w.approvals.length = 0;
    const r = await w.requestApproval.execute({ recommendationId: w.recommendation.id, responseId: plan.id, tenantId: TENANT });
    expect(r.value).toMatchObject({ approvalRole: "IR_TEAM", status: "pending", stepOrder: 1 });
    await irDecide(w, r.value.id, "rejected", "IR_TEAM", "no");
    expect((await w.requestApproval.execute({ recommendationId: w.recommendation.id, responseId: plan.id, tenantId: TENANT })).error).toBe("RESPONSE_NOT_AWAITING_DECISION");
  });
});

describe("Traceability — ResponsePlan.recommendationStepId is the source of truth", () => {
  it("the plan references the exact RecommendationStep it came from, and RequestApproval resolves that step by id (not action+target)", async () => {
    // Two steps with the SAME action and target: the legacy action+target match could not tell them apart.
    const w = world(ATK08, [
      { actionId: "act-disable-account", target: "j.smith", requiresApproval: false },
      { actionId: "act-disable-account", target: "j.smith", requiresApproval: false },
    ]);
    const plan = (await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-2", tenantId: TENANT })).value;
    expect(plan.recommendationStepId).toBe("step-2");

    w.approvals.length = 0; // the IR decision was never opened for this ticket
    w.events.length = 0;
    const again = await w.requestApproval.execute({ recommendationId: w.recommendation.id, responseId: plan.id, tenantId: TENANT });
    expect(again.isSuccess).toBe(true);
    const approvalEvent = w.events.find((e) => e.eventType === "APPROVAL_REQUIRED") as { recommendation: { stepsRequiringApproval: { title: string }[] } };
    expect(approvalEvent.recommendation.stepsRequiringApproval.map((s) => s.title)).toEqual(["step 2"]); // legacy matching would list both
  });
});

describe("ATK-08 account compromise on DC-01 (CRITICAL) — Policy reason tags for the single IR decision", () => {
  it("one IR_TEAM step (no Manager, no chain); Policy records why the ticket is sensitive; SOC owns the case", async () => {
    const w = world(ATK08, [{ actionId: "act-disable-account", target: "j.smith", requiresApproval: false }]);
    const plan = (await w.createPlan.execute({ recommendationId: w.recommendation.id, stepId: "step-1", tenantId: TENANT })).value;
    expect(plan).toMatchObject({ status: "PENDING_IR_DECISION", approvalStatus: "PENDING", assignedRole: "IR_TEAM" });
    expect(w.approvals.map((a) => [a.stepOrder, a.approvalRole, a.status])).toEqual([[1, "IR_TEAM", "pending"]]);
    expect(w.approvals[0].reason).toContain("assetCriticality=CRITICAL");
    expect(w.approvals[0].reason).not.toMatch(/manager/i);
    const evaluated = w.audit.find((a) => a.action === "POLICY_EVALUATED")!.metadata!;
    expect(evaluated).toMatchObject({ approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], responsibleRole: "SOC", executorRole: "IR_TEAM", priority: "P0" });
    expect(evaluated.matchedPolicies).toEqual(expect.arrayContaining(["RULE-P04", "RULE-P06", "RULE-P09"]));
    expect(evaluated.matchedPolicies).not.toEqual(expect.arrayContaining(["RULE-P11"]));
    expect(evaluated.approvalReason).toEqual(expect.arrayContaining(["CRITICAL_ASSET", "HIGH_IMPACT_ACTION", "CRITICAL_SEVERITY"]));
    expect(w.audit.find((a) => a.action === "APPROVAL_REQUESTED")?.metadata).toMatchObject({ approvalChain: ["IR_TEAM"], origin: "IR_DECISION" });
    expect(JSON.stringify(w.audit)).not.toContain("MANAGER");
  });
});

describe("Role & severity policy matrix (real rules, real catalog)", () => {
  const evaluate = async (facts: Facts, actionId: string | null, catalogPath?: string) =>
    world(facts, [], { catalogPath }).approvalService.evaluate({ tenantId: TENANT, incidentId: facts.incidentId, actionId });

  it("LOW: SOC owns, executor IR_TEAM; no reason tag (the retired 'no approval' rule RULE-P01 no longer exists)", async () => {
    const d = await evaluate({ incidentId: "e1", severity: "low", riskScore: 10, hosts: ["WKS-TEST-01"] }, "act-low");
    expect(d.policy).toMatchObject({ responsibleRole: "SOC", executorRole: "IR_TEAM", approvalRequired: false, approvalChain: [], priority: "P3" });
    expect(d.policy.matchedPolicies).not.toContain("RULE-P01");
  });

  it("MEDIUM: SOC owns; a reason tag only if another rule flags the ticket", async () => {
    const d = await evaluate({ incidentId: "m1", severity: "medium", riskScore: 30, hosts: ["WKS-DEV-12"] }, "act-block-ip");
    expect(d.policy).toMatchObject({ responsibleRole: "SOC", approvalRequired: false, approvalChain: [] });
  });

  it("HIGH by severity: SOC owns, IR_TEAM approves (RULE-P07)", async () => {
    const d = await evaluate({ incidentId: "h1", severity: "high", riskScore: 21, hosts: ["WKS-DEV-12"] }, "act-block-ip");
    expect(d.policy).toMatchObject({ responsibleRole: "SOC", approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"] });
    expect(d.policy.approvalReason).toContain("HIGH_SEVERITY");
  });

  it("a legacy risk 60 on a MEDIUM incident no longer escalates: SOC owns, no reason tag", async () => {
    const d = await evaluate({ incidentId: "h2", severity: "medium", riskScore: 60, hosts: ["WKS-DEV-12"] }, "act-block-ip");
    expect(d.policy).toMatchObject({ responsibleRole: "SOC", approvalRequired: false, approvalChain: [] });
    expect(d.policy.approvalReason).not.toContain("HIGH_RISK");
    expect(d.policy.matchedPolicies).not.toContain("RULE-P08");
  });

  it("HIGH even with a LOW-impact action on a critical asset: IR approval flagged", async () => {
    const d = await evaluate({ incidentId: "h3", severity: "high", riskScore: 30, hosts: ["DC-01"] }, "act-low");
    expect(d.assets?.criticality).toBe("CRITICAL");
    expect(d.policy).toMatchObject({ approvalRequired: true, approvalChain: ["IR_TEAM"] });
  });

  it("CRITICAL severity (not a risk score): IR_TEAM is the only approver (RULE-P09)", async () => {
    const d = await evaluate({ incidentId: "c1", severity: "critical", riskScore: null, hosts: ["WKS-DEV-12"] }, "act-block-ip");
    expect(d.policy).toMatchObject({ responsibleRole: "SOC", approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], priority: "P0" });
    expect(d.policy.approvalReason).toContain("CRITICAL_SEVERITY");
    expect(d.policy.approvalReason).not.toContain("CRITICAL_RISK");
  });

  it("same severity, any legacy risk value (0 / 24.9 / 50 / 75 / 99): identical Policy decision", async () => {
    const decisions: string[] = [];
    for (const risk of [0, 24.9, 50, 75, 99]) {
      const d = await evaluate({ incidentId: `b${risk}`, severity: "low", riskScore: risk, hosts: ["WKS-TEST-01"] }, "act-block-ip");
      decisions.push(JSON.stringify(d.policy));
    }
    expect(new Set(decisions).size).toBe(1);
  });

  it("critical asset + high-impact action at LOW severity: IR_TEAM with the asset/impact reason tags (RULE-P04)", async () => {
    const d = await evaluate({ incidentId: "e4", severity: "low", riskScore: 5, hosts: ["DC-01"] }, "act-isolate");
    expect(d.policy).toMatchObject({ approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"] });
    expect(d.policy.matchedPolicies).toContain("RULE-P04");
    expect(d.policy.approvalReason).toEqual(expect.arrayContaining(["CRITICAL_ASSET", "HIGH_IMPACT_ACTION"]));
  });

  it("high-impact action on a non-critical asset at MEDIUM: no reason tag", async () => {
    const d = await evaluate({ incidentId: "e5", severity: "medium", riskScore: 30, hosts: ["WKS-DEV-12"] }, "act-isolate");
    expect(d.policy.approvalRequired).toBe(false);
  });

  it("CRITICAL-impact action anywhere: IR_TEAM (RULE-P05)", async () => {
    const d = await evaluate({ incidentId: "e6", severity: "low", riskScore: 5, hosts: ["WKS-TEST-01"] }, "act-critical");
    expect(d.policy).toMatchObject({ approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"] });
    expect(d.policy.approvalReason).toContain("CRITICAL_IMPACT_ACTION");
  });

  it("unknown host resolves to the catalog default tier (tier2_high), never lower", async () => {
    const d = await evaluate({ incidentId: "e7", severity: "medium", riskScore: 30, hosts: ["NOT-IN-CATALOG-99"] }, "act-block-ip");
    expect(d.assets).toMatchObject({ criticality: "HIGH", assets: [{ host: "NOT-IN-CATALOG-99", known: false, tier: "tier2_high" }] });
  });

  it("several hosts: the most critical wins", async () => {
    const d = await evaluate({ incidentId: "e8", severity: "medium", riskScore: 30, hosts: ["WKS-TEST-01", "DC-01"] }, null);
    expect(d.assets?.criticality).toBe("CRITICAL");
  });

  it("catalog unavailable: fails CLOSED to CRITICAL (the reason tags can only get stricter)", async () => {
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    const d = await evaluate({ incidentId: "e9", severity: "low", riskScore: 5, hosts: ["WKS-TEST-01"] }, "act-isolate", path.join(__dirname, "does-not-exist.yaml"));
    spy.mockRestore();
    expect(d.assets?.criticality).toBe("CRITICAL");
    expect(d.policy).toMatchObject({ approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"] });
  });

  it("INTAKE: HIGH / CRITICAL open an incident automatically; MEDIUM waits for SOC review; LOW never", async () => {
    const evaluator = new PolicyEvaluator(policyRepository);
    const auto: boolean[] = [];
    for (const severity of ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const) auto.push((await evaluator.evaluate(TENANT, { severity })).autoCreateIncident);
    expect(auto).toEqual([false, false, true, true]);
  });
});
