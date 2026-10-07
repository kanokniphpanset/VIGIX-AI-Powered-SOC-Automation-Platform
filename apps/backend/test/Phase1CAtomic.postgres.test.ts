import { randomUUID } from "node:crypto";
import express from "express";
import { Server } from "node:http";
import { AddressInfo } from "node:net";
import { PrismaClient } from "@prisma/client";
import { AtomicWorkflow } from "../src/infrastructure/database/postgres/AtomicWorkflow";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PrismaApprovalRepository } from "../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaResponsePlanRepository } from "../src/infrastructure/database/postgres/repositories/ResponsePlanRepository.prisma";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaIncidentRepository } from "../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaVerificationRepository } from "../src/infrastructure/database/postgres/repositories/VerificationRepository.prisma";
import { PrismaActionRepository } from "../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { DecideApprovalUseCase } from "../src/application/approval/use-cases/DecideApproval.usecase";
import { StartResponseUseCase } from "../src/application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../src/application/response/use-cases/CompleteResponse.usecase";
import { FailResponseUseCase } from "../src/application/response/use-cases/FailResponse.usecase";
import { CreateVerificationUseCase } from "../src/application/verification/use-cases/CreateVerification.usecase";
import { RejectRecommendationUseCase } from "../src/application/recommendation/use-cases/RejectRecommendation.usecase";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { UpdateIncidentStatusUseCase } from "../src/application/incident/use-cases/UpdateIncidentStatus.usecase";
import { UpdatePlaybookUseCase } from "../src/application/playbook/use-cases/UpdatePlaybook.usecase";
import { ApprovalController } from "../src/presentation/http/controllers/ApprovalController";
import { buildApprovalRoutes } from "../src/presentation/http/routes/approval.routes";
import { signToken, signServiceToken } from "../src/presentation/http/middlewares/auth.middleware";
import { Result } from "../src/shared/result/Result";
import { RunRehuntVerificationUseCase } from "../src/application/verification/use-cases/RunRehuntVerification.usecase";
import { PrismaAlertRepository } from "../src/infrastructure/database/postgres/repositories/AlertRepository.prisma";
import { CreateIncidentUseCase } from "../src/application/incident/use-cases/CreateIncident.usecase";
import { MergeAlertsIntoIncidentUseCase } from "../src/application/incident/use-cases/MergeAlertsIntoIncident.usecase";
import { ManualDecisionUseCase } from "../src/application/approval/use-cases/ManualDecision.usecase";
import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { PrismaRunbookRepository } from "../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { alertWorkflow } from "../src/infrastructure/database/postgres/AlertWorkflow";
import { PrismaIncidentSeverityWriter } from "../src/infrastructure/database/postgres/repositories/IncidentSeverityWriter.prisma";
import { ValidateIncidentSeverityUseCase } from "../src/application/triage/SocTriage.usecases";

jest.setTimeout(30000);
const url = process.env.PHASE1C_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
suite("Phase 1C — real PostgreSQL atomic state and audit", () => {
  let db: PrismaClient;
  let atomic: AtomicWorkflow;
  let tenantId: string;
  let actor: string;
  let faultActor: string;
  let actionId: string;
  let responses: PrismaResponsePlanRepository;
  let approvals: PrismaApprovalRepository;
  let recommendations: PrismaRecommendationRepository;
  let incidents: PrismaIncidentRepository;
  let audit: AuditLogger;
  const emit = jest.fn(async (_event?: unknown) => {});
  const context = { getIncidentContext: async () => null, getEvidence: async () => [] };
  const notification = { emit: (event: unknown) => atomic.afterCommit(() => emit(event as never)) };

  beforeAll(async () => {
    if (!url || !/^vigix_phase1c_test_[a-z0-9_]+$/.test(new URL(url).pathname.slice(1))) throw new Error("Dedicated Phase 1C DB required; no runtime fallback");
    db = new PrismaClient({ datasources: { db: { url } } });
    atomic = new AtomicWorkflow(db);
    responses = new PrismaResponsePlanRepository(atomic.prisma);
    approvals = new PrismaApprovalRepository(atomic.prisma);
    recommendations = new PrismaRecommendationRepository(atomic.prisma);
    incidents = new PrismaIncidentRepository(atomic.prisma);
    audit = new AuditLogger(atomic.prisma);
    tenantId = (await db.tenant.create({ data: { name: "Phase1C isolated fixture" } })).id;
    actor = randomUUID(); faultActor = `fault:${randomUUID()}`;
    for (const id of [actor, faultActor]) await db.user.create({ data: { id, tenantId, email: `${id}@phase1c.invalid`, passwordHash: "not-a-login", role: "IR_TEAM" } });
    actionId = (await db.action.create({ data: { tenantId, code: `TEST-${randomUUID()}`, name: "Test action", category: "CONTAINMENT", impactLevel: "HIGH" } })).id;
    // Fault injection lives ONLY in the explicitly guarded test database.
    await db.$executeRawUnsafe(`CREATE OR REPLACE FUNCTION phase1c_fault_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.actor LIKE 'fault:%' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`);
    await db.$executeRawUnsafe(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='phase1c_fault_audit') THEN CREATE TRIGGER phase1c_fault_audit BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION phase1c_fault_audit(); END IF; END $$`);
  });
  afterAll(async () => { if (db) await db.$disconnect(); }); // No reset, cleanup DELETE or compensating writes.
  beforeEach(() => { jest.restoreAllMocks(); emit.mockClear(); });

  async function fixture(status = "PENDING_IR_DECISION", round = 1) {
    const alert = await db.alert.create({ data: { tenantId, externalAlertId: randomUUID(), siemSource: "test", severity: "medium", receivedAt: new Date(), rawPayload: {} } });
    const incident = await db.incident.create({ data: { tenantId, alertId: alert.id, title: "Phase1C", status: "investigating", investigationNumber: round } });
    const investigation = await db.investigation.create({ data: { incidentId: incident.id, investigationNumber: round, createdBy: actor } });
    const rec = await db.recommendation.create({ data: { tenantId, incidentId: incident.id, investigationId: investigation.id, investigationNumber: round, recommendationNumber: 1, status: "VALIDATED", summary: "test", createdBy: "test-agent",
      steps: { create: { stepOrder: 1, title: "test", actionId, reason: "evidence", evidence: [], instructions: [], phase: "ACTION" } } }, include: { steps: true } });
    const response = await db.responsePlan.create({ data: { tenantId, incidentId: incident.id, recommendationId: rec.id, recommendationStepId: rec.steps[0].id, actionId, reason: "test evidence", assignedRole: "IR_TEAM", status, approvalStatus: status === "PENDING_IR_DECISION" ? "PENDING" : "APPROVED" } });
    const approval = await db.approval.create({ data: { recommendationId: rec.id, responseId: response.id, approvalRole: "IR_TEAM", reason: "Policy IR decision", status: status === "PENDING_IR_DECISION" ? "pending" : "approved", ...(status !== "PENDING_IR_DECISION" ? { decidedBy: actor, decidedAt: new Date() } : {}) } });
    return { incident, rec, response, approval };
  }
  const decision = () => atomic.wrap(new DecideApprovalUseCase(approvals, audit, recommendations, context as never, responses, notification as never, "http://test"), "approval");
  const decide = (f: Awaited<ReturnType<typeof fixture>>, by = actor, status: "approved" | "rejected" = "approved") => decision().execute({ approvalId: f.approval.id, tenantId, status, decidedBy: by, decidedByRole: "IR_TEAM", comment: "human review" });
  const successAudits = (id: string) => db.auditLog.count({ where: { entityId: id, action: { in: ["APPROVAL_DECIDED", "APPROVAL_APPROVED", "APPROVAL_REJECTED"] } } });
  const verification = (reopen = false) => atomic.wrap(new CreateVerificationUseCase(
    new PrismaVerificationRepository(atomic.prisma), responses, incidents,
    { evaluate: async () => ({ requireNewInvestigation: reopen, requireEscalation: false, matchedPolicies: [] }) } as never,
    audit, context as never, notification as never, "http://test",
    { execute: async () => Result.fail("AI_UNAVAILABLE") } as never, undefined, undefined,
    effect => atomic.afterCommit(effect)), "incident");
  const verify = (f: Awaited<ReturnType<typeof fixture>>, by = actor, reopen = false) => verification(reopen).execute({ incidentId: f.incident.id, responseId: f.response.id, tenantId, verifiedBy: by, query: "test", matchingEvents: reopen ? 1 : 0, threatContained: !reopen });

  test("approval and response state commit with both human audit events", async () => {
    const f = await fixture(); expect((await decide(f)).isSuccess).toBe(true);
    expect((await db.approval.findUniqueOrThrow({ where: { id: f.approval.id } })).status).toBe("approved");
    expect((await db.responsePlan.findUniqueOrThrow({ where: { id: f.response.id } })).status).toBe("READY_FOR_EXECUTION");
    expect(await successAudits(f.approval.id)).toBe(2);
    expect(await db.auditLog.findFirst({ where: { entityId: f.approval.id } })).toMatchObject({ tenantId, actor });
  });
  test("audit insert failure rolls approval and response back", async () => {
    const f = await fixture(); await expect(decide(f, faultActor)).rejects.toThrow();
    expect((await db.approval.findUniqueOrThrow({ where: { id: f.approval.id } })).status).toBe("pending");
    expect((await db.responsePlan.findUniqueOrThrow({ where: { id: f.response.id } })).status).toBe("PENDING_IR_DECISION");
    expect(await successAudits(f.approval.id)).toBe(0);
  });
  test("manual IR decision rolls approval creation and ticket readiness back on failed audit", async () => {
    const f = await fixture("PENDING_MANUAL_DECISION");
    const manual = atomic.wrap(new ManualDecisionUseCase(approvals, responses, audit), "response");
    const before = await db.approval.count({ where: { responseId: f.response.id } });
    await expect(manual.execute({ tenantId, responseId: f.response.id, decidedBy: faultActor, decidedByRole: "IR_TEAM", note: "manual containment" })).rejects.toThrow();
    expect(await db.approval.count({ where: { responseId: f.response.id } })).toBe(before);
    expect((await db.responsePlan.findUniqueOrThrow({ where: { id: f.response.id } })).status).toBe("PENDING_MANUAL_DECISION");
  });
  test("failed optional approval opening preserves an audited pending ticket with no partial approval", async () => {
    const f = await fixture("FAILED");
    const actions = new PrismaActionRepository(atomic.prisma);
    const ctx = { getIncidentContext: async () => ({ incidentId: f.incident.id, title: "test", status: "investigating", priority: "medium", alertSeverity: "medium", investigationNumber: 1 }), getEvidence: async () => [] };
    const faultAudit = { record: async (event: Parameters<AuditLogger["record"]>[0]) => { if (event.action === "APPROVAL_REQUESTED") throw new Error("optional approval audit failed"); await audit.record(event); } };
    const service = atomic.wrap(new ApprovalService(ctx as never, actions, new PolicyEvaluator({ findAllEnabled: async () => [] } as never), approvals, faultAudit as never, notification as never, "http://test"), "recommendation", "open");
    const create = atomic.wrap(new CreateResponsePlanUseCase(recommendations, actions, new PrismaRunbookRepository(atomic.prisma), service, responses, audit, notification as never, "http://test"), "recommendation");
    const result = await create.execute({ tenantId, recommendationId: f.rec.id, stepId: f.rec.steps[0].id });
    expect(result.isSuccess).toBe(true);
    expect(result.value.status).toBe("PENDING_IR_DECISION");
    expect(await db.approval.count({ where: { responseId: result.value.id } })).toBe(0);
    expect(await db.auditLog.count({ where: { entityId: result.value.id, action: "RESPONSE_PLAN_CREATED" } })).toBe(1);
  });
  test("state failure after audit inserts rolls the audit and earlier state back", async () => {
    const f = await fixture(); const failure = jest.spyOn(responses, "updateStatus").mockRejectedValueOnce(new Error("injected state failure"));
    await expect(decide(f)).rejects.toThrow("injected state failure"); failure.mockRestore();
    expect((await db.approval.findUniqueOrThrow({ where: { id: f.approval.id } })).status).toBe("pending");
    expect(await successAudits(f.approval.id)).toBe(0);
  });
  test("approve/reject race produces one decision, never two success audits", async () => {
    const f = await fixture(); const results = await Promise.all([decide(f), decide(f, actor, "rejected")]);
    expect(results.filter(r => r.isSuccess)).toHaveLength(1);
    expect(results.find(r => r.isFailure)!.error).toBe("ALREADY_DECIDED");
    expect(await successAudits(f.approval.id)).toBe(2);
  });
  test("response start + execution rollback on failed audit; notification is discarded", async () => {
    const f = await fixture("READY_FOR_EXECUTION"); const notify = jest.fn(async () => {});
    const start = atomic.wrap(new StartResponseUseCase(responses, approvals, audit, atomic.defer({ notify } as never, ["notify"])), "response");
    await expect(start.execute({ tenantId, responseId: f.response.id, startedBy: faultActor })).rejects.toThrow();
    expect((await db.responsePlan.findUniqueOrThrow({ where: { id: f.response.id } })).status).toBe("READY_FOR_EXECUTION");
    expect(await db.stepExecution.count({ where: { planId: f.response.id } })).toBe(0);
    expect(notify).not.toHaveBeenCalled();
  });
  test("response notification observes committed state and audit", async () => {
    const f = await fixture("READY_FOR_EXECUTION"); let observed = false; const notify = jest.fn(async () => {
      expect((await db.responsePlan.findUniqueOrThrow({ where: { id: f.response.id } })).status).toBe("IN_PROGRESS");
      expect(await db.auditLog.count({ where: { entityId: f.response.id, action: "RESPONSE_STARTED" } })).toBe(1);
      observed = true;
    });
    const start = atomic.wrap(new StartResponseUseCase(responses, approvals, audit, atomic.defer({ notify } as never, ["notify"])), "response");
    expect((await start.execute({ tenantId, responseId: f.response.id, startedBy: actor })).isSuccess).toBe(true);
    expect(notify).toHaveBeenCalledTimes(1);
    expect(observed).toBe(true);
  });
  test("response complete/fail race permits one terminal transition", async () => {
    const f = await fixture("IN_PROGRESS");
    const complete = atomic.wrap(new CompleteResponseUseCase(responses, audit, incidents, new PrismaActionRepository(atomic.prisma), context as never, notification as never, "http://test"), "response");
    const fail = atomic.wrap(new FailResponseUseCase(responses, audit), "response");
    const results = await Promise.all([complete.execute({ tenantId, responseId: f.response.id, completedBy: actor, executionResult: {} }), fail.execute({ tenantId, responseId: f.response.id, failedBy: actor, executionResult: {} })]);
    expect(results.filter(r => r.isSuccess)).toHaveLength(1);
    expect(await db.auditLog.count({ where: { entityId: f.response.id, action: { in: ["RESPONSE_COMPLETED", "RESPONSE_FAILED"] } } })).toBe(1);
  });
  test("verification audit failure rolls back verification, resolution and cycle", async () => {
    const f = await fixture("COMPLETED"); await expect(verify(f, faultActor)).rejects.toThrow();
    expect(await db.verification.count({ where: { incidentId: f.incident.id } })).toBe(0);
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).status).toBe("investigating");
    expect(emit).not.toHaveBeenCalled();
  });
  test("failed reopen audit rolls back the new cycle and all success audit events", async () => {
    const f = await fixture("COMPLETED"); await expect(verify(f, faultActor, true)).rejects.toThrow();
    expect(await db.verification.count({ where: { incidentId: f.incident.id } })).toBe(0);
    expect(await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).toMatchObject({ investigationNumber: 1, status: "investigating" });
    expect(await db.investigation.count({ where: { incidentId: f.incident.id } })).toBe(1);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id } })).toBe(0);
    expect(emit).not.toHaveBeenCalled();
  });
  test("verification/re-hunt result race creates one verification and one completion audit", async () => {
    const f = await fixture("COMPLETED"); const results = await Promise.all([verify(f), verify(f)]);
    expect(results.filter(r => r.isSuccess)).toHaveLength(1);
    expect(results.find(r => r.isFailure)!.error).toBe("ALREADY_VERIFIED");
    expect(await db.verification.count({ where: { incidentId: f.incident.id } })).toBe(1);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "INCIDENT_RESOLVED" } })).toBe(1);
  });
  test("reopen commits before best-effort evidence and generation; failed AI does not undo it", async () => {
    const f = await fixture("COMPLETED"); let observed = false;
    const result = await verification(true).execute({ tenantId, incidentId: f.incident.id, responseId: f.response.id, verifiedBy: actor, query: "test", matchingEvents: 1, threatContained: false,
      onInvestigationReopened: async n => { expect(n).toBe(2); expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).investigationNumber).toBe(2); observed = true; } });
    expect(result.isSuccess).toBe(true); expect(observed).toBe(true);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "INVESTIGATION_REOPENED" } })).toBe(1);
  });
  test("maximum three rounds remains unchanged and escalation is audited atomically", async () => {
    const f = await fixture("COMPLETED", 3); expect((await verify(f, actor, true)).isSuccess).toBe(true);
    expect(await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).toMatchObject({ status: "escalated", investigationNumber: 3 });
    expect(await db.investigation.count({ where: { incidentId: f.incident.id } })).toBe(1);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "INCIDENT_ESCALATED" } })).toBe(1);
  });
  test("in-flight SIEM re-hunt holds no transaction lock and cannot double-verify a ticket", async () => {
    const f = await fixture("COMPLETED");
    let release!: () => void; let started!: () => void;
    const pending = new Promise<void>(resolve => { release = resolve; });
    const entered = new Promise<void>(resolve => { started = resolve; });
    const port = { isConfigured: () => true, rehunt: async () => { started(); await pending; return { index: "test", query: "test", source: "MOCK_REHUNT", matchingEvents: 0, affectedHosts: [], iocRecurrence: false, spreadDetected: false, threatContained: true, events: [], truncated: false }; } };
    const hunt = new RunRehuntVerificationUseCase(port as never, verification(), incidents, new PrismaAlertRepository(atomic.prisma), responses, new PrismaVerificationRepository(atomic.prisma), { ...context, getIocs: async () => [] } as never, undefined, audit);
    const running = hunt.execute({ tenantId, incidentId: f.incident.id, responseId: f.response.id, verifiedBy: actor });
    await entered;
    try { expect((await verify(f)).isSuccess).toBe(true); } finally { release(); }
    expect((await running).error).toBe("ALREADY_VERIFIED");
    expect(await db.verification.count({ where: { incidentId: f.incident.id } })).toBe(1);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "INCIDENT_RESOLVED" } })).toBe(1);
  });
  test("incident status race is idempotent; audit failure never returns successful mutation", async () => {
    const f = await fixture(); const update = atomic.wrap(new UpdateIncidentStatusUseCase(incidents, audit), "incident");
    await expect(update.execute({ tenantId, id: f.incident.id, status: "dismissed", actor: faultActor })).rejects.toThrow();
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).status).toBe("investigating");
    await Promise.all([update.execute({ tenantId, id: f.incident.id, status: "dismissed", actor }), update.execute({ tenantId, id: f.incident.id, status: "dismissed", actor })]);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "INCIDENT_STATUS_CHANGED" } })).toBe(1);
  });
  test("human severity validation keeps its existing rules and rolls state and timeline back on audit failure", async () => {
    const f = await fixture();
    const validate = atomic.wrap(new ValidateIncidentSeverityUseCase({ getIncidentContext: async () => ({ status: "investigating", priority: "medium", alertSeverity: "medium" }) } as never,
      new PrismaIncidentSeverityWriter(atomic.prisma), audit), "incident");
    const input = { tenantId, incidentId: f.incident.id, actor: faultActor, actorRole: "SOC", severity: "HIGH" as const, note: "human validation" };
    // Pending IR decisions retain the existing lock rule. Use a failed synthetic ticket to permit the existing human flow.
    await db.responsePlan.update({ where: { id: f.response.id }, data: { status: "FAILED" } });
    const before = await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } });
    await expect(validate.execute(input)).rejects.toThrow();
    expect(await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).toEqual(before);
    expect(await db.incidentTimeline.count({ where: { incidentId: f.incident.id, eventType: "SEVERITY_VALIDATED" } })).toBe(0);
    expect((await validate.execute({ ...input, actor })).isSuccess).toBe(true);
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).priority).toBe("high");
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "SEVERITY_VALIDATED" } })).toBe(1);
  });
  test("incident creation rolls alert handoff, links, evidence and timeline back when audit fails", async () => {
    const alerts = new PrismaAlertRepository(atomic.prisma);
    const alert = await db.alert.create({ data: { tenantId, externalAlertId: randomUUID(), siemSource: "test", severity: "low", receivedAt: new Date(), rawPayload: {} } });
    const create = atomic.wrap(new CreateIncidentUseCase(incidents, alerts, audit), "incident");
    await expect(create.execute({ tenantId, createdBy: faultActor, title: "manual LOW incident", priority: "low", alertIds: [alert.id] })).rejects.toThrow();
    expect(await db.incident.count({ where: { alertId: alert.id } })).toBe(0);
    expect(await db.incidentAlert.count({ where: { alertId: alert.id } })).toBe(0);
    expect(await db.evidence.count({ where: { alertId: alert.id } })).toBe(0);
    expect(await db.alert.findUniqueOrThrow({ where: { id: alert.id } })).toEqual(alert);
  });
  test("concurrent incident creation for SIEM aliases produces one incident and one audit", async () => {
    const externalAlertId = randomUUID();
    const aliases = await Promise.all([1, 2].map(() => db.alert.create({ data: { tenantId, externalAlertId, siemSource: "test", severity: "low", receivedAt: new Date(), rawPayload: {} } })));
    const create = atomic.wrap(new CreateIncidentUseCase(incidents, new PrismaAlertRepository(atomic.prisma), audit), "incident");
    const results = await Promise.all(aliases.map(alert => create.execute({ tenantId, createdBy: actor, title: "SIEM alias race", priority: "low", alertIds: [alert.id] })));
    expect(results.filter(result => result.isSuccess)).toHaveLength(1);
    expect(results.find(result => result.isFailure)?.error.code).toBe("DUPLICATE_ALERT");
    const winner = results.find(result => result.isSuccess)!.value;
    expect(await db.incident.count({ where: { alertId: { in: aliases.map(a => a.id) } } })).toBe(1);
    expect(await db.auditLog.count({ where: { entityId: winner.id, action: "INCIDENT_CREATED" } })).toBe(1);
  });
  test("merge audit failure rolls moved links, source dismissal and timeline back", async () => {
    const create = atomic.wrap(new CreateIncidentUseCase(incidents, new PrismaAlertRepository(atomic.prisma), audit), "incident");
    const alerts = await Promise.all([1, 2].map(() => db.alert.create({ data: { tenantId, externalAlertId: randomUUID(), siemSource: "test", severity: "medium", receivedAt: new Date(), rawPayload: {} } })));
    const target = (await create.execute({ tenantId, createdBy: actor, title: "merge target", priority: "medium", alertIds: [alerts[0].id] })).value;
    const source = (await create.execute({ tenantId, createdBy: actor, title: "merge source", priority: "medium", alertIds: [alerts[1].id] })).value;
    const before = await db.incident.findUniqueOrThrow({ where: { id: source.id } });
    const links = await db.incidentAlert.findMany({ where: { incidentId: source.id } });
    const timelines = await db.incidentTimeline.count({ where: { incidentId: { in: [target.id, source.id] } } });
    const merge = atomic.wrap(new MergeAlertsIntoIncidentUseCase(incidents, new PrismaAlertRepository(atomic.prisma), { syncIncident: async () => {} } as never, audit), "incident");
    await expect(merge.execute({ tenantId, incidentId: target.id, alertIds: [alerts[1].id], actor: faultActor })).rejects.toThrow();
    expect(await db.incident.findUniqueOrThrow({ where: { id: source.id } })).toEqual(before);
    expect(await db.incidentAlert.findMany({ where: { incidentId: source.id } })).toEqual(links);
    expect(await db.incidentTimeline.count({ where: { incidentId: { in: [target.id, source.id] } } })).toBe(timelines);
    expect(await db.auditLog.count({ where: { entityId: target.id, action: "ALERTS_MERGED" } })).toBe(0);
  });
  test("existing transactional SOC triage remains atomic on audit failure", async () => {
    const alert = await db.alert.create({ data: { tenantId, externalAlertId: randomUUID(), siemSource: "test", severity: "medium", receivedAt: new Date(), rawPayload: {} } });
    await expect(alertWorkflow(db).triage.execute({ tenantId, alertId: alert.id, actor: faultActor, decision: "FALSE_POSITIVE", reason: "confirmed benign" })).rejects.toThrow();
    expect(await db.alert.findUniqueOrThrow({ where: { id: alert.id } })).toEqual(alert);
  });
  test("SOC reject rolls back both recommendation and dismissal on failed audit", async () => {
    const f = await fixture(); await db.responsePlan.update({ where: { id: f.response.id }, data: { status: "FAILED" } });
    const reject = atomic.wrap(new RejectRecommendationUseCase(recommendations, responses, incidents, audit), "recommendation");
    await expect(reject.execute({ tenantId, recommendationId: f.rec.id, actor: faultActor, note: "benign" })).rejects.toThrow();
    expect((await db.recommendation.findUniqueOrThrow({ where: { id: f.rec.id } })).status).toBe("VALIDATED");
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).status).toBe("investigating");
  });
  test("generation audit failure rolls snapshot, recommendation and supersession back", async () => {
    const f = await fixture(); const generate = new GenerateRecommendationUseCase(
      { build: async () => Result.ok({ investigationNumber: 1 }) } as never, { generate: async () => ({}) }, faultActor,
      { validate: async () => ({ status: "VALIDATED", summary: "new", steps: [], snapshot: { playbookCode: "PB", playbookVersion: "1", procedureCode: "P", procedureVersion: "1", procedureContent: {}, policyResult: {} } }) } as never,
      recommendations, audit, atomic);
    await expect(generate.execute({ tenantId, incidentId: f.incident.id })).rejects.toThrow();
    expect(await db.playbookSnapshot.count({ where: { incidentId: f.incident.id } })).toBe(0);
    expect(await db.recommendation.count({ where: { incidentId: f.incident.id } })).toBe(1);
    expect((await db.recommendation.findUniqueOrThrow({ where: { id: f.rec.id } })).status).toBe("VALIDATED");
  });
  test("playbook update and replaced steps rollback with audit failure", async () => {
    const book = await db.playbook.create({ data: { tenantId, code: `PB-${randomUUID()}`, name: "before", triggerConditions: {}, steps: { create: { stepOrder: 1, title: "before", description: "before" } } }, include: { steps: true } });
    const update = atomic.wrap(new UpdatePlaybookUseCase(new PrismaPlaybookRepository(atomic.prisma), audit), "playbook");
    await expect(update.execute({ tenantId, id: book.id, actor: faultActor, name: "after", steps: [{ stepOrder: 1, title: "after", description: "after" }] })).rejects.toThrow();
    expect(await db.playbook.findUniqueOrThrow({ where: { id: book.id }, include: { steps: true } })).toEqual(book);
  });
  test("nested best-effort failure rolls back its state and audit without undoing audited parent", async () => {
    const f = await fixture(); await atomic.run("incident", { tenantId, incidentId: f.incident.id }, async () => {
      await atomic.prisma.incident.update({ where: { id: f.incident.id }, data: { title: "parent" } });
      await audit.record({ tenantId, actor, action: "PARENT_CHANGED", entity: "Incident", entityId: f.incident.id });
      try { await atomic.run("incident", { tenantId, incidentId: f.incident.id }, async () => {
        await atomic.prisma.incident.update({ where: { id: f.incident.id }, data: { title: "child" } });
        await audit.record({ tenantId, actor: faultActor, action: "CHILD_CHANGED", entity: "Incident", entityId: f.incident.id });
      }); } catch { /* Existing best-effort child workflow semantics. */ }
    });
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).title).toBe("parent");
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "PARENT_CHANGED" } })).toBe(1);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id, action: "CHILD_CHANGED" } })).toBe(0);
  });
  test("caught audit failure cannot commit a successful mutation", async () => {
    const f = await fixture(); await expect(atomic.run("incident", { tenantId, incidentId: f.incident.id }, async () => {
      await atomic.prisma.incident.update({ where: { id: f.incident.id }, data: { title: "uncommitted" } });
      try { await audit.record({ tenantId, actor: faultActor, action: "CHANGED", entity: "Incident", entityId: f.incident.id }); } catch { /* Simulate legacy best-effort catch. */ }
      return Result.ok({});
    })).rejects.toThrow();
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).title).toBe(f.incident.title);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id } })).toBe(0);
  });
  test("failure result after partial writes rolls state and success audit back", async () => {
    const f = await fixture(); const result = await atomic.run("incident", { tenantId, incidentId: f.incident.id }, async () => {
      await atomic.prisma.incident.update({ where: { id: f.incident.id }, data: { title: "uncommitted" } });
      await audit.record({ tenantId, actor, action: "CHANGED", entity: "Incident", entityId: f.incident.id });
      return Result.fail("FAILED_STATE");
    });
    expect(result.error).toBe("FAILED_STATE");
    expect((await db.incident.findUniqueOrThrow({ where: { id: f.incident.id } })).title).toBe(f.incident.title);
    expect(await db.auditLog.count({ where: { entityId: f.incident.id } })).toBe(0);
  });
  test("real protected route rejects anonymous, service, SOC and cross-tenant callers", async () => {
    const f = await fixture(); const app = express(); app.use(express.json());
    app.use("/approvals", buildApprovalRoutes(new ApprovalController({} as never, decision(), {} as never, {} as never)));
    const server: Server = app.listen(0); await new Promise<void>(resolve => server.once("listening", resolve));
    const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/approvals/${f.approval.id}/approve?tenantId=${tenantId}`;
    const call = (token?: string) => fetch(endpoint, { method: "POST", signal: AbortSignal.timeout(10000), headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify({ comment: "review" }) });
    try {
      expect((await call()).status).toBe(401);
      expect((await call(signServiceToken({ id: "service:test", tenantId, scopes: [], jobIds: [] }))).status).toBe(403);
      expect((await call(signToken({ id: actor, tenantId, role: "SOC" }))).status).toBe(403);
      expect((await call(signToken({ id: actor, tenantId: randomUUID(), role: "IR_TEAM" }))).status).toBe(404);
      expect(await successAudits(f.approval.id)).toBe(0);
      expect((await call(signToken({ id: faultActor, tenantId, role: "IR_TEAM" }))).status).toBe(500);
      expect((await db.approval.findUniqueOrThrow({ where: { id: f.approval.id } })).status).toBe("pending");
      expect((await call(signToken({ id: actor, tenantId, role: "IR_TEAM" }))).status).toBe(200);
    } finally { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
  });
});
