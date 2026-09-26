import * as fs from "node:fs";
import * as path from "node:path";

import { POLICIES } from "../prisma/seeds/policy.seed";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { MockRehuntAdapter, MockRehuntMode, DEFAULT_MOCK_ATTACKS_DIR } from "../src/infrastructure/external-services/siem/MockRehuntAdapter";
import { RunRehuntVerificationUseCase } from "../src/application/verification/use-cases/RunRehuntVerification.usecase";
import { CreateVerificationUseCase, MAX_INVESTIGATION_ROUNDS } from "../src/application/verification/use-cases/CreateVerification.usecase";
import { StartResponseUseCase } from "../src/application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../src/application/response/use-cases/CompleteResponse.usecase";
import { FailResponseUseCase } from "../src/application/response/use-cases/FailResponse.usecase";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { Incident } from "../src/domain/incident/entities/Incident.entity";
import { Alert } from "../src/domain/alert/entities/Alert.entity";
import { Verification } from "../src/domain/verification/entities/Verification.entity";
import { ResponsePlan, ResponseStatus, ResponseApprovalStatus } from "../src/domain/response/entities/ResponsePlan.entity";
import { Approval } from "../src/domain/approval/entities/Approval.entity";
import { IIncidentRepository } from "../src/domain/incident/repositories/IIncidentRepository";
import { IAlertRepository } from "../src/domain/alert/repositories/IAlertRepository";
import { IResponsePlanRepository } from "../src/domain/response/repositories/IResponsePlanRepository";
import { IVerificationRepository, CreateVerificationData } from "../src/domain/verification/repositories/IVerificationRepository";
import { IApprovalRepository } from "../src/domain/approval/repositories/IApprovalRepository";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { IInvestigationRepository } from "../src/domain/investigation/IInvestigationRepository";
import { CreateEvidenceData, CreateIocData, DuplicateIocError } from "../src/domain/investigation/Investigation.types";
import { IActionRepository } from "../src/domain/action/repositories/IActionRepository";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { INotificationDispatcherPort } from "../src/application/notification/ports/INotificationDispatcherPort";

/**
 * Task 9 — Human execution -> Verification -> Mock re-hunt -> RESOLVED / new cycle / escalation.
 * REAL: Start/Complete/FailResponse, RunRehuntVerification, CreateVerification, PolicyEvaluator (canonical
 * POLICIES incl. RULE-V01..V03), MockRehuntAdapter over resources/mock-attacks. FAKE: persistence, audit sink,
 * notifications, and the recommendation generator (recorded, so its timing and inputs can be asserted).
 */

const TENANT = "tenant-1";
/** IR justification for proceeding without Manager approval (Policy did not require one for these tickets). */
const IR_NOTE = "Single endpoint, approved playbook action, no critical asset affected — IR approves the response.";
const fixtures: Record<string, any> = Object.fromEntries(
  fs
    .readdirSync(DEFAULT_MOCK_ATTACKS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .flatMap((d) => fs.readdirSync(path.join(DEFAULT_MOCK_ATTACKS_DIR, d.name)).filter((f) => /^case-.*\.json$/.test(f)).map((f) => path.join(DEFAULT_MOCK_ATTACKS_DIR, d.name, f)))
    .map((f) => JSON.parse(fs.readFileSync(f, "utf-8")))
    .map((c) => [c.id, c])
);

const policies = POLICIES.map((p, i) =>
  Policy.create({
    id: `pol-${i}`, tenantId: TENANT, code: p.code, name: p.name, description: p.description, type: p.type, enabled: true, version: 1, precedence: p.precedence,
    createdAt: new Date(), updatedAt: new Date(),
    rules: p.rules.map((r, j) => PolicyRule.create({ id: `r-${i}-${j}`, policyId: `pol-${i}`, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })),
  })
);

/** The incident's hunted IOCs: the primary alert's + (for correlated cases) the related alerts' searchable ones. */
function incidentIocs(c: any, correlated: boolean) {
  const alerts = correlated ? [c.alert, ...(c.relatedAlerts ?? [])] : [c.alert];
  const text = JSON.stringify(alerts);
  return c.expected.iocs
    .filter((i: any) => ["ip", "domain", "url", "hash"].includes(i.type) && text.includes(i.value))
    .map((i: any) => ({ iocType: { ip: "IPV4", domain: "DOMAIN", url: "URL", hash: "SHA256" }[i.type as "ip"], iocValue: i.value, source: "aggregated", reputationScore: null }));
}

function world(caseId: string, opts: { mode?: MockRehuntMode; correlated?: boolean; approvalStatus?: ResponseApprovalStatus; planStatus?: ResponseStatus } = {}) {
  const c = fixtures[caseId];
  const audit: Array<{ action: string; actor: string; entityId: string; metadata?: any }> = [];
  const order: string[] = [];
  let incident = Incident.create({ id: `inc-${caseId}`, tenantId: TENANT, alertId: `alert-${caseId}`, title: c.title, status: "investigating", priority: "high", openedAt: new Date(), closedAt: null, mttdSeconds: null, mttrSeconds: null, investigationNumber: 1 });
  const alert = Alert.create({ id: `alert-${caseId}`, tenantId: TENANT, externalAlertId: c.alert.id, siemSource: "wazuh", rawPayload: c.alert, severity: c.expected.severity, status: "received", receivedAt: new Date(), createdAt: new Date() });

  const plans: ResponsePlan[] = [];
  const verifications: Verification[] = [];
  const evidence: CreateEvidenceData[] = [];
  const iocs: Array<CreateIocData & { id: string }> = [];
  const approvals: Approval[] = [];
  const investigations = () =>
    Array.from({ length: incident.investigationNumber }, (_, i) => ({ id: `inv-${i + 1}`, incidentId: incident.id, investigationNumber: i + 1, isCurrent: i + 1 === incident.investigationNumber }));

  const incidentRepository = {
    findById: async () => incident,
    updateStatus: async (_id: string, _t: string, status: Incident["status"]) => {
      order.push(`incident:${status}`);
      incident = Incident.create({ ...incident.toJSON(), status, closedAt: status === "resolved" ? new Date() : null });
      return incident;
    },
    incrementInvestigationNumber: async () => {
      order.push(`investigation:${incident.investigationNumber + 1}`);
      incident = Incident.create({ ...incident.toJSON(), investigationNumber: incident.investigationNumber + 1, status: "investigating" });
      return incident;
    },
  } as unknown as IIncidentRepository;
  const alertRepository = { findById: async () => alert } as unknown as IAlertRepository;
  const responsePlanRepository = {
    findById: async (id: string) => plans.find((p) => p.id === id) ?? null,
    updateStatus: async (id: string, _t: string, d: Record<string, unknown>) => {
      const i = plans.findIndex((p) => p.id === id);
      plans[i] = ResponsePlan.create({ ...plans[i].toJSON(), ...d, updatedAt: new Date() });
      return plans[i];
    },
  } as unknown as IResponsePlanRepository;
  const verificationRepository: IVerificationRepository = {
    findById: async (id) => verifications.find((v) => v.id === id) ?? null,
    findAllByIncident: async () => verifications,
    findAll: async () => verifications,
    create: async (d: CreateVerificationData) => {
      const v = Verification.create({ id: `ver-${verifications.length + 1}`, ...d, verifiedAt: new Date() } as never);
      verifications.push(v);
      return v;
    },
  };
  const approvalRepository = { findByResponse: async (id: string) => approvals.filter((a) => a.responseId === id), findByRecommendation: async () => [] } as unknown as IApprovalRepository;
  const contextRepository = {
    getIocs: async () => [...incidentIocs(c, !!opts.correlated), ...iocs.map((i) => ({ iocType: i.iocType, iocValue: i.iocValue, source: i.source, reputationScore: null }))],
    getLatestRiskScore: async () => 39,
  } as unknown as IRecommendationContextRepository;
  const investigationRepository = {
    listByIncident: async () => investigations(),
    createEvidence: async (d: CreateEvidenceData) => {
      order.push(`evidence:${d.investigationId}`);
      evidence.push(d);
      return { id: `ev-${evidence.length}` };
    },
    createIoc: async (d: CreateIocData) => {
      const dup = iocs.find((i) => i.investigationId === d.investigationId && i.iocType === d.iocType && i.iocValue === d.iocValue);
      if (dup) throw new DuplicateIocError(dup.id);
      const row = { ...d, id: `ioc-${iocs.length + 1}` };
      iocs.push(row);
      return row;
    },
  } as unknown as IInvestigationRepository;
  const auditLogger = { record: async (e: any) => void audit.push(e) } as unknown as AuditLogger;
  const notifications = { emit: async () => undefined } as unknown as INotificationDispatcherPort;
  const generate = {
    execute: jest.fn(async () => {
      order.push(`recommendation:inv-${incident.investigationNumber}`);
      return { isFailure: false, isSuccess: true, value: {} };
    }),
  } as unknown as GenerateRecommendationUseCase;

  const createVerification = new CreateVerificationUseCase(verificationRepository, responsePlanRepository, incidentRepository, new PolicyEvaluator({ findAllEnabled: async () => policies } as unknown as IPolicyRepository), auditLogger, contextRepository, notifications, "http://vigix.test", generate);
  const runRehunt = new RunRehuntVerificationUseCase(new MockRehuntAdapter(opts.mode ?? "FIXTURE"), createVerification, incidentRepository, alertRepository, responsePlanRepository, verificationRepository, contextRepository, investigationRepository, auditLogger);
  const start = new StartResponseUseCase(responsePlanRepository, approvalRepository, auditLogger);
  const complete = new CompleteResponseUseCase(responsePlanRepository, auditLogger, incidentRepository, { findById: async () => null } as unknown as IActionRepository, contextRepository, notifications, "http://vigix.test");
  const fail = new FailResponseUseCase(responsePlanRepository, auditLogger);

  /** An IR-approved Response Ticket for the current cycle (SOC sent it; IR APPROVED it with a note). */
  const addPlan = (o: { irDecision?: "approved" | "rejected" | "none" } = {}) => {
    const p = ResponsePlan.create({
      id: `plan-${plans.length + 1}`, tenantId: TENANT, incidentId: incident.id, recommendationId: `rec-${incident.investigationNumber}`, recommendationStepId: "step-1", actionId: "act-1",
      target: c.response.target, reason: c.response.action, expectedResult: null, approvalStatus: opts.approvalStatus ?? "APPROVED", assignedRole: "IR_TEAM", assignedTo: null,
      status: opts.planStatus ?? "READY_FOR_EXECUTION", executionResult: null, executedAt: null, completedAt: null, createdAt: new Date(), updatedAt: new Date(),
    });
    plans.push(p);
    const decision = o.irDecision ?? "approved";
    if (decision !== "none") {
      approvals.push(Approval.create({
        id: `appr-${approvals.length + 1}`, tenantId: TENANT, recommendationId: p.recommendationId, responseId: p.id, approvalRole: "IR_TEAM", reason: "IR decision required",
        status: decision, stepOrder: 1, requestedTo: null, decidedBy: "ir-lead", decidedAt: new Date(), comment: IR_NOTE, createdAt: new Date(),
      }));
    }
    return p;
  };
  /** Human execution + re-hunt verification of one round. */
  const executeAndVerify = async () => {
    const plan = addPlan();
    const s = await start.execute({ responseId: plan.id, tenantId: TENANT, startedBy: "ir-1" });
    expect(s.isSuccess).toBe(true);
    const done = await complete.execute({ responseId: plan.id, tenantId: TENANT, completedBy: "ir-1", executionResult: { performed: c.response.action } });
    expect(done.isSuccess).toBe(true);
    return runRehunt.execute({ incidentId: incident.id, responseId: plan.id, tenantId: TENANT, verifiedBy: "ir-1" });
  };

  return { c, audit, order, plans, verifications, evidence, iocs, approvals, generate, start, complete, fail, runRehunt, createVerification, addPlan, executeAndVerify, incident: () => incident };
}

describe("Human execution (existing Start/Complete/Fail)", () => {
  it("READY_FOR_EXECUTION -> Start (IN_PROGRESS, executed_at, audit) -> Complete (COMPLETED, completed_at, audit)", async () => {
    const w = world("ATK-01");
    const p = w.addPlan();
    const s = await w.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: "ir-1" });
    expect(s.value).toMatchObject({ status: "IN_PROGRESS", assignedTo: "ir-1" });
    expect(s.value.executedAt).toBeInstanceOf(Date);
    const c = await w.complete.execute({ responseId: p.id, tenantId: TENANT, completedBy: "ir-1", executionResult: { blocked: "185.220.101.45" } });
    expect(c.value).toMatchObject({ status: "COMPLETED", executionResult: { blocked: "185.220.101.45" } });
    expect(c.value.completedAt).toBeInstanceOf(Date);
    expect(w.audit.map((a) => a.action)).toEqual(["RESPONSE_STARTED", "RESPONSE_COMPLETED"]);
    expect(w.audit.some((a) => /MANAGER/.test(a.action))).toBe(false);
  });

  it("no IR APPROVE, no execution: a ticket without an approved IR decision cannot start, whatever its status says", async () => {
    const w = world("ATK-01", { approvalStatus: "NOT_REQUIRED" });
    const p = w.addPlan({ irDecision: "none" });
    expect((await w.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: "ir-1" })).error).toBe("APPROVAL_PENDING");
    const q = w.addPlan({ irDecision: "rejected" });
    expect((await w.start.execute({ responseId: q.id, tenantId: TENANT, startedBy: "ir-1" })).error).toBe("APPROVAL_REJECTED");
    expect(w.plans.map((x) => x.status)).toEqual(["READY_FOR_EXECUTION", "READY_FOR_EXECUTION"]);
    expect(w.audit).toEqual([]);
  });

  it("a ticket still waiting for the IR decision cannot start", async () => {
    const w = world("ATK-08", { approvalStatus: "PENDING", planStatus: "PENDING_IR_DECISION" });
    const p = w.addPlan({ irDecision: "none" });
    expect((await w.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: "ir-1" })).error).toBe("APPROVAL_PENDING");
    expect(w.audit.some((a) => a.action === "RESPONSE_STARTED")).toBe(false);
  });

  it("Fail -> FAILED; a failed response can never be verified (RESPONSE_NOT_COMPLETED), no re-hunt verdict", async () => {
    const w = world("ATK-01");
    const p = w.addPlan();
    await w.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: "ir-1" });
    const f = await w.fail.execute({ responseId: p.id, tenantId: TENANT, failedBy: "ir-1", executionResult: { error: "firewall API rejected rule" } } as never);
    expect(f.value).toMatchObject({ status: "FAILED" });
    expect(w.audit.map((a) => a.action)).toContain("RESPONSE_FAILED");
    expect((await w.runRehunt.execute({ incidentId: w.incident().id, responseId: p.id, tenantId: TENANT, verifiedBy: "ir-1" })).error).toBe("RESPONSE_NOT_COMPLETED");
    expect((await w.createVerification.execute({ incidentId: w.incident().id, responseId: p.id, tenantId: TENANT, verifiedBy: "ir-1", query: "manual", matchingEvents: 0, threatContained: true })).error).toBe("RESPONSE_NOT_COMPLETED");
    expect(w.verifications).toEqual([]);
    expect(w.incident().status).toBe("investigating");
  });

  it("REJECTED ticket (IR REJECT): cannot start, no execution, cannot be verified", async () => {
    const w = world("ATK-08", { approvalStatus: "REJECTED", planStatus: "REJECTED" });
    const p = w.addPlan({ irDecision: "rejected" });
    expect((await w.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: "ir-1" })).error).toBe("APPROVAL_REJECTED");
    expect(w.plans[0]).toMatchObject({ status: "REJECTED", executedAt: null });
    expect((await w.runRehunt.execute({ incidentId: w.incident().id, responseId: p.id, tenantId: TENANT, verifiedBy: "ir-1" })).error).toBe("RESPONSE_NOT_COMPLETED");
    expect(w.verifications).toEqual([]);
    expect(w.audit.some((a) => a.action === "RESPONSE_STARTED")).toBe(false);
  });
});

describe("ATK-01 happy path", () => {
  it("execute -> re-hunt NO_MATCH -> RESOLVED -> incident resolved, no new cycle, no new recommendation", async () => {
    const w = world("ATK-01");
    const r = await w.executeAndVerify();
    expect(r.value.verification).toMatchObject({ result: "RESOLVED", matchingEvents: 0, threatContained: true, spreadDetected: false, iocRecurrence: false });
    expect(r.value.verification.afterState).toMatchObject({ evidenceSource: "MOCK_REHUNT" });
    expect(w.incident()).toMatchObject({ status: "resolved", investigationNumber: 1 });
    expect(w.generate.execute).not.toHaveBeenCalled();
    expect(w.audit.map((a) => a.action)).toEqual(["RESPONSE_STARTED", "RESPONSE_COMPLETED", "REHUNT_STARTED", "INCIDENT_RESOLVED", "VERIFICATION_COMPLETED"]);
  });

  it("ATK-08 approved plan: human executes -> re-hunt NO_MATCH -> RESOLVED", async () => {
    const w = world("ATK-08", { approvalStatus: "APPROVED" });
    const r = await w.executeAndVerify();
    expect(r.value.verification.result).toBe("RESOLVED");
    expect(w.incident().status).toBe("resolved");
  });
});

describe("Unresolved loop (fixture rounds)", () => {
  it("ATK-02: MATCH -> NOT_RESOLVED -> Investigation #2 with recurrence evidence + carried IOC BEFORE Recommendation #2; nothing auto-executed; round 2 NO_MATCH -> RESOLVED", async () => {
    const w = world("ATK-02");
    const r1 = await w.executeAndVerify();
    expect(r1.value.verification).toMatchObject({ result: "NOT_RESOLVED", iocRecurrence: true, spreadDetected: false, matchingEvents: 2 });
    expect(w.incident()).toMatchObject({ status: "investigating", investigationNumber: 2 });
    // New evidence in the NEW cycle, then the new recommendation — in that order.
    expect(w.order).toEqual(["investigation:2", "evidence:inv-2", "evidence:inv-2", "recommendation:inv-2"]);
    expect(w.evidence.every((e) => e.investigationId === "inv-2" && e.type === "WAZUH_EVENT" && e.source === "MOCK_REHUNT")).toBe(true);
    expect(w.iocs).toEqual([expect.objectContaining({ investigationId: "inv-2", iocType: "IPV4", iocValue: "185.220.101.46", source: "REHUNT" })]);
    expect(w.evidence.find((e) => e.iocIds.length > 0)?.iocIds).toEqual(["ioc-1"]);
    // No response was started for the new cycle — SOC must review the new recommendation and send it to IR again.
    expect(w.plans).toHaveLength(1);
    expect(w.audit.filter((a) => a.action === "RESPONSE_STARTED")).toHaveLength(1);
    expect(w.audit.map((a) => a.action)).toContain("INVESTIGATION_REOPENED");

    const r2 = await w.executeAndVerify();
    expect(r2.value.verification.result).toBe("RESOLVED");
    expect(w.incident()).toMatchObject({ status: "resolved", investigationNumber: 2 });
  });

  it("ATK-06: SPREAD -> NOT_RESOLVED + spread -> Investigation #2 + escalation audited (RULE-V02) -> round 2 RESOLVED", async () => {
    const w = world("ATK-06");
    const r1 = await w.executeAndVerify();
    expect(r1.value.verification).toMatchObject({ result: "NOT_RESOLVED", spreadDetected: true, affectedHosts: expect.arrayContaining(["WEB-01", "WEB-02"]) });
    expect(w.incident().investigationNumber).toBe(2);
    expect(w.audit.find((a) => a.action === "INVESTIGATION_ESCALATED")?.metadata).toMatchObject({ reasons: ["POLICY_REQUIRE_ESCALATION"], escalatedTo: "IR_TEAM" });
    expect(w.evidence.map((e) => (e.structuredData as any).agent).sort()).toEqual(["WEB-01", "WEB-02"]);
    expect((await w.executeAndVerify()).value.verification.result).toBe("RESOLVED");
  });

  it("ATK-10: persistence MATCH -> Investigation #2 -> round 2 RESOLVED", async () => {
    const w = world("ATK-10");
    expect((await w.executeAndVerify()).value.verification).toMatchObject({ result: "NOT_RESOLVED", iocRecurrence: true });
    expect(w.iocs.map((i) => `${i.iocType}:${i.iocValue}`).sort()).toEqual(["DOMAIN:vigix-mock-c2.net", "URL:http://vigix-mock-c2.net/beacon.ps1"]);
    expect((await w.executeAndVerify()).value.verification.result).toBe("RESOLVED");
  });

  it(`ATK-04 (correlated incident): 3 MATCH rounds -> cycles 2 and 3 -> round ${MAX_INVESTIGATION_ROUNDS} escalates to IR, no 4th cycle, no recommendation, never resolved`, async () => {
    const w = world("ATK-04", { correlated: true });
    for (let round = 1; round <= 3; round++) {
      const r = await w.executeAndVerify();
      expect(r.value.verification.result).toBe("NOT_RESOLVED");
    }
    expect(w.incident()).toMatchObject({ investigationNumber: 3, status: "escalated" }); // loop ended, not closed
    expect(w.generate.execute).toHaveBeenCalledTimes(2); // for cycles 2 and 3 only
    const escalated = w.audit.filter((a) => a.action === "INVESTIGATION_ESCALATED");
    expect(escalated).toHaveLength(1);
    expect(escalated[0].metadata).toMatchObject({ reasons: ["MAX_INVESTIGATION_ROUNDS_REACHED"], escalatedTo: "IR_TEAM", investigationNumber: 3, maxInvestigationRounds: 3 });
    expect(w.audit.filter((a) => a.action === "INVESTIGATION_REOPENED")).toHaveLength(2);
    expect(w.audit.filter((a) => a.action === "RESPONSE_STARTED")).toHaveLength(3); // only the 3 human-started ones
    // Incident-level escalation event (handoff to human SOC / IR review), never an automatic response.
    const incidentEscalated = w.audit.filter((a) => a.action === "INCIDENT_ESCALATED");
    expect(incidentEscalated).toHaveLength(1);
    expect(incidentEscalated[0].metadata).toMatchObject({ handoffTo: ["SOC", "IR_TEAM"], investigationNumber: 3 });
    expect(w.audit.filter((a) => a.action === "INCIDENT_RESOLVED")).toHaveLength(0);
    expect(w.audit.filter((a) => a.action === "REHUNT_STARTED")).toHaveLength(3);
  });
});

describe("Re-hunt failure safety", () => {
  it.each([
    ["ERROR", "REHUNT_QUERY_FAILED"],
    ["TIMEOUT", "REHUNT_TIMEOUT"],
    ["INDEXER_UNAVAILABLE", "REHUNT_UNREACHABLE"],
  ] as const)("%s -> %s: no Verification, incident untouched (not RESOLVED), REHUNT_FAILED audited", async (mode, error) => {
    const w = world("ATK-01", { mode });
    const r = await w.executeAndVerify();
    expect(r.error).toBe(error);
    expect(w.verifications).toEqual([]);
    expect(w.incident()).toMatchObject({ status: "investigating", investigationNumber: 1 });
    expect(w.audit.find((a) => a.action === "REHUNT_FAILED")?.metadata).toMatchObject({ code: mode === "ERROR" ? "QUERY_FAILED" : mode === "TIMEOUT" ? "TIMEOUT" : "UNREACHABLE" });
    expect(w.audit.some((a) => a.action === "VERIFICATION_COMPLETED")).toBe(false);
    // The plan stays COMPLETED, so the re-hunt can be retried once the SIEM is back.
    expect(w.plans[0].status).toBe("COMPLETED");
  });

  it("verification cannot be repeated for the same response (ALREADY_VERIFIED)", async () => {
    const w = world("ATK-01");
    const r = await w.executeAndVerify();
    expect((await w.runRehunt.execute({ incidentId: w.incident().id, responseId: r.value.verification.responseId!, tenantId: TENANT, verifiedBy: "ir-1" })).error).toBe("ALREADY_VERIFIED");
    expect(w.verifications).toHaveLength(1);
  });

  it("manual verification claiming contained but with matching events is NOT_RESOLVED", async () => {
    const w = world("ATK-01");
    const p = w.addPlan();
    await w.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: "ir-1" });
    await w.complete.execute({ responseId: p.id, tenantId: TENANT, completedBy: "ir-1", executionResult: {} });
    const v = await w.createVerification.execute({ incidentId: w.incident().id, responseId: p.id, tenantId: TENANT, verifiedBy: "ir-1", query: "manual", matchingEvents: 3, threatContained: true });
    expect(v.value.result).toBe("NOT_RESOLVED");
    expect(w.incident().status).not.toBe("resolved");
  });
});
