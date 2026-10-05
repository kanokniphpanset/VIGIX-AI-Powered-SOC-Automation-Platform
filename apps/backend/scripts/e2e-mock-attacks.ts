/**
 * VIGIX 10-case Mock Attack E2E runner (Task 10) — `npm run e2e:mock-attacks` (from apps/backend).
 *
 * Drives every case in resources/mock-attacks through the REAL use cases against the REAL PostgreSQL and the
 * running AI orchestrator, and asserts database state at each step:
 *
 *   WazuhAdapter -> IngestAlertFromSiem (HIGH / CRITICAL: incident opened automatically; MEDIUM: SOC creates it, no claim)
 *   -> AI analysis -> GenerateRecommendation (LLM) -> SOC Send to IR -> Response Ticket (PENDING_IR_DECISION)
 *   -> IR APPROVE / REJECT with a note (DecideApproval) -> Start/Complete (IR)
 *   -> RunRehuntVerification (MockRehuntAdapter, fixture round = investigation cycle) -> CreateVerification
 *   -> RESOLVED / new cycle (evidence -> IOC -> Recommendation #n) / escalation after 3 rounds.
 *
 * Task 10.3 (Response Process Recommendation v2) adds: action-level steps only (no Core Flow repetition),
 * instructions + verificationCriteria persisted, playbook = the one selected for the incident type, runbook =
 * the action's own runbook, responsible role/approval from Policy, ResponsePlan.recommendationStepId and
 * StepExecution traceability (Incident -> Recommendation -> RecommendationStep -> Action -> ResponsePlan -> StepExecution).
 *
 * Only notifications are replaced (no-op) so nothing leaves the machine. Human steps use explicit actors
 * ("phase34-e2e-soc", "ir-e2e"). Two operational roles only: SOC and IR_TEAM. Requirements: Postgres (DATABASE_URL), AI orchestrator (AI_ORCHESTRATOR_URL) with LLM.
 *
 * Result per check: PASS | FAIL | GAP. GAP = behaviour that deviates from the fixture because of a documented,
 * not-yet-built product capability (none open today; ATK-04's alert correlation gap is closed). A GAP is never a PASS.
 * Related alerts are correlated into the case's incident at ingestion (domain/alert/alertCorrelation.ts); a primary
 * alert must open its OWN incident, so an open incident left behind by an aborted run (same tenant, same fixture
 * timestamps) shows up as a FAIL here — resolve or dismiss it first.
 * Exit code 1 if any check FAILs.
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";

import { PrismaAlertRepository } from "../src/infrastructure/database/postgres/repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaInvestigationRepository } from "../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";
import { PrismaPolicyRepository } from "../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { PrismaApprovalRepository } from "../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaResponsePlanRepository } from "../src/infrastructure/database/postgres/repositories/ResponsePlanRepository.prisma";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaActionRepository } from "../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { FakeRecommendationAgent } from "../src/infrastructure/ai/FakeRecommendationAgent";
import { PrismaVerificationRepository } from "../src/infrastructure/database/postgres/repositories/VerificationRepository.prisma";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";
import { MockRehuntAdapter, MockRehuntMode, DEFAULT_MOCK_ATTACKS_DIR } from "../src/infrastructure/external-services/siem/MockRehuntAdapter";
import { LangGraphOrchestratorAdapter } from "../src/infrastructure/ai/LangGraphOrchestratorAdapter";
import "dotenv/config";
import { randomUUID } from "node:crypto";
import { alertWorkflow } from "../src/infrastructure/database/postgres/AlertWorkflow";
import { RunIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { GetIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { PrismaAiAnalysisRunGuard } from "../src/infrastructure/database/postgres/repositories/AiAnalysisRunGuard.prisma";
import { ValidateIncidentSeverityUseCase } from "../src/application/triage/SocTriage.usecases";
import { PrismaIncidentSeverityWriter } from "../src/infrastructure/database/postgres/repositories/IncidentSeverityWriter.prisma";
import { LlmRecommendationAgent } from "../src/infrastructure/ai/LlmRecommendationAgent";
import { RecommendationPromptBuilder } from "../src/infrastructure/ai/RecommendationPromptBuilder";
import { RecommendationValidator } from "../src/infrastructure/recommendation-validation/RecommendationValidator";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { ResourceAssetCriticalityProvider } from "../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { IngestAlertFromSiemUseCase } from "../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { PrismaIncidentCorrelationReader } from "../src/infrastructure/database/postgres/repositories/IncidentCorrelationReader.prisma";
import { CreateIncidentUseCase } from "../src/application/incident/use-cases/CreateIncident.usecase";
import { PolicyIncidentIntake } from "../src/infrastructure/policy-engine/PolicyIncidentIntake";
import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { IRecommendationAgentPort } from "../src/application/recommendation/ports/IRecommendationAgentPort";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { DecideApprovalUseCase } from "../src/application/approval/use-cases/DecideApproval.usecase";
import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { StartResponseUseCase } from "../src/application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../src/application/response/use-cases/CompleteResponse.usecase";
import { FailResponseUseCase } from "../src/application/response/use-cases/FailResponse.usecase";
import { CreateVerificationUseCase, MAX_INVESTIGATION_ROUNDS } from "../src/application/verification/use-cases/CreateVerification.usecase";
import { RunRehuntVerificationUseCase } from "../src/application/verification/use-cases/RunRehuntVerification.usecase";
import { CreateIocUseCase } from "../src/application/investigation/use-cases/CreateIoc.usecase";
import { SiemInboundWebhookController } from "../src/presentation/http/webhooks/siem-inbound.webhook";
import { INotificationDispatcherPort } from "../src/application/notification/ports/INotificationDispatcherPort";

const TENANT = "00000000-0000-0000-0000-000000000001";
const IR = "ir-e2e";
const AI_URL = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";

// ---------------------------------------------------------------- wiring (real, except notifications)
const prisma = new PrismaClient();
const noNotify = { emit: async () => undefined } as unknown as INotificationDispatcherPort;
const alerts = new PrismaAlertRepository(prisma);
const incidents = new PrismaIncidentRepository(prisma);
const investigations = new PrismaInvestigationRepository(prisma);
const ctxRepo = new PrismaRecommendationContextRepository(prisma);
const actions = new PrismaActionRepository(prisma);
const runbooks = new PrismaRunbookRepository(prisma);
const playbookRepo = new PrismaPlaybookRepository(prisma);
const recs = new PrismaRecommendationRepository(prisma);
const approvals = new PrismaApprovalRepository(prisma);
const plans = new PrismaResponsePlanRepository(prisma);
const verifications = new PrismaVerificationRepository(prisma);
const audit = new AuditLogger(prisma);
const policy = new PolicyEvaluator(new PrismaPolicyRepository(prisma));
const wazuh = new WazuhAdapter();

// HIGH / CRITICAL open their incident at ingestion (Policy INTAKE); the AI analysis is run explicitly below.
const ingest = new IngestAlertFromSiemUseCase(alerts, incidents, { enqueue: async () => { throw new Error("Ingestion must not queue AI"); }, latestForIncident: async () => null }, audit, new PolicyIncidentIntake(policy), new CreateIncidentUseCase(incidents, alerts, audit), { reader: new PrismaIncidentCorrelationReader(prisma), investigations });
const webhook = new SiemInboundWebhookController(ingest, { wazuh });
const approvalService = new ApprovalService(ctxRepo, actions, policy, approvals, audit, noNotify, "http://localhost", new ResourceAssetCriticalityProvider());
const makeGenerate = (agent: IRecommendationAgentPort) =>
  new GenerateRecommendationUseCase(
    new RecommendationContextBuilder(ctxRepo, actions, runbooks, playbookRepo, approvalService),
    agent,
    "LlmRecommendationAgent/v2.0.0",
    new RecommendationValidator(actions, runbooks),
    recs,
    audit
  );
const generate = makeGenerate(new LlmRecommendationAgent(AI_URL));
const createPlan = new CreateResponsePlanUseCase(recs, actions, runbooks, approvalService, plans, audit, noNotify, "http://localhost");
const decide = new DecideApprovalUseCase(approvals, audit, recs, ctxRepo, plans, noNotify, "http://localhost");
const start = new StartResponseUseCase(plans, approvals, audit);
const complete = new CompleteResponseUseCase(plans, audit, incidents, actions, ctxRepo, noNotify, "http://localhost");
const fail = new FailResponseUseCase(plans, audit);
const createVerification = new CreateVerificationUseCase(verifications, plans, incidents, policy, audit, ctxRepo, noNotify, "http://localhost", generate);
const rehunt = (mode: MockRehuntMode = "FIXTURE") =>
  new RunRehuntVerificationUseCase(new MockRehuntAdapter(mode), createVerification, incidents, alerts, plans, verifications, ctxRepo, investigations, audit);
const createIoc = new CreateIocUseCase(investigations, audit);

// ---------------------------------------------------------------- reporting
type Status = "PASS" | "FAIL" | "GAP";
interface Check { scope: string; name: string; status: Status; detail: string }
const checks: Check[] = [];
const summary: Array<{ atk: string; flow: string; approval: string; verification: string; finalState: string; status: Status }> = [];
/** The actual (LLM) Recommendation #1 of each case, as persisted — printed and written to the report. */
const recommendationExamples: Array<Record<string, unknown>> = [];

/** Incident-level playbook expected per fixture attack type (Task 10.3). */
const EXPECTED_PLAYBOOK: Record<string, string> = {
  SSH_BRUTE_FORCE: "PB-SSH-BRUTEFORCE",
  MALWARE: "PB-MALWARE",
  SQL_INJECTION: "PB-SQL-INJECTION",
  ACCOUNT_COMPROMISE: "PB-ACCOUNT-COMPROMISE",
  POWERSHELL: "PB-POWERSHELL",
};
function check(scope: string, name: string, ok: boolean, detail: unknown = "", gap = false): boolean {
  const status: Status = ok ? "PASS" : gap ? "GAP" : "FAIL";
  checks.push({ scope, name, status, detail: typeof detail === "string" ? detail : JSON.stringify(detail) });
  console.log(`  [${status}] ${scope} :: ${name}${detail !== "" ? ` — ${typeof detail === "string" ? detail : JSON.stringify(detail)}` : ""}`);
  return ok;
}

// ---------------------------------------------------------------- fixtures
type Fixture = Record<string, any>;
const fixtures: Fixture[] = fs
  .readdirSync(DEFAULT_MOCK_ATTACKS_DIR, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .flatMap((d) => fs.readdirSync(path.join(DEFAULT_MOCK_ATTACKS_DIR, d.name)).filter((f) => /^case-.*\.json$/.test(f)).map((f) => path.join(DEFAULT_MOCK_ATTACKS_DIR, d.name, f)))
  .map((f) => JSON.parse(fs.readFileSync(f, "utf-8")))
  .sort((a, b) => a.id.localeCompare(b.id));

// ---------------------------------------------------------------- DB probes
const invRows = (incidentId: string) => prisma.investigation.findMany({ where: { incidentId }, orderBy: { investigationNumber: "asc" } });
const recRows = (incidentId: string) => prisma.recommendation.findMany({ where: { incidentId }, orderBy: { recommendationNumber: "asc" }, include: { steps: true } });
const planRows = (incidentId: string) => prisma.responsePlan.findMany({ where: { incidentId }, orderBy: { createdAt: "asc" } });
const auditActions = async (entityIds: string[], action: string) => prisma.auditLog.count({ where: { entityId: { in: entityIds }, action } });

async function ingestAlert(alert: Fixture) {
  const r = await ingest.execute({ ...wazuh.normalize({ ...alert, id: "phase34-e2e-" + randomUUID() }), tenantId: TENANT });
  const sev = r.value.alert.severity.toLowerCase();
  const actor = "phase34-e2e-soc";
  let incidentId = r.value.incidentId;
  // A correlated (related) alert joined an incident that is already analysed and triaged: nothing more to do here.
  if (r.value.correlation) return { ...r.value, pipelineDispatched: true, investigationSynced: true };
  if (sev === "high" || sev === "critical") {
    check("INTAKE", `${sev.toUpperCase()} alert opened its incident automatically (no claim, no AI queued by ingestion)`, !!incidentId && !r.value.triageRequired, incidentId ?? "none");
  } else if (sev === "medium") {
    check("INTAKE", "MEDIUM alert waits for SOC review (no automatic incident)", r.value.triageRequired && !incidentId);
    // SOC review (no claim): create the incident from the alert.
    const escalated = await alertWorkflow(prisma).triage.execute({ tenantId: TENANT, alertId: r.value.alert.id, actor, decision: "CREATE_INCIDENT", reason: "Explicit synthetic E2E investigation" });
    if (escalated.isFailure || !escalated.value.incidentId) throw new Error("E2E SOC review failed");
    incidentId = escalated.value.incidentId;
  } else {
    throw new Error("LOW alerts are outside the SOC workflow; this fixture cannot be run through it");
  }
  if (!incidentId) throw new Error("No incident for the E2E alert");
  const analysis = await new RunIncidentAiAnalysisUseCase(incidents, new PrismaAiAnalysisRunGuard(prisma), new LangGraphOrchestratorAdapter(AI_URL), investigations, new GetIncidentAiAnalysisUseCase(ctxRepo), audit).execute({ tenantId: TENANT, incidentId, actor });
  if (analysis.isFailure) throw new Error("Live AI analysis: " + analysis.error);
  const severity = r.value.alert.severity.toUpperCase() as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  const validation = await new ValidateIncidentSeverityUseCase(ctxRepo, new PrismaIncidentSeverityWriter(prisma), audit).execute({ tenantId: TENANT, incidentId, actor, actorRole: "SOC", severity, note: null });
  if (validation.isFailure) throw new Error(validation.error);
  check("TRIAGE", "SOC confirmed the Wazuh severity (no AI severity exists)", validation.isSuccess && validation.value.wazuhSeverity === severity && !validation.value.overridesWazuh);
  return { ...r.value, incidentId, pipelineDispatched: true, investigationSynced: true };
}

/** Recommendation for the current cycle with at least one action step. A human may re-request once (LLM output varies). */
async function ensureActionableRecommendation(scope: string, incidentId: string) {
  const currentCycle = (await prisma.incident.findUnique({ where: { id: incidentId } }))?.investigationNumber ?? 1;
  let latest = (await recRows(incidentId)).filter((r) => r.status === "VALIDATED").pop();
  const usable = () => !!latest && latest.investigationNumber === currentCycle && latest.steps.some((s) => s.actionId);
  // The automatic generation for a new cycle may have been rejected by the validator; a human may re-request (max 2).
  for (let attempt = 0; attempt < 2 && !usable(); attempt++) {
    const g = await generate.execute({ incidentId, tenantId: TENANT });
    if (g.isFailure) check(scope, `recommendation generation attempt ${attempt + 1}`, false, g.error);
    latest = (await recRows(incidentId)).filter((r) => r.status === "VALIDATED").pop();
  }
  return latest;
}

async function humanPlan(scope: string, recommendationId: string, stepId: string, decision: "approve" | "reject" = "approve") {
  const p = await createPlan.execute({ recommendationId, stepId, tenantId: TENANT });
  if (p.isFailure) {
    check(scope, "response plan created", false, p.error);
    return null;
  }
  let plan = p.value;
  let approval: { role: string; status: string } | null = null;
  check(scope, "ticket created first, awaiting the IR decision (PENDING_IR_DECISION, IR_TEAM)", plan.status === "PENDING_IR_DECISION" && plan.assignedRole === "IR_TEAM", plan.status);
  while (plan.status === "PENDING_IR_DECISION") {
    const a = (await approvals.findByResponse(plan.id, TENANT)).find(a => a.status === "pending");
    if (!a) throw new Error("Ticket awaiting the IR decision has no open approval");
    const d = await decide.execute({
      approvalId: a.id,
      tenantId: TENANT,
      status: decision === "approve" ? "approved" : "rejected",
      decidedBy: IR,
      decidedByRole: "IR_TEAM",
      comment: decision === "approve" ? "E2E: IR approved after reviewing the evidence" : "E2E: IR rejected — disabling this account is not acceptable",
    });
    if (d.isFailure) throw new Error(d.error);
    approval = { role: approval ? `${approval.role} → ${a.approvalRole}` : a.approvalRole, status: d.value.status };
    plan = (await plans.findById(plan.id, TENANT))!;
  }
  return { plan, approval };
}

async function executeByHuman(planId: string) {
  const s = await start.execute({ responseId: planId, tenantId: TENANT, startedBy: IR });
  if (s.isFailure) return s.error;
  const c = await complete.execute({ responseId: planId, tenantId: TENANT, completedBy: IR, executionResult: { simulated: true, by: IR } });
  return c.isFailure ? c.error : "COMPLETED";
}

/** Response Process Recommendation v2 assertions on the persisted recommendation (Task 10.3). */
async function checkRecommendationV2(scope: string, fx: Fixture, recommendationId: string, printExample: boolean) {
  const rec = await prisma.recommendation.findUnique({
    where: { id: recommendationId },
    include: { steps: { include: { action: true, sourceRunbook: true }, orderBy: { stepOrder: "asc" } }, snapshot: true },
  });
  if (!rec) return;
  const wantPlaybook = EXPECTED_PLAYBOOK[fx.attackType];
  check(scope, `playbook = ${wantPlaybook} (selected for ${fx.attackType})`, rec.snapshot?.playbookCode === wantPlaybook, rec.snapshot?.playbookCode ?? "no snapshot");
  check(scope, "every step is ONE containment Action (no Core Flow step / investigation / re-hunt action)", rec.steps.length > 0 && rec.steps.every((s) => s.action?.category === "CONTAINMENT" && s.phase === "ACTION"), rec.steps.map((s) => s.action?.code ?? "none"));
  check(scope, "every step has ordered instructions + verificationCriteria", rec.steps.every((s) => Array.isArray(s.instructions) && (s.instructions as any[]).length > 0 && (s.instructions as any[]).every((i, n) => i.order === n + 1 && i.instruction) && !!s.verificationCriteria), rec.steps.map((s) => (Array.isArray(s.instructions) ? (s.instructions as any[]).length : 0)));
  check(scope, "every step's runbook = its Action's runbook", rec.steps.every((s) => !!s.sourceRunbookId && s.sourceRunbookId === s.action?.runbookId), rec.steps.map((s) => `${s.action?.code}->${s.sourceRunbook?.code}`));
  const ev = await ctxRepo.getEvidence(rec.incidentId, rec.investigationNumber);
  const manual = (await ctxRepo.getIocs(rec.incidentId, rec.investigationNumber)).filter((i) => i.manual).map((i) => i.iocValue);
  const targetable = new Set([...ev.flatMap((e) => e.iocValues), ...manual, ...ev.map((e) => e.host).filter((h): h is string => !!h)]);
  check(scope, "every step target is an evidence-linked / analyst-added IOC or affected host", rec.steps.every((s) => !!s.target && targetable.has(s.target)), rec.steps.map((s) => s.target));
  const phases = [/\bvalidat/i, /\bcheck/i, /\bblock/i, /\bmonitor/i, /\bre-?hunt/i, /\bverif/i].filter((p) => p.test(rec.summary)).length;
  check(scope, "summary is action-level (does not restate the Core Flow)", phases < 4, rec.summary);
  if (printExample) {
    const example = {
      atk: fx.id,
      incidentId: rec.incidentId,
      recommendationNumber: rec.recommendationNumber,
      summary: rec.summary,
      playbook: rec.snapshot?.playbookCode,
      steps: rec.steps.map((s) => ({
        stepId: s.id,
        action: s.action?.code,
        target: s.target,
        objective: s.objective,
        reason: s.reason,
        runbook: s.sourceRunbook?.code,
        requiresApproval: s.requiresApproval,
        policy: (rec.snapshot?.policyResult as any)?.[s.action?.code ?? ""] ?? null,
        instructions: s.instructions,
        verificationCriteria: s.verificationCriteria,
        evidence: s.evidence,
      })),
    };
    recommendationExamples.push(example);
    const lines = JSON.stringify(example, null, 2).split("\n").map((l) => `  | ${l}`);
    console.log(`  --- actual AI recommendation (${fx.id} #${rec.recommendationNumber}) ---\n${lines.join("\n")}`);
  }
}

// ---------------------------------------------------------------- one case
async function runCase(fx: Fixture, variant: "production" | "analyst-correlated" = "production") {
  const scope = variant === "production" ? fx.id : `${fx.id} (${variant})`;
  console.log(`\n=== ${scope}: ${fx.title}`);
  const exp = fx.expected;
  const row = { atk: scope, flow: "", approval: "not required", verification: "", finalState: "", status: "PASS" as Status };
  const before = checks.length;

  // 1. Alert -> Incident -> Investigation -> Evidence/IOC
  const ing = await ingestAlert(fx.alert);
  check(scope, "ingested + AI dispatched + investigation synced", !!ing.incidentId && ing.pipelineDispatched && ing.investigationSynced, { incidentId: ing.incidentId, pipelineDispatched: ing.pipelineDispatched, investigationSynced: ing.investigationSynced });
  const incidentId = ing.incidentId!;
  const incidentRow = await prisma.incident.findUnique({ where: { id: incidentId } });
  check(scope, "incident references the alert", incidentRow?.alertId === ing.alert.id);
  check(scope, "incident_alerts link", (await prisma.incidentAlert.count({ where: { incidentId, alertId: ing.alert.id } })) === 1);
  const inv1 = (await invRows(incidentId))[0];
  check(scope, "Investigation #1 ACTIVE", inv1?.investigationNumber === 1 && inv1.status === "ACTIVE");
  const ev1 = await prisma.evidence.findMany({ where: { investigationId: inv1.id }, include: { iocLinks: { include: { ioc: true } } } });
  check(scope, "WAZUH_ALERT evidence (SYSTEM) from the alert", ev1.some((e) => e.type === "WAZUH_ALERT" && e.origin === "SYSTEM" && e.alertId === ing.alert.id));
  const linked = new Set(ev1.flatMap((e) => e.iocLinks.map((l) => l.ioc.iocValue.toLowerCase())));
  const expectedPrimary = exp.iocs.filter((i: any) => JSON.stringify(fx.alert).toLowerCase().includes(i.value.toLowerCase().replace(/\\/g, "\\\\")));
  const missingIocs = expectedPrimary.filter((i: any) => ![...linked].some((v) => v.includes(i.value.toLowerCase()) || i.value.toLowerCase().includes(v)));
  check(scope, "expected IOCs of the alert linked to evidence", missingIocs.length === 0, missingIocs.length ? { missing: missingIocs } : `${linked.size} linked`);
  check(scope, "no cycle-less IOC", (await prisma.threatIntelIoc.count({ where: { incidentId, investigationId: null } })) === 0);

  // 2. AI analysis persisted for THIS incident
  const aiRows = await prisma.agentResult.findMany({ where: { agentExecution: { incidentId } }, select: { agentName: true, output: true } });
  const report = aiRows.find((r) => r.agentName === "recommendation_agent")?.output as any;
  check(scope, "AI analysis stored (llm_analyst, ml_risk, recommendation_agent)", ["llm_analyst", "ml_risk", "recommendation_agent"].every((n) => aiRows.some((r) => r.agentName === n)));
  check(scope, "AI report references this incident", report?.incidentId === incidentId, report?.incidentId);

  check(scope, "primary alert opened its own incident (not correlated into an earlier one)", !ing.correlation, ing.correlation ?? "own incident");

  // Related alerts are correlated into this incident at ingestion: their evidence + IOCs join Investigation #1.
  for (const ra of fx.relatedAlerts ?? []) {
    const r = await ingestAlert(ra);
    check(scope, `related alert ${ra.id} correlated into the case's incident`, r.incidentId === incidentId && !!r.correlation, r.correlation ?? r.incidentId ?? "none");
    check(scope, `related alert ${ra.id} is WAZUH_ALERT evidence of Investigation #1`, (await prisma.evidence.count({ where: { investigationId: inv1.id, alertId: r.alert.id, type: "WAZUH_ALERT" } })) === 1);
  }

  // ATK-04 correlated variant: an ANALYST correlates the related alert by adding its C2 IOCs to Investigation #1
  // through the real manual-IOC path (CreateIocUseCase, origin MANUAL). No database shortcut.
  if (variant === "analyst-correlated") {
    for (const ra of fx.relatedAlerts ?? []) {
      const d = ra.data ?? {};
      for (const [iocType, iocValue] of [["IPV4", d.dstip], ["DOMAIN", d.dns?.question?.name], ["URL", d.url]] as const) {
        if (!iocValue) continue;
        const r = await createIoc.execute({ tenantId: TENANT, investigationId: inv1.id, createdBy: "analyst-e2e", body: { iocType, iocValue, source: `correlated alert ${ra.id}` } as never });
        check(scope, `analyst adds correlated IOC ${iocType}=${iocValue}`, r.isSuccess || (r.error as any)?.code === "DUPLICATE_IOC", r.isFailure ? r.error : "created");
      }
    }
  }

  // 3..n. Recommendation -> Policy -> Approval -> Plan -> Human execution -> Re-hunt -> Verification (per round)
  const humanPlanIds: string[] = [];
  let finalVerdict = "";
  const roundResults: string[] = [];
  for (let round = 1; round <= MAX_INVESTIGATION_ROUNDS; round++) {
    const rs = `${scope} r${round}`;
    const rec = await ensureActionableRecommendation(rs, incidentId);
    const invs = await invRows(incidentId);
    const cycle = invs.find((i) => i.investigationNumber === round);
    if (!check(rs, `VALIDATED recommendation for cycle ${round} with an action step`, !!rec && rec.investigationNumber === round && rec.investigationId === cycle?.id && rec.steps.some((s) => s.actionId), rec ? { n: rec.recommendationNumber, cycle: rec.investigationNumber, actionSteps: rec.steps.filter((s) => s.actionId).length } : "none")) {
      row.flow = `stopped r${round}: no actionable recommendation`;
      break;
    }
    const step = rec!.steps.find((s) => s.actionId)!;
    await checkRecommendationV2(rs, fx, rec!.id, round === 1 && variant === "production");

    // ATK-08: the manager first REJECTS a plan for this step — it must never run or verify.
    if (fx.id === "ATK-08" && round === 1) {
      const rj = await humanPlan(rs, rec!.id, step.id, "reject");
      if (rj) {
        check(rs, "IR rejected the ticket (with a note)", !!rj.approval && rj.plan.status === "REJECTED", rj.approval ?? "none");
        const st = await start.execute({ responseId: rj.plan.id, tenantId: TENANT, startedBy: IR });
        const v = await rehunt().execute({ incidentId, responseId: rj.plan.id, tenantId: TENANT, verifiedBy: IR });
        const dbPlan = await prisma.responsePlan.findUnique({ where: { id: rj.plan.id } });
        check(rs, "REJECTED plan: start refused, not executed, not verifiable", st.isFailure && v.isFailure && dbPlan?.status === "REJECTED" && dbPlan.executedAt === null && (await prisma.verification.count({ where: { responseId: rj.plan.id } })) === 0, { start: st.isFailure ? st.error : "started!", verify: v.isFailure ? v.error : "verified!", status: dbPlan?.status });
        const dbApproval = await prisma.approval.findFirst({ where: { responseId: rj.plan.id } });
        check(rs, "rejection reason + decider stored, APPROVAL_DECIDED audited", !!dbApproval?.comment && !!dbApproval.decidedBy && (await auditActions([dbApproval.id], "APPROVAL_DECIDED")) === 1);
      }
    }

    let hp = await humanPlan(rs, rec!.id, step.id, "approve");
    if (!hp) break;
    humanPlanIds.push(hp.plan.id);
    const planDb = await prisma.responsePlan.findUnique({ where: { id: hp.plan.id } });
    check(rs, "ResponsePlan.recommendationStepId = the step it was created from", planDb?.recommendationStepId === step.id && hp.plan.recommendationStepId === step.id, planDb?.recommendationStepId ?? "null");
    const snap = rec!.snapshotId ? await prisma.playbookSnapshot.findUnique({ where: { id: rec!.snapshotId } }) : null;
    const stepAction = await prisma.action.findUnique({ where: { id: step.actionId! } });
    const policyForStep = (snap?.policyResult as any)?.[stepAction?.code ?? ""];
    const executionPolicy = await approvalService.evaluate({ tenantId: TENANT, incidentId, actionId: hp.plan.actionId! });
    check(rs, "plan assignedRole follows Policy executorRole (case ownership is separate)", !!policyForStep && hp.plan.assignedRole === (executionPolicy.policy.executorRole ?? "IR_TEAM"), { plan: hp.plan.assignedRole, executorRole: executionPolicy.policy.executorRole, caseOwner: policyForStep?.responsibleRole });
    check(rs, "step requiresApproval = Policy approvalRequired", !!policyForStep && step.requiresApproval === policyForStep.approvalRequired, { step: step.requiresApproval, policy: policyForStep?.approvalRequired });
    if (hp.approval) row.approval = `${hp.approval.role} ${hp.approval.status}`;
    if (round === 1) {
      // Two-role workflow: every ticket waits for the IR decision, whatever the fixture expected from Policy.
      check(rs, `IR decision recorded (fixture Policy expectation: ${exp.approval})`, hp.approval?.role === "IR_TEAM" && hp.approval.status === "approved", hp.approval ?? "none");
      if (fx.id === "ATK-08") row.approval = "IR rejected (plan A) + approved (plan B)";
    }
    check(rs, "plan READY_FOR_EXECUTION after the IR APPROVE", hp.plan.status === "READY_FOR_EXECUTION", hp.plan.status);

    // Negative: a FAILED response can never be verified (ATK-07).
    if (fx.id === "ATK-07" && round === 1) {
      const fp = hp;
      if (fp) {
        await start.execute({ responseId: fp.plan.id, tenantId: TENANT, startedBy: IR });
        await fail.execute({ responseId: fp.plan.id, tenantId: TENANT, failedBy: IR, executionResult: { error: "E2E: tool failure" } });
        const v = await rehunt().execute({ incidentId, responseId: fp.plan.id, tenantId: TENANT, verifiedBy: IR });
        check(rs, "FAILED response -> not verifiable (FAILED != RESOLVED)", v.isFailure && v.error === "RESPONSE_NOT_COMPLETED" && (await prisma.verification.count({ where: { responseId: fp.plan.id } })) === 0, v.isFailure ? v.error : "verified!");
        hp = await humanPlan(rs, rec!.id, step.id, "approve");
        if (!hp) break;
        humanPlanIds.push(hp.plan.id);
      }
    }

    const ex = await executeByHuman(hp.plan.id);
    const dbPlan = await prisma.responsePlan.findUnique({ where: { id: hp.plan.id } });
    check(rs, "human start + complete (executed_at, completed_at, COMPLETED)", ex === "COMPLETED" && !!dbPlan?.executedAt && !!dbPlan.completedAt && dbPlan.status === "COMPLETED", ex);
    const se = await prisma.stepExecution.findMany({ where: { planId: hp.plan.id } });
    check(rs, "StepExecution COMPLETED by the human, traced to the RecommendationStep", se.length === 1 && se[0].status === "COMPLETED" && se[0].recommendationStepId === step.id && se[0].executedBy === IR && !!se[0].startedAt && !!se[0].completedAt, se.map((x) => ({ status: x.status, step: x.recommendationStepId, by: x.executedBy })));

    // Negative: re-hunt ERROR / TIMEOUT / INDEXER_UNAVAILABLE never yield a verdict (ATK-09).
    if (fx.id === "ATK-09" && round === 1) {
      for (const mode of ["ERROR", "TIMEOUT", "INDEXER_UNAVAILABLE"] as const) {
        const v = await rehunt(mode).execute({ incidentId, responseId: hp.plan.id, tenantId: TENANT, verifiedBy: IR });
        const inc = await prisma.incident.findUnique({ where: { id: incidentId } });
        check(rs, `re-hunt ${mode} -> error, no verification, incident not resolved`, v.isFailure && (await prisma.verification.count({ where: { responseId: hp.plan.id } })) === 0 && inc?.status !== "resolved", v.isFailure ? v.error : "verdict!");
      }
      check(rs, "REHUNT_FAILED audited 3x", (await auditActions([hp.plan.id], "REHUNT_FAILED")) === 3);
    }

    const recsBefore = (await recRows(incidentId)).length;
    const plansBefore = (await planRows(incidentId)).length;
    const v = await rehunt().execute({ incidentId, responseId: hp.plan.id, tenantId: TENANT, verifiedBy: IR });
    if (!check(rs, "re-hunt + verification", v.isSuccess, v.isFailure ? v.error : "")) break;
    const verification = await prisma.verification.findFirst({ where: { responseId: hp.plan.id } });
    const fr = fx.rehunt.rounds.find((r: any) => r.round === round);
    const deviation = !fr || fr.expected.verification !== verification?.result || fr.expected.matchingEvents !== verification?.matchingEvents || fr.expected.spreadDetected !== verification?.spreadDetected;
    check(rs, `verification vs fixture round ${round}`, !deviation, { db: { result: verification?.result, matching: verification?.matchingEvents, spread: verification?.spreadDetected }, fixture: fr?.expected });
    check(rs, "verification provenance MOCK_REHUNT + round index", (verification?.afterState as any)?.evidenceSource === "MOCK_REHUNT" && (verification?.wazuhIndex ?? "").endsWith(`#round-${round}`));
    roundResults.push(`${verification?.result}${verification?.spreadDetected ? "+SPREAD" : ""}`);
    finalVerdict = verification!.result;

    const invsAfter = await invRows(incidentId);
    const recsAfter = await recRows(incidentId);
    const plansAfter = await planRows(incidentId);
    check(rs, "no response plan auto-created by verification", plansAfter.length === plansBefore);
    check(rs, "no response auto-started (RESPONSE_STARTED only for human plans)", (await auditActions(plansAfter.map((p) => p.id), "RESPONSE_STARTED")) === plansAfter.filter((p) => p.executedAt).length);

    if (verification!.result === "RESOLVED") {
      const inc = await prisma.incident.findUnique({ where: { id: incidentId } });
      check(rs, "RESOLVED only from NO_MATCH + contained", verification!.matchingEvents === 0 && verification!.threatContained && !verification!.spreadDetected && !verification!.iocRecurrence);
      check(rs, "incident resolved, current cycle COMPLETED, no new cycle/recommendation", inc?.status === "resolved" && invsAfter.length === round && invsAfter[round - 1].status === "COMPLETED" && recsAfter.length === recsBefore);
      break;
    }

    // NOT_RESOLVED
    const inc = await prisma.incident.findUnique({ where: { id: incidentId } });
    check(rs, "NOT_RESOLVED never closes the incident", inc?.status !== "resolved");
    if (round === MAX_INVESTIGATION_ROUNDS) {
      check(rs, "max rounds: incident status ESCALATED (not closed)", (await prisma.incident.findUnique({ where: { id: incidentId } }))?.status === "escalated");
      check(rs, "max rounds: no 4th cycle, no new recommendation", invsAfter.length === MAX_INVESTIGATION_ROUNDS && recsAfter.length === recsBefore, { cycles: invsAfter.length, recs: recsAfter.length });
      check(rs, "INVESTIGATION_ESCALATED (MAX_INVESTIGATION_ROUNDS_REACHED) audited", (await prisma.auditLog.count({ where: { entityId: incidentId, action: "INVESTIGATION_ESCALATED", metadata: { path: ["reasons"], array_contains: ["MAX_INVESTIGATION_ROUNDS_REACHED"] } } })) === 1);
      finalVerdict = "ESCALATED";
      break;
    }
    const next = invsAfter.find((i) => i.investigationNumber === round + 1);
    check(rs, `Investigation #${round + 1} ACTIVE, #${round} COMPLETED`, next?.status === "ACTIVE" && invsAfter[round - 1].status === "COMPLETED");
    const nextEvidence = next ? await prisma.evidence.findMany({ where: { investigationId: next.id }, include: { iocLinks: { include: { ioc: true } } } }) : [];
    const nextRec = recsAfter.find((r) => r.investigationNumber === round + 1);
    check(rs, "new-cycle evidence = re-hunt events (MOCK_REHUNT)", nextEvidence.length === verification!.matchingEvents && nextEvidence.every((e) => e.type === "WAZUH_EVENT" && e.source === "MOCK_REHUNT"), nextEvidence.length);
    const carried = nextEvidence.flatMap((e) => e.iocLinks.map((l) => l.ioc)).filter((i) => i.source === "REHUNT");
    check(rs, "IOCs carried into the new cycle when events contained them", !verification!.iocRecurrence || carried.length > 0, carried.map((i) => `${i.iocType}:${i.iocValue}`));
    if (check(rs, `Recommendation #${round + 1} generated for cycle ${round + 1}`, !!nextRec && nextRec.status === "VALIDATED" && nextRec.investigationId === next?.id, nextRec ? { n: nextRec.recommendationNumber, status: nextRec.status } : "none")) {
      check(rs, "new-cycle evidence recorded BEFORE Recommendation #n", nextEvidence.every((e) => e.createdAt <= nextRec!.createdAt));
      check(rs, "previous recommendation SUPERSEDED", recsAfter.filter((r) => r.recommendationNumber <= round).every((r) => r.status === "SUPERSEDED" || r.status === "INVALID"));
    }
    check(rs, "SPREAD escalation audited when spread", !verification!.spreadDetected || (await prisma.auditLog.count({ where: { entityId: incidentId, action: "INVESTIGATION_ESCALATED" } })) >= 1);
  }

  // Final state vs fixture
  const expectedFinal = exp.finalOutcome === "ESCALATED_TO_IR" ? "ESCALATED" : "RESOLVED";
  const inc = await prisma.incident.findUnique({ where: { id: incidentId } });
  const primary = roundResults[0]?.includes("SPREAD") ? "SPREAD" : roundResults[0];
  check(scope, `primary result = fixture ${exp.primaryResult}`, primary === exp.primaryResult, primary);
  check(scope, `final state = fixture ${expectedFinal}`, finalVerdict === expectedFinal, { db: finalVerdict, incident: inc?.status, cycles: (await invRows(incidentId)).length });

  const mine = checks.slice(before);
  row.status = mine.some((c) => c.status === "FAIL") ? "FAIL" : mine.some((c) => c.status === "GAP") ? "GAP" : "PASS";
  row.flow = row.flow || `cycles ${(await invRows(incidentId)).length}, plans ${humanPlanIds.length}`;
  row.verification = roundResults.join(" → ");
  row.finalState = `${finalVerdict} (incident ${inc?.status})`;
  summary.push(row);
  return incidentId;
}

// ---------------------------------------------------------------- negative E2E (outside the 10 flows)
async function negatives(atk01Incident: string) {
  console.log("\n=== NEGATIVE E2E");
  const scope = "NEG";
  // Invalid alert payload -> 422 at the webhook, nothing stored.
  const alertsBefore = await prisma.alert.count();
  const res: any = { code: 0, body: null, status(c: number) { this.code = c; return this; }, json(b: unknown) { this.body = b; } };
  const broken = { ...fixtures[0].alert, rule: { ...fixtures[0].alert.rule, description: undefined } };
  await webhook.handle({ params: { source: "wazuh" }, body: broken } as never, res as never);
  check(scope, "invalid alert payload -> 422, no alert stored", res.code === 422 && (await prisma.alert.count()) === alertsBefore, res.code);

  const recsBefore = await prisma.recommendation.count({ where: { incidentId: atk01Incident } });
  const failuresBefore = await auditActions([atk01Incident], "RECOMMENDATION_GENERATION_FAILED");
  const cases: Array<[string, IRecommendationAgentPort, string]> = [
    ["AI timeout (1 ms, live AI)", new LlmRecommendationAgent(AI_URL, new RecommendationPromptBuilder(), 1), "AI_UNAVAILABLE"],
    ["AI unreachable", new LlmRecommendationAgent("http://localhost:8999"), "AI_UNAVAILABLE"],
    ["AI malformed response", { generate: async () => "I recommend blocking it." }, "INVALID_AI_OUTPUT"],
    ["AI invalid recommendation (empty steps)", { generate: async () => ({ summary: "nothing", steps: [] }) }, "INVALID_AI_OUTPUT"],
    ["AI invalid recommendation (self-approval key)", { generate: async () => ({ summary: "s", steps: [], approved: true }) }, "INVALID_AI_OUTPUT"],
  ];
  for (const [name, agent, want] of cases) {
    const r = await makeGenerate(agent).execute({ incidentId: atk01Incident, tenantId: TENANT });
    check(scope, `${name} -> ${want}, no recommendation persisted`, r.isFailure && r.error === want && (await prisma.recommendation.count({ where: { incidentId: atk01Incident } })) === recsBefore, r.isFailure ? r.error : "persisted!");
  }
  // v2 validator on the live incident: a valid candidate (deterministic agent, real context) with ONE defect each.
  const fake = new FakeRecommendationAgent();
  const mutate = (fn: (c: any) => void): IRecommendationAgentPort => ({
    generate: async (ctx) => {
      const c: any = await fake.generate(ctx);
      fn(c);
      return c;
    },
  });
  const v2cases: Array<[string, IRecommendationAgentPort]> = [
    ["invented target", mutate((c) => (c.steps[0].target = "203.0.113.77"))],
    ["invented IOC in instructions", mutate((c) => c.steps[0].instructions.push({ order: c.steps[0].instructions.length + 1, instruction: "Also block 198.51.100.23." }))],
    ["invented action", mutate((c) => (c.steps[0].action = "ACT-REIMAGE-HOST"))],
    ["wrong responsible role", mutate((c) => (c.steps[0].responsibleRole = c.steps[0].responsibleRole === "IR_TEAM" ? "SOC" : "IR_TEAM"))],
    ["policy bypass", mutate((c) => (c.steps[0].instructions[0].instruction = "Apply the block now without waiting for approval."))],
    ["Core Flow repetition", mutate((c) => (c.summary = "Validate the alert, check the host, block the source, monitor, then re-hunt Wazuh."))],
    ["runbook not matching action", mutate((c) => (c.steps[0].runbook = "RB-ISOLATE-ENDPOINT"))],
    ["playbook not matching incident type", mutate((c) => (c.steps[0].playbook = "PB-MALWARE"))],
    ["empty instructions", mutate((c) => (c.steps[0].instructions = []))],
  ];
  for (const [name, agent] of v2cases) {
    const plansBefore = await prisma.responsePlan.count({ where: { incidentId: atk01Incident } });
    const r = await makeGenerate(agent).execute({ incidentId: atk01Incident, tenantId: TENANT });
    const failure = await prisma.auditLog.findFirst({ where: { entityId: atk01Incident, action: "RECOMMENDATION_GENERATION_FAILED" }, orderBy: { createdAt: "desc" } });
    const persisted = (await prisma.recommendation.count({ where: { incidentId: atk01Incident } })) !== recsBefore;
    const planned = (await prisma.responsePlan.count({ where: { incidentId: atk01Incident } })) !== plansBefore;
    check(
      scope,
      `v2 validator rejects: ${name} -> INVALID_AI_OUTPUT, nothing persisted, no plan, audited`,
      r.isFailure && r.error === "INVALID_AI_OUTPUT" && !persisted && !planned,
      r.isFailure ? ((failure?.metadata as any)?.violations ?? []).slice(0, 2).join(" | ") : "persisted!"
    );
  }
  check(scope, "each AI failure audited", (await auditActions([atk01Incident], "RECOMMENDATION_GENERATION_FAILED")) - failuresBefore === cases.length + v2cases.length);
  const resolvedStillResolved = await prisma.recommendation.findFirst({ where: { incidentId: atk01Incident }, orderBy: { recommendationNumber: "desc" } });
  check(scope, "AI failures never supersede the valid recommendation", resolvedStillResolved?.status === "VALIDATED");
}

// ---------------------------------------------------------------- integrity / invariants over this run's incidents
async function integrity(incidentIds: string[]) {
  console.log("\n=== POSTGRESQL INTEGRITY");
  const scope = "DB";
  const ids = incidentIds.map((i) => `'${i}'`).join(",");
  const q = async (sql: string) => Number(((await prisma.$queryRawUnsafe(sql)) as Array<{ n: bigint }>)[0].n);
  const invariants: Array<[string, string]> = [
    ["IOC ↔ evidence links stay inside one incident", `select count(*) n from evidence_iocs ei join evidence e on e.id=ei.evidence_id join investigations v on v.id=e.investigation_id join threat_intel_iocs t on t.id=ei.ioc_id where v.incident_id in (${ids}) and t.incident_id<>v.incident_id`],
    ["IOC cycle = evidence cycle for every link", `select count(*) n from evidence_iocs ei join evidence e on e.id=ei.evidence_id join threat_intel_iocs t on t.id=ei.ioc_id where t.incident_id in (${ids}) and t.investigation_id<>e.investigation_id`],
    ["no cycle-less IOC", `select count(*) n from threat_intel_iocs where incident_id in (${ids}) and investigation_id is null`],
    ["no duplicate WAZUH_ALERT evidence per alert+cycle", `select count(*) n from (select investigation_id, alert_id from evidence e join investigations v on v.id=e.investigation_id where v.incident_id in (${ids}) and e.type='WAZUH_ALERT' group by 1,2 having count(*)>1) x`],
    ["every recommendation linked to its cycle's investigation", `select count(*) n from recommendations r left join investigations v on v.id=r.investigation_id where r.incident_id in (${ids}) and (v.id is null or v.investigation_number<>r.investigation_number or v.incident_id<>r.incident_id)`],
    ["at most one live (VALIDATED) recommendation per incident", `select count(*) n from (select incident_id from recommendations where incident_id in (${ids}) and status='VALIDATED' group by 1 having count(*)>1) x`],
    ["plans belong to their recommendation's incident", `select count(*) n from response_plans p join recommendations r on r.id=p.recommendation_id where p.incident_id in (${ids}) and r.incident_id<>p.incident_id`],
    ["REJECTED ≠ EXECUTED", `select count(*) n from response_plans where incident_id in (${ids}) and (approval_status='REJECTED' or status='REJECTED') and executed_at is not null`],
    ["executed plans had approval when policy required it", `select count(*) n from response_plans p where p.incident_id in (${ids}) and p.executed_at is not null and p.approval_status in ('PENDING','REJECTED')`],
    ["verifications only for COMPLETED plans", `select count(*) n from verifications v join response_plans p on p.id=v.response_id where v.incident_id in (${ids}) and p.status<>'COMPLETED'`],
    ["RESOLVED only with 0 events, contained, no spread/recurrence", `select count(*) n from verifications where incident_id in (${ids}) and result='RESOLVED' and (coalesce(matching_events,0)>0 or not threat_contained or spread_detected or ioc_recurrence)`],
    ["resolved incidents have a RESOLVED verification", `select count(*) n from incidents i where i.id in (${ids}) and i.status='resolved' and not exists (select 1 from verifications v where v.incident_id=i.id and v.result='RESOLVED')`],
    ["no incident beyond ${MAX} cycles".replace("${MAX}", String(MAX_INVESTIGATION_ROUNDS)), `select count(*) n from incidents where id in (${ids}) and investigation_number>${MAX_INVESTIGATION_ROUNDS}`],
    ["one ACTIVE investigation max, and it is the current cycle", `select count(*) n from investigations v join incidents i on i.id=v.incident_id where i.id in (${ids}) and v.status='ACTIVE' and v.investigation_number<>i.investigation_number`],
    ["every plan references a step of its own recommendation with the same action (recommendationStepId)", `select count(*) n from response_plans p left join recommendation_steps s on s.id=p.recommendation_step_id where p.incident_id in (${ids}) and (s.id is null or s.recommendation_id<>p.recommendation_id or s.action_id is distinct from p.action_id)`],
    ["every step execution traces to its plan's recommendation step", `select count(*) n from step_executions se join response_plans p on p.id=se.plan_id where p.incident_id in (${ids}) and se.recommendation_step_id is distinct from p.recommendation_step_id`],
    ["every executed plan has a StepExecution", `select count(*) n from response_plans p where p.incident_id in (${ids}) and p.executed_at is not null and not exists (select 1 from step_executions se where se.plan_id=p.id)`],
    ["every recommendation step is an action-level step with instructions", `select count(*) n from recommendation_steps s join recommendations r on r.id=s.recommendation_id left join actions a on a.id=s.action_id where r.incident_id in (${ids}) and (a.id is null or a.category<>'CONTAINMENT' or s.instructions is null or jsonb_array_length(s.instructions)=0 or s.verification_criteria is null)`],
    ["every step runbook = its action's runbook", `select count(*) n from recommendation_steps s join recommendations r on r.id=s.recommendation_id join actions a on a.id=s.action_id where r.incident_id in (${ids}) and s.source_runbook_id is distinct from a.runbook_id`],
    ["every recommendation has its cycle's playbook snapshot", `select count(*) n from recommendations r left join playbook_snapshots ps on ps.id=r.snapshot_id where r.incident_id in (${ids}) and (ps.id is null or ps.investigation_number<>r.investigation_number)`],
    ["approvals point at their plan's recommendation",`select count(*) n from approvals a join response_plans p on p.id=a.response_id where p.incident_id in (${ids}) and a.recommendation_id<>p.recommendation_id`],
  ];
  for (const [name, sql] of invariants) {
    const n = await q(sql);
    check(scope, name, n === 0, `${n} violation(s)`);
  }
  // Re-running the sync is idempotent (no duplicates).
  const snapshot = async () => ({ inv: await prisma.investigation.count({ where: { incidentId: { in: incidentIds } } }), ev: await prisma.evidence.count({ where: { investigation: { incidentId: { in: incidentIds } } } }), ioc: await prisma.threatIntelIoc.count({ where: { incidentId: { in: incidentIds } } }), links: await prisma.evidenceIoc.count({ where: { evidence: { investigation: { incidentId: { in: incidentIds } } } } }), ia: await prisma.incidentAlert.count({ where: { incidentId: { in: incidentIds } } }) });
  const a = await snapshot();
  for (const id of incidentIds) await investigations.syncIncident(id, TENANT);
  const b = await snapshot();
  check(scope, "syncIncident re-run creates no duplicates", JSON.stringify(a) === JSON.stringify(b), { before: a, after: b });
}

// ---------------------------------------------------------------- main
(async () => {
  const startedAt = Date.now();
  const only = process.argv.slice(2);
  const incidentIds: string[] = [];
  let atk01: string | null = null;
  for (const fx of fixtures.filter((f) => only.length === 0 || only.includes(f.id))) {
    const id = await runCase(fx);
    incidentIds.push(id);
    if (fx.id === "ATK-01") atk01 = id;
    if (fx.id === "ATK-04") incidentIds.push(await runCase(fx, "analyst-correlated"));
  }
  if (atk01) await negatives(atk01);
  await integrity(incidentIds);

  console.log("\n=== SUMMARY");
  console.log("ATK | Flow | Approval | Verification | Final State | Result");
  for (const r of summary) console.log(`${r.atk} | ${r.flow} | ${r.approval} | ${r.verification} | ${r.finalState} | ${r.status}`);
  const totals = { PASS: 0, FAIL: 0, GAP: 0 } as Record<Status, number>;
  for (const c of checks) totals[c.status]++;
  console.log(`\nchecks: ${totals.PASS} PASS, ${totals.FAIL} FAIL, ${totals.GAP} GAP — ${((Date.now() - startedAt) / 1000).toFixed(0)} s`);
  const out = process.env.E2E_REPORT_PATH;
  if (out) fs.writeFileSync(out, JSON.stringify({ summary, checks, totals, incidentIds, recommendationExamples }, null, 2));
  await prisma.$disconnect();
  process.exit(totals.FAIL > 0 ? 1 : 0);
})().catch(async (err) => {
  console.error("E2E runner crashed:", err);
  await prisma.$disconnect();
  process.exit(2);
});
