/**
 * One-off: take the 4 MEDIUM TC alerts (brute force, phishing, SQLi, suspicious
 * process) all the way through the workflow, starting with the SOC triage step
 * that a MEDIUM alert needs (it does NOT auto-open an incident):
 *
 *   SOC triage (CREATE_INCIDENT) -> AI analysis (9 agents + MITRE mapping)
 *   -> GenerateRecommendation -> SOC plan -> IR approve -> execute -> re-hunt -> RESOLVED
 *
 *   npx ts-node --transpile-only scripts/walk-tc-medium.ts
 */
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { alertWorkflow } from "../src/infrastructure/database/postgres/AlertWorkflow";
import { PrismaAlertRepository } from "../src/infrastructure/database/postgres/repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaInvestigationRepository } from "../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaActionRepository } from "../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { PrismaPlaybookRepository } from "../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaRecommendationRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaApprovalRepository } from "../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaResponsePlanRepository } from "../src/infrastructure/database/postgres/repositories/ResponsePlanRepository.prisma";
import { PrismaVerificationRepository } from "../src/infrastructure/database/postgres/repositories/VerificationRepository.prisma";
import { PrismaPolicyRepository } from "../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { PrismaAiAnalysisRunGuard } from "../src/infrastructure/database/postgres/repositories/AiAnalysisRunGuard.prisma";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { ResourceAssetCriticalityProvider } from "../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { LangGraphOrchestratorAdapter } from "../src/infrastructure/ai/LangGraphOrchestratorAdapter";
import { RunIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { GetIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { GenerateRecommendationUseCase } from "../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { RecommendationValidator } from "../src/infrastructure/recommendation-validation/RecommendationValidator";
import { LlmRecommendationAgent } from "../src/infrastructure/ai/LlmRecommendationAgent";
import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { StartResponseUseCase } from "../src/application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../src/application/response/use-cases/CompleteResponse.usecase";
import { DecideApprovalUseCase } from "../src/application/approval/use-cases/DecideApproval.usecase";
import { CreateVerificationUseCase } from "../src/application/verification/use-cases/CreateVerification.usecase";
import { RunRehuntVerificationUseCase } from "../src/application/verification/use-cases/RunRehuntVerification.usecase";
import { INotificationDispatcherPort } from "../src/application/notification/ports/INotificationDispatcherPort";
import { ISiemRehuntPort, RehuntQuery, RehuntResult, RehuntHealth } from "../src/application/verification/ports/ISiemRehuntPort";

const AI_URL = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";
const MEDIUM: Record<string, string> = { "5712": "TC-01 Brute Force", "100310": "TC-03 Phishing", "31103": "TC-06 SQL Injection", "100330": "TC-08 Suspicious Process" };
const SOC = "tc-flow-soc";
const IR = "tc-flow-ir";

class CleanRehuntAdapter implements ISiemRehuntPort {
  isConfigured(): boolean { return true; }
  async health(): Promise<RehuntHealth> { return { configured: true, reachable: true, indexPattern: "clean-rehunt-*" }; }
  async rehunt(q: RehuntQuery): Promise<RehuntResult> {
    return { source: "MOCK_REHUNT", index: `clean-rehunt/no-match#round-${q.investigationNumber ?? 1}`, query: JSON.stringify({ incidentId: q.incidentId }), timeRange: { start: q.timeRange.start.toISOString(), end: q.timeRange.end.toISOString() }, matchingEvents: 0, affectedHosts: [], iocRecurrence: false, spreadDetected: false, threatContained: true, events: [], truncated: false };
  }
}

const TENANT = "00000000-0000-0000-0000-000000000001";

(async () => {
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
  const approvalService = new ApprovalService(ctxRepo, actions, policy, approvals, audit, noNotify, "http://localhost", new ResourceAssetCriticalityProvider());
  const runAnalysis = new RunIncidentAiAnalysisUseCase(incidents, new PrismaAiAnalysisRunGuard(prisma), new LangGraphOrchestratorAdapter(AI_URL), investigations, new GetIncidentAiAnalysisUseCase(ctxRepo), audit);
  const generate = new GenerateRecommendationUseCase(
    new RecommendationContextBuilder(ctxRepo, actions, runbooks, playbookRepo, approvalService),
    new LlmRecommendationAgent(AI_URL), "LlmRecommendationAgent/v2.0.0",
    new RecommendationValidator(actions, runbooks), recs, audit
  );
  const createPlan = new CreateResponsePlanUseCase(recs, actions, runbooks, approvalService, plans, audit, noNotify, "http://localhost");
  const decide = new DecideApprovalUseCase(approvals, audit, recs, ctxRepo, plans, noNotify, "http://localhost");
  const start = new StartResponseUseCase(plans, approvals, audit);
  const complete = new CompleteResponseUseCase(plans, audit, incidents, actions, ctxRepo, noNotify, "http://localhost");
  const createVerification = new CreateVerificationUseCase(verifications, plans, incidents, policy, audit, ctxRepo, noNotify, "http://localhost", generate);
  const rehunt = new RunRehuntVerificationUseCase(new CleanRehuntAdapter(), createVerification, incidents, alerts, plans, verifications, ctxRepo, investigations, audit);

  for (const [rule, name] of Object.entries(MEDIUM)) {
    const alert = await prisma.alert.findFirst({ where: { siemSource: "wazuh", rawPayload: { path: ["rule", "id"], equals: rule } }, orderBy: { receivedAt: "desc" } });
    if (!alert) { console.log(`${name}: alert not found`); continue; }
    const line: string[] = [name.padEnd(20)];

    // 1. SOC triage -> open incident (unless one already exists)
    let incidentId = (await prisma.incident.findFirst({ where: { alertId: alert.id } }))?.id;
    if (!incidentId) {
      const t = await alertWorkflow(prisma).triage.execute({ tenantId: TENANT, alertId: alert.id, actor: SOC, decision: "CREATE_INCIDENT", reason: "SOC review: confirmed for investigation" } as never);
      if (t.isFailure || !(t as any).value.incidentId) { console.log(`${line[0]}| triage FAIL ${(t as any).error}`); continue; }
      incidentId = (t as any).value.incidentId as string;
      line.push("SOC triage→incident");
    } else line.push("incident exists");

    const incNow = await prisma.incident.findUnique({ where: { id: incidentId } });
    if (incNow?.status === "resolved") { console.log(`${line[0]}| already RESOLVED`); continue; }

    // 2. AI analysis
    const a = await runAnalysis.execute({ tenantId: TENANT, incidentId, actor: SOC });
    line.push(a.isSuccess ? "AI✓" : `AI FAIL(${(a as any).error})`);
    const mm = await prisma.mitreMapping.findMany({ where: { incidentId }, select: { techniqueId: true } });
    line.push(`mitre[${mm.map((m) => m.techniqueId).join(",") || "-"}]`);

    // 3. Recommendation (retry up to 3 for LLM variance)
    const recRows = () => prisma.recommendation.findMany({ where: { incidentId }, include: { steps: true } });
    const usable = async () => (await recRows()).some((r) => r.status === "VALIDATED" && r.steps.some((s) => s.actionId));
    for (let i = 0; i < 3 && !(await usable()); i++) await generate.execute({ incidentId, tenantId: TENANT });
    const rec = (await recRows()).filter((r) => r.status === "VALIDATED").pop();
    const step = rec?.steps.find((s) => s.actionId);
    if (!rec || !step) { console.log(`${line.join(" | ")} | REC FAIL`); continue; }
    line.push(`rec✓(${rec.steps.filter((s) => s.actionId).length} steps)`);

    // 4. SOC plan -> IR approve -> execute -> verify
    const p = await createPlan.execute({ recommendationId: rec.id, stepId: step.id, tenantId: TENANT });
    if (p.isFailure) { console.log(`${line.join(" | ")} | plan FAIL ${p.error}`); continue; }
    let plan = p.value;
    while (plan.status === "PENDING_IR_DECISION") {
      const ap = (await approvals.findByResponse(plan.id, TENANT)).find((x) => x.status === "pending");
      if (!ap) break;
      await decide.execute({ approvalId: ap.id, tenantId: TENANT, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "TC-flow: IR approved" });
      plan = (await plans.findById(plan.id, TENANT))!;
    }
    await start.execute({ responseId: plan.id, tenantId: TENANT, startedBy: IR });
    await complete.execute({ responseId: plan.id, tenantId: TENANT, completedBy: IR, executionResult: { simulated: true, by: IR } });
    const v = await rehunt.execute({ incidentId, responseId: plan.id, tenantId: TENANT, verifiedBy: IR });
    const inc = await prisma.incident.findUnique({ where: { id: incidentId } });
    const ver = await prisma.verification.findFirst({ where: { responseId: plan.id } });
    line.push(`IR approve→execute→verify ${v.isSuccess ? ver?.result : "FAIL"}`, `incident=${inc?.status}`);
    console.log(line.join(" | "));
  }
  await prisma.$disconnect();
})().catch((e) => { console.error("crashed:", String(e?.stack ?? e).slice(0, 700)); process.exit(2); });
