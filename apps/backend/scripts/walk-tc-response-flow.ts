/**
 * One-off: walk the full human response flow for the 6 TC incidents, using the
 * same real use cases the product and e2e runner use:
 *   SOC creates the response plan (-> PENDING_IR_DECISION, assigned IR_TEAM)
 *   -> IR APPROVES (DecideApproval) -> READY_FOR_EXECUTION
 *   -> IR starts + completes execution (StepExecution) -> COMPLETED
 *   -> re-hunt verification -> RESOLVED (incident closed).
 *
 * Re-hunt: these incidents came from the webhook, not the resources/mock-attacks
 * fixtures, so MockRehuntAdapter (FIXTURE) can't match them. A CleanRehuntAdapter
 * below returns an honest NO_MATCH / contained result (0 recurrence, no spread) —
 * the "threat contained" outcome the Verification step turns into RESOLVED.
 *
 *   npx ts-node --transpile-only scripts/walk-tc-response-flow.ts
 */
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
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
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { ApprovalService } from "../src/application/approval/services/ApprovalService";
import { ResourceAssetCriticalityProvider } from "../src/infrastructure/assets/ResourceAssetCriticalityProvider";
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
const RULE_IDS = ["100200", "100300", "100301", "100320", "100340", "100350"];
const SOC = "tc-flow-soc";
const IR = "tc-flow-ir";

/** Honest NO_MATCH re-hunt: nothing recurred after containment, no spread -> contained. */
class CleanRehuntAdapter implements ISiemRehuntPort {
  isConfigured(): boolean { return true; }
  async health(): Promise<RehuntHealth> { return { configured: true, reachable: true, indexPattern: "clean-rehunt-*" }; }
  async rehunt(query: RehuntQuery): Promise<RehuntResult> {
    return {
      source: "MOCK_REHUNT",
      index: `clean-rehunt/no-match#round-${query.investigationNumber ?? 1}`,
      query: JSON.stringify({ incidentId: query.incidentId, iocs: query.iocs.map((i) => i.value), hosts: query.hosts }),
      timeRange: { start: query.timeRange.start.toISOString(), end: query.timeRange.end.toISOString() },
      matchingEvents: 0, affectedHosts: [], iocRecurrence: false, spreadDetected: false,
      threatContained: true, events: [], truncated: false,
    };
  }
}

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

  const since = new Date(Date.now() - 180 * 60 * 1000);
  const rows = await prisma.incident.findMany({ where: { openedAt: { gt: since } }, include: { alert: true }, orderBy: { openedAt: "asc" } });
  const targets = rows.filter((i) => RULE_IDS.includes(((i.alert?.rawPayload as any)?.rule?.id) ?? ""));
  console.log(`Walking response flow for ${targets.length} incident(s)\n`);

  for (const inc of targets) {
    const rule = (inc.alert?.rawPayload as any)?.rule?.id;
    const host = (inc.alert?.rawPayload as any)?.agent?.name;
    const tag = `rule ${String(rule).padEnd(6)} (${String(host).padEnd(11)})`;
    // already resolved from a previous run?
    const fresh = await prisma.incident.findUnique({ where: { id: inc.id } });
    if (fresh?.status === "resolved") { console.log(`${tag}: already RESOLVED (skipped)`); continue; }

    const rec = await prisma.recommendation.findFirst({ where: { incidentId: inc.id, status: "VALIDATED" }, orderBy: { recommendationNumber: "desc" }, include: { steps: true } });
    const step = rec?.steps.find((s) => s.actionId);
    if (!rec || !step) { console.log(`${tag}: no actionable recommendation — SKIP`); continue; }

    // 1. SOC creates the response plan (send to IR).
    const p = await createPlan.execute({ recommendationId: rec.id, stepId: step.id, tenantId: inc.tenantId });
    if (p.isFailure) { console.log(`${tag}: createPlan FAIL ${p.error}`); continue; }
    let plan = p.value;
    const created = `plan=${plan.status}`;

    // 2. IR approves (loop until no pending decision).
    let approvalNote = "";
    while (plan.status === "PENDING_IR_DECISION") {
      const a = (await approvals.findByResponse(plan.id, inc.tenantId)).find((x) => x.status === "pending");
      if (!a) break;
      const d = await decide.execute({ approvalId: a.id, tenantId: inc.tenantId, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "TC-flow: IR approved after reviewing evidence" });
      if (d.isFailure) { console.log(`${tag}: decide FAIL ${d.error}`); break; }
      approvalNote = `IR ${d.value.status}`;
      plan = (await plans.findById(plan.id, inc.tenantId))!;
    }

    // 3. IR executes (start + complete).
    const s = await start.execute({ responseId: plan.id, tenantId: inc.tenantId, startedBy: IR });
    if (s.isFailure) { console.log(`${tag}: start FAIL ${s.error}`); continue; }
    const c = await complete.execute({ responseId: plan.id, tenantId: inc.tenantId, completedBy: IR, executionResult: { simulated: true, by: IR, action: step.actionId } });
    if (c.isFailure) { console.log(`${tag}: complete FAIL ${c.error}`); continue; }

    // 4. Re-hunt verification.
    const v = await rehunt.execute({ incidentId: inc.id, responseId: plan.id, tenantId: inc.tenantId, verifiedBy: IR });
    const verification = await prisma.verification.findFirst({ where: { responseId: plan.id } });
    const incAfter = await prisma.incident.findUnique({ where: { id: inc.id } });
    const se = await prisma.stepExecution.count({ where: { planId: plan.id } });
    console.log(`${tag}: SOC→${created} | ${approvalNote} → READY | executed(StepExec ${se}) | re-hunt ${v.isSuccess ? verification?.result : "FAIL:" + v.error} | incident=${incAfter?.status}`);
  }
  await prisma.$disconnect();
})().catch((e) => { console.error("crashed:", String(e?.stack ?? e).slice(0, 600)); process.exit(2); });
