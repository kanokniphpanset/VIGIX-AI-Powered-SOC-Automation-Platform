/**
 * wiring.ts — assembles the REAL VIGIX use cases (same classes the API uses) for the evaluation harness,
 * mirroring scripts/run-repeated-evaluation.ts + scripts/walk-tc-response-flow.ts. It differs in exactly one
 * place on purpose: the re-hunt provider is createRehuntProvider(process.env) — the real Wazuh Indexer adapter —
 * never a CleanRehuntAdapter. Notifications are stubbed (no e-mail/Discord/Telegram from an evaluation).
 */
import { PrismaClient } from "@prisma/client";
import { WazuhAdapter } from "../../src/infrastructure/external-services/siem/WazuhAdapter";
import { createRehuntProvider } from "../../src/infrastructure/external-services/siem/createRehuntProvider";
import { alertWorkflow } from "../../src/infrastructure/database/postgres/AlertWorkflow";
import { PrismaAlertRepository } from "../../src/infrastructure/database/postgres/repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "../../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaInvestigationRepository } from "../../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";
import { PrismaRecommendationContextRepository } from "../../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaActionRepository } from "../../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { PrismaPlaybookRepository } from "../../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaRecommendationRepository } from "../../src/infrastructure/database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaApprovalRepository } from "../../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaResponsePlanRepository } from "../../src/infrastructure/database/postgres/repositories/ResponsePlanRepository.prisma";
import { PrismaVerificationRepository } from "../../src/infrastructure/database/postgres/repositories/VerificationRepository.prisma";
import { PrismaPolicyRepository } from "../../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { PrismaAiAnalysisRunGuard } from "../../src/infrastructure/database/postgres/repositories/AiAnalysisRunGuard.prisma";
import { AuditLogger } from "../../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PrismaIncidentResponseSetupStore } from "../../src/infrastructure/database/postgres/repositories/IncidentResponseSetupStore.prisma";
import { IncidentResponseSetupService } from "../../src/application/incident/services/IncidentResponseSetupService";
import { PolicyEvaluator } from "../../src/infrastructure/policy-engine/PolicyEvaluator";
import { PolicyIncidentIntake } from "../../src/infrastructure/policy-engine/PolicyIncidentIntake";
import { ApprovalService } from "../../src/application/approval/services/ApprovalService";
import { ResourceAssetCriticalityProvider } from "../../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { LangGraphOrchestratorAdapter } from "../../src/infrastructure/ai/LangGraphOrchestratorAdapter";
import { RecommendationContextBuilder } from "../../src/application/recommendation/services/RecommendationContextBuilder";
import { RecommendationValidator } from "../../src/infrastructure/recommendation-validation/RecommendationValidator";
import { LlmRecommendationAgent } from "../../src/infrastructure/ai/LlmRecommendationAgent";
import { GenerateRecommendationUseCase } from "../../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { IngestAlertFromSiemUseCase } from "../../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { CreateIncidentUseCase } from "../../src/application/incident/use-cases/CreateIncident.usecase";
import { RunIncidentAiAnalysisUseCase } from "../../src/application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { GetIncidentAiAnalysisUseCase } from "../../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { CreateResponsePlanUseCase } from "../../src/application/response/use-cases/CreateResponsePlan.usecase";
import { StartResponseUseCase } from "../../src/application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../../src/application/response/use-cases/CompleteResponse.usecase";
import { DecideApprovalUseCase } from "../../src/application/approval/use-cases/DecideApproval.usecase";
import { CreateVerificationUseCase } from "../../src/application/verification/use-cases/CreateVerification.usecase";
import { RunRehuntVerificationUseCase } from "../../src/application/verification/use-cases/RunRehuntVerification.usecase";
import { CreateIocUseCase } from "../../src/application/investigation/use-cases/CreateIoc.usecase";
import { INotificationDispatcherPort } from "../../src/application/notification/ports/INotificationDispatcherPort";
import { ContainmentProcedureLoader } from "../../src/infrastructure/knowledge/ContainmentProcedureLoader";
import { PrismaGenerationPlaybookCatalogReader } from "../../src/infrastructure/database/postgres/repositories/GenerationPlaybookCatalogReader.prisma";

export const TENANT = "00000000-0000-0000-0000-000000000001";
export const SOC = "eval-soc";
export const IR = "eval-ir";

export function buildEvalContext(prisma: PrismaClient, aiUrl: string) {
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
  const ingest = new IngestAlertFromSiemUseCase(alerts, incidents, { enqueue: async () => { throw new Error("no queue"); }, latestForIncident: async () => null }, audit, new PolicyIncidentIntake(policy), new CreateIncidentUseCase(incidents, alerts, audit));
  const runAnalysis = new RunIncidentAiAnalysisUseCase(incidents, new PrismaAiAnalysisRunGuard(prisma), new LangGraphOrchestratorAdapter(aiUrl), investigations, new GetIncidentAiAnalysisUseCase(ctxRepo), audit);
  // PRODUCTION PARITY (container.ts): the context builder gets the SOC response setup (playbook selection from the
  // incident's MITRE techniques incl. the alert's own, guidance-limited actions) and the ACTION_COMPLIANCE policies
  // (evidence each Action requires). The earlier evaluation scripts omitted both, so their recommendations were
  // built on a different code path than the running product (Real-Wazuh Clean Run #1 finding).
  const responseSetup = new IncidentResponseSetupService(new PrismaIncidentResponseSetupStore(prisma), ctxRepo, incidents, playbookRepo, actions, policy, audit);
  // Production parity (container.ts): the generation catalog reader pins the exact published playbook revision (Phase 1D); without it generation fails with PLAYBOOK_PROVENANCE_NOT_FOUND.
  // The attack-specific containment procedure (YAML knowledge) is part of the production context as well.
  const contextBuilder = new RecommendationContextBuilder(ctxRepo, actions, runbooks, playbookRepo, approvalService, undefined, { resolve: (i: string, t: string) => responseSetup.resolve(i, t) }, policy, new PrismaGenerationPlaybookCatalogReader(prisma), new ContainmentProcedureLoader());
  const generate = new GenerateRecommendationUseCase(contextBuilder, new LlmRecommendationAgent(aiUrl), "LlmRecommendationAgent/v2.0.0", new RecommendationValidator(actions, runbooks), recs, audit);
  const createPlan = new CreateResponsePlanUseCase(recs, actions, runbooks, approvalService, plans, audit, noNotify, "http://localhost");
  const decide = new DecideApprovalUseCase(approvals, audit, recs, ctxRepo, plans, noNotify, "http://localhost");
  const start = new StartResponseUseCase(plans, approvals, audit);
  const complete = new CompleteResponseUseCase(plans, audit, incidents, actions, ctxRepo, noNotify, "http://localhost");
  const createVerification = new CreateVerificationUseCase(verifications, plans, incidents, policy, audit, ctxRepo, noNotify, "http://localhost", generate);
  // REAL provider: REHUNT_PROVIDER must be "wazuh" (asserted by the runner preflight).
  const rehuntProvider = createRehuntProvider(process.env);
  const rehunt = new RunRehuntVerificationUseCase(rehuntProvider, createVerification, incidents, alerts, plans, verifications, ctxRepo, investigations, audit);
  const createIoc = new CreateIocUseCase(investigations, audit);
  return { wazuh: new WazuhAdapter(), ingest, runAnalysis, generate, createPlan, decide, start, complete, rehunt, rehuntProvider, createIoc, approvals, plans, alertWorkflow: () => alertWorkflow(prisma) };
}
