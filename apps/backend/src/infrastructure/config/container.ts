import { alertWorkflow } from '../database/postgres/AlertWorkflow';
import { IncidentSlaService } from "../../application/sla/IncidentSlaService";
import { GetDashboardSummaryUseCase, HealthItem } from "../../application/dashboard/use-cases/GetDashboardSummary.usecase";
import { PrismaDashboardReadRepository } from "../database/postgres/repositories/DashboardReadRepository.prisma";
import { PrismaWorkReadRepository } from "../database/postgres/repositories/WorkReadRepository.prisma";
import { WorkQueries } from "../../application/work/WorkQueries.usecases";
import { IncidentContextEmailUseCase } from "../../application/notification/use-cases/IncidentContextEmail.usecase";
import { PrismaIncidentEmailContextReader } from "../database/postgres/repositories/IncidentEmailContextReader.prisma";
import { DashboardController } from "../../presentation/http/controllers/DashboardController";
import { ListAlertInboxUseCase, GetAlertViewUseCase } from "../../application/alert/use-cases/AlertInbox.usecases";
import { MergeAlertsIntoIncidentUseCase } from "../../application/incident/use-cases/MergeAlertsIntoIncident.usecase";
import { GetIncidentAiAnalysisUseCase } from "../../application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { prisma } from "../database/postgres/client";

// Repositories (infrastructure implements domain ports)
import { PrismaAlertRepository } from "../database/postgres/repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "../database/postgres/repositories/IncidentRepository.prisma";
import { PrismaPolicyRepository } from "../database/postgres/repositories/PolicyRepository.prisma";
import { PolicyAuditLogger } from "../database/postgres/repositories/PolicyAuditLogger";
import { PrismaActionRepository } from "../database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../database/postgres/repositories/RunbookRepository.prisma";
import { PrismaMitreTechniqueRepository } from "../database/postgres/repositories/MitreTechniqueRepository.prisma";
import { PrismaPlaybookRepository } from "../database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaRecommendationRepository } from "../database/postgres/repositories/RecommendationRepository.prisma";
import { PrismaRecommendationContextRepository } from "../database/postgres/repositories/RecommendationContextRepository.prisma";
import { AuditLogger } from "../database/postgres/repositories/AuditLogger";
import { PrismaAuthRepository } from "../database/postgres/repositories/AuthRepository.prisma";
import { PrismaApprovalRepository } from "../database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaResponsePlanRepository } from "../database/postgres/repositories/ResponsePlanRepository.prisma";
import { PrismaVerificationRepository } from "../database/postgres/repositories/VerificationRepository.prisma";

// Vector store / knowledge search (infrastructure)
import { QdrantProvider } from "../vectorstore/QdrantProvider";
import { VectorSearchService } from "../../application/knowledge/services/VectorSearchService";

// SIEM adapters (infrastructure implements ISiemAdapter per vendor)
import { WazuhAdapter } from "../external-services/siem/WazuhAdapter";
import { createRehuntProvider } from "../external-services/siem/createRehuntProvider";
import { PrismaInvestigationRepository } from "../database/postgres/repositories/InvestigationRepository.prisma";
import {
  ListInvestigationsByIncidentUseCase,
  GetInvestigationUseCase,
  ListEvidenceUseCase,
  GetEvidenceUseCase,
  ListIocsByInvestigationUseCase,
} from "../../application/investigation/use-cases/ReadInvestigation.usecases";
import { CreateEvidenceUseCase } from "../../application/investigation/use-cases/CreateEvidence.usecase";
import { CreateIocUseCase } from "../../application/investigation/use-cases/CreateIoc.usecase";
import { ListRelatedAlertEvidenceUseCase } from "../../application/investigation/use-cases/RelatedAlertEvidence.usecase";
import { PrismaRelatedAlertEvidenceReader } from "../database/postgres/repositories/RelatedAlertEvidenceReader.prisma";
import { InvestigationController } from "../../presentation/http/controllers/InvestigationController";
import { RunRehuntVerificationUseCase } from "../../application/verification/use-cases/RunRehuntVerification.usecase";
import { SplunkAdapter } from "../external-services/siem/SplunkAdapter";
import { DefenderAdapter } from "../external-services/siem/DefenderAdapter";
import { ElkAdapter } from "../external-services/siem/ElkAdapter";
import { SiemSource } from "../../domain/alert/entities/Alert.entity";
import { ISiemAdapter } from "../external-services/siem/ISiemAdapter";

// AI orchestrator adapter (infrastructure implements IAiOrchestratorPort)
import { LangGraphOrchestratorAdapter } from "../ai/LangGraphOrchestratorAdapter";

// Workflow engine adapter (infrastructure implements IWorkflowEnginePort)
import { N8nWorkflowEngineAdapter } from "../automation/N8nWorkflowEngineAdapter";
import { INotificationDispatcherPort } from "../../application/notification/ports/INotificationDispatcherPort";
import { NotificationRole } from "../../application/notification/events/NotificationEvent";
import { EmailNotificationAdapter } from "../notification/EmailNotificationAdapter";
import { DiscordNotificationAdapter } from "../notification/DiscordNotificationAdapter";
import { TelegramNotificationAdapter } from "../notification/TelegramNotificationAdapter";
import { MultiChannelNotificationDispatcher } from "../notification/MultiChannelNotificationDispatcher";
import { NotificationTestController } from "../../presentation/http/controllers/NotificationTestController";
import { ApprovalService } from "../../application/approval/services/ApprovalService";
import { IrHandoffController } from "../../presentation/http/controllers/IrHandoffController";
import { PrismaNotificationDeliveryRepository } from "../database/postgres/repositories/NotificationDeliveryRepository.prisma";
import { PrismaNotificationRecipientRepository } from "../database/postgres/repositories/NotificationRecipientRepository.prisma";
import { RoleEmailDirectory } from "../../application/notification/services/RoleEmailDirectory";
import { ListNotificationRecipientsUseCase, UpdateNotificationRecipientUseCase } from "../../application/settings/use-cases/NotificationRecipients.usecases";
import { SettingsController } from "../../presentation/http/controllers/SettingsController";
import { PrismaAlertScenarioRepository } from "../database/postgres/repositories/AlertScenarioRepository.prisma";
import { SetAlertScenarioUseCase } from "../../application/alert/use-cases/AlertScenario.usecases";
import { RunIncidentAiAnalysisUseCase } from "../../application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { AiAnalysisJobService, DEFAULT_AI_JOB_POLICY } from "../../application/agent-orchestration/services/AiAnalysisJobService";
import { PrismaAiAnalysisJobRepository } from "../database/postgres/repositories/AiAnalysisJobRepository.prisma";
import { AiAnalysisWorker } from "../workers/AiAnalysisWorker";
import { PrismaAiAnalysisRunGuard } from "../database/postgres/repositories/AiAnalysisRunGuard.prisma";
import { IrEmailService } from "../../application/notification/services/IrEmailService";
import { GetKnowledgeArticleUseCase, PreviewArticleEmailUseCase, SendArticleToIrUseCase } from "../../application/knowledge/use-cases/KnowledgeArticles.usecases";
import { GetResponseGuideUseCase, PreviewResponseGuideUseCase, SendResponseGuideToIrUseCase } from "../../application/incident/use-cases/ResponseGuide.usecases";
import { PrismaPlaybookSnapshotReader } from "../database/postgres/repositories/PlaybookSnapshotReader.prisma";
import { IrEmailController } from "../../presentation/http/controllers/IrEmailController";
import nodemailer from "nodemailer";

// Policy engine (infrastructure — deterministic rule evaluation)
import { PolicyEvaluator } from "../policy-engine/PolicyEvaluator";
import { PolicyIncidentIntake } from "../policy-engine/PolicyIncidentIntake";
import { NotificationDecisionService } from "../../application/triage/NotificationDecisionService";
import { DecideIncidentNotificationUseCase, TriageAlertUseCase, ValidateIncidentSeverityUseCase } from "../../application/triage/SocTriage.usecases";
import { PrismaIncidentSeverityReader, PrismaIncidentSeverityWriter } from "../database/postgres/repositories/IncidentSeverityWriter.prisma";
import { GetIncidentSeverityUseCase } from "../../application/triage/IncidentSeverity.usecase";
import { SocTriageController } from "../../presentation/http/controllers/SocTriageController";
import { IncidentAssignmentService } from "../../application/incident/services/IncidentAssignmentService";
import { SLAEvaluator } from "../policy-engine/SLAEvaluator";
import { ResourceAssetCriticalityProvider } from "../assets/ResourceAssetCriticalityProvider";

// Recommendation AI agent + validator (infrastructure)
import { FakeRecommendationAgent } from "../ai/FakeRecommendationAgent";
import { LlmRecommendationAgent } from "../ai/LlmRecommendationAgent";
import { OpenRouterRecommendationAgent } from "../ai/OpenRouterRecommendationAgent";
import { probeWazuhManagerApi, wazuhManagerConfigFromEnv } from "../external-services/siem/WazuhManagerHealth";
import { FallbackRecommendationAgent } from "../ai/FallbackRecommendationAgent";
import { IRecommendationAgentPort } from "../../application/recommendation/ports/IRecommendationAgentPort";
import { RecommendationValidator } from "../recommendation-validation/RecommendationValidator";
import { RecommendationContextBuilder } from "../../application/recommendation/services/RecommendationContextBuilder";

// Use-cases (application layer, depends only on the ports)
import { CreateIncidentUseCase } from "../../application/incident/use-cases/CreateIncident.usecase";
import { ListAlertsByIncidentUseCase } from "../../application/incident/use-cases/ListAlertsByIncident.usecase";
import { GetIncidentAlertFactsUseCase } from "../../application/incident/use-cases/GetIncidentAlertFacts.usecase";
import { IncidentResponseSetupService } from "../../application/incident/services/IncidentResponseSetupService";
import { PrismaIncidentResponseSetupStore } from "../database/postgres/repositories/IncidentResponseSetupStore.prisma";
import { ListAlertsUseCase } from "../../application/alert/use-cases/ListAlerts.usecase";
import { GetAlertByIdUseCase } from "../../application/alert/use-cases/GetAlertById.usecase";
import { IngestAlertFromSiemUseCase } from "../../application/alert/use-cases/IngestAlertFromSiem.usecase";
import { ListIncidentsUseCase } from "../../application/incident/use-cases/ListIncidents.usecase";
import { GetIncidentByIdUseCase } from "../../application/incident/use-cases/GetIncidentById.usecase";
import { GetIncidentTimelineUseCase } from "../../application/incident/use-cases/GetIncidentTimeline.usecase";
import { UpdateIncidentStatusUseCase } from "../../application/incident/use-cases/UpdateIncidentStatus.usecase";
import { ListIocsByIncidentUseCase } from "../../application/incident/use-cases/ListIocsByIncident.usecase";
import { PrismaThreatIntelVerdictReader } from "../database/postgres/repositories/ThreatIntelVerdictReader.prisma";
import { ListMitreMappingsByIncidentUseCase } from "../../application/incident/use-cases/ListMitreMappingsByIncident.usecase";
import { CreatePolicyUseCase } from "../../application/policy/use-cases/CreatePolicy.usecase";
import { UpdatePolicyUseCase } from "../../application/policy/use-cases/UpdatePolicy.usecase";
import { EnablePolicyUseCase } from "../../application/policy/use-cases/EnablePolicy.usecase";
import { DisablePolicyUseCase } from "../../application/policy/use-cases/DisablePolicy.usecase";
import { DeletePolicyUseCase } from "../../application/policy/use-cases/DeletePolicy.usecase";
import { GetPolicyUseCase } from "../../application/policy/use-cases/GetPolicy.usecase";
import { ListPoliciesUseCase } from "../../application/policy/use-cases/ListPolicies.usecase";
import { EvaluatePolicyUseCase } from "../../application/policy/use-cases/EvaluatePolicy.usecase";
import { CreateActionUseCase } from "../../application/action/use-cases/CreateAction.usecase";
import { UpdateActionUseCase } from "../../application/action/use-cases/UpdateAction.usecase";
import { EnableActionUseCase } from "../../application/action/use-cases/EnableAction.usecase";
import { DisableActionUseCase } from "../../application/action/use-cases/DisableAction.usecase";
import { GetActionUseCase } from "../../application/action/use-cases/GetAction.usecase";
import { ListActionsUseCase } from "../../application/action/use-cases/ListActions.usecase";
import { CreateRunbookUseCase } from "../../application/runbook/use-cases/CreateRunbook.usecase";
import { UpdateRunbookUseCase } from "../../application/runbook/use-cases/UpdateRunbook.usecase";
import { GetRunbookUseCase } from "../../application/runbook/use-cases/GetRunbook.usecase";
import { ListRunbooksUseCase } from "../../application/runbook/use-cases/ListRunbooks.usecase";
import { ListMitreTechniquesUseCase } from "../../application/mitre/use-cases/ListMitreTechniques.usecase";
import { CreatePlaybookUseCase } from "../../application/playbook/use-cases/CreatePlaybook.usecase";
import { UpdatePlaybookUseCase } from "../../application/playbook/use-cases/UpdatePlaybook.usecase";
import { DeletePlaybookUseCase } from "../../application/playbook/use-cases/DeletePlaybook.usecase";
import { GetPlaybookUseCase } from "../../application/playbook/use-cases/GetPlaybook.usecase";
import { ListPlaybooksUseCase } from "../../application/playbook/use-cases/ListPlaybooks.usecase";
import { GenerateRecommendationUseCase } from "../../application/recommendation/use-cases/GenerateRecommendation.usecase";
import { GetRecommendationUseCase } from "../../application/recommendation/use-cases/GetRecommendation.usecase";
import { ListRecommendationsUseCase } from "../../application/recommendation/use-cases/ListRecommendations.usecase";
import { ValidateRecommendationUseCase } from "../../application/recommendation/use-cases/ValidateRecommendation.usecase";
import { LoginUseCase } from "../../application/identity/use-cases/Login.usecase";
import { RequestApprovalUseCase } from "../../application/approval/use-cases/RequestApproval.usecase";
import { DecideApprovalUseCase } from "../../application/approval/use-cases/DecideApproval.usecase";
import { GetApprovalUseCase } from "../../application/approval/use-cases/GetApproval.usecase";
import { ListApprovalsByRecommendationUseCase } from "../../application/approval/use-cases/ListApprovalsByRecommendation.usecase";
import { SendRecommendationToIrUseCase } from "../../application/response/use-cases/SendRecommendationToIr.usecase";
import { CreateResponsePlanUseCase } from "../../application/response/use-cases/CreateResponsePlan.usecase";
import { StartResponseUseCase } from "../../application/response/use-cases/StartResponse.usecase";
import { CompleteResponseUseCase } from "../../application/response/use-cases/CompleteResponse.usecase";
import { FailResponseUseCase } from "../../application/response/use-cases/FailResponse.usecase";
import { GetResponseUseCase } from "../../application/response/use-cases/GetResponse.usecase";
import { ListResponsePlansUseCase } from "../../application/response/use-cases/ListResponsePlans.usecase";
import { CreateVerificationUseCase } from "../../application/verification/use-cases/CreateVerification.usecase";
import { GetVerificationUseCase } from "../../application/verification/use-cases/GetVerification.usecase";
import { ListVerificationsUseCase } from "../../application/verification/use-cases/ListVerifications.usecase";
import { ListAllVerificationsUseCase } from "../../application/verification/use-cases/ListAllVerifications.usecase";

// Controllers (presentation layer)
import { AlertController } from "../../presentation/http/controllers/AlertController";
import { IncidentController } from "../../presentation/http/controllers/IncidentController";
import { PolicyController } from "../../presentation/http/controllers/PolicyController";
import { PolicyEvaluationController } from "../../presentation/http/controllers/PolicyEvaluationController";
import { ActionController } from "../../presentation/http/controllers/ActionController";
import { RunbookController } from "../../presentation/http/controllers/RunbookController";
import { MitreController } from "../../presentation/http/controllers/MitreController";
import { PlaybookController } from "../../presentation/http/controllers/PlaybookController";
import { RecommendationController } from "../../presentation/http/controllers/RecommendationController";
import { AuthController } from "../../presentation/http/controllers/AuthController";
import { ApprovalController } from "../../presentation/http/controllers/ApprovalController";
import { KnowledgeSearchController } from "../../presentation/http/controllers/KnowledgeSearchController";
import { ResponseController } from "../../presentation/http/controllers/ResponseController";
import { VerificationController } from "../../presentation/http/controllers/VerificationController";
import { SiemInboundWebhookController } from "../../presentation/http/webhooks/siem-inbound.webhook";
import { OrchestratorCallbackController } from "../../presentation/http/webhooks/orchestrator-callback.webhook";
import { PrismaInAppNotificationRepository } from "../database/postgres/repositories/InAppNotificationRepository.prisma";
import { InAppNotifier, InAppRecordingDispatcher } from "../../application/notification/services/InAppNotifier";
import { InAppNotificationController } from "../../presentation/http/controllers/InAppNotificationController";
import { PrismaAlertInboxQuery } from "../database/postgres/repositories/AlertInboxQuery.prisma";

/**
 * container.ts — composition root.
 * This is the ONLY file in the codebase allowed to know about every layer at once.
 * Everything upstream (domain, application) stays ignorant of how it's wired together.
 * Swap PrismaAlertRepository, a SIEM adapter, the orchestrator adapter, or the
 * workflow engine adapter here — nothing else in the codebase changes.
 */

// Repositories
const alertRepository = new PrismaAlertRepository(prisma);
const incidentRepository = new PrismaIncidentRepository(prisma);
const investigationRepository = new PrismaInvestigationRepository(prisma);
const policyRepository = new PrismaPolicyRepository(prisma);
const policyAuditLogger = new PolicyAuditLogger(prisma);
const actionRepository = new PrismaActionRepository(prisma);
const runbookRepository = new PrismaRunbookRepository(prisma);
const mitreTechniqueRepository = new PrismaMitreTechniqueRepository(prisma);
const playbookRepository = new PrismaPlaybookRepository(prisma);
const recommendationRepository = new PrismaRecommendationRepository(prisma);
const recommendationContextRepository = new PrismaRecommendationContextRepository(prisma);
const auditLogger = new AuditLogger(prisma);
// Analyst-set lab test-scenario labels on alerts (Alert Inbox search/filter).
const alertScenarioRepository = new PrismaAlertScenarioRepository(prisma);
const authRepository = new PrismaAuthRepository(prisma);
const approvalRepository = new PrismaApprovalRepository(prisma);
const responsePlanRepository = new PrismaResponsePlanRepository(prisma);
const verificationRepository = new PrismaVerificationRepository(prisma);

// Policy engine
const slaEvaluator = new SLAEvaluator();
const policyEvaluator = new PolicyEvaluator(policyRepository, slaEvaluator);

// SIEM adapter registry — add a new vendor by adding one line here
const siemAdapters: Partial<Record<SiemSource, ISiemAdapter>> = {
  wazuh: new WazuhAdapter(),
  splunk: new SplunkAdapter(),
  defender: new DefenderAdapter(),
  elk: new ElkAdapter(),
};

// AI orchestrator — points at the ai-orchestrator FastAPI service (apps/ai-orchestrator)
const aiOrchestratorUrl = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";
const aiOrchestrator = new LangGraphOrchestratorAdapter(aiOrchestratorUrl);

// Workflow engine — points at the n8n instance (see infra/docker/docker-compose.yml)
const n8nUrl = process.env.N8N_URL ?? "http://localhost:5678";
const n8nApiKey = process.env.N8N_API_KEY;
// Not wired to any automatic path: AI decisions never trigger n8n. Kept for a future explicit human action.
export const workflowEngine = new N8nWorkflowEngineAdapter(n8nUrl, n8nApiKey);

// Notification delivery (Phase N2 built the event/routing side; this is the
// backend-native delivery layer that replaced n8n as the active path — see
// docs/architecture/notification-event-contract.md). Routing (recipient
// roles + channels) is unchanged; only what used to POST to n8n and let it
// render+send now renders+sends in-process via one adapter per channel.
const emailTransporter = process.env.EMAIL_HOST
  ? nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT ?? 587),
      secure: process.env.EMAIL_SECURE === "true",
      auth: process.env.EMAIL_USER
        ? {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
          }
        : undefined,
    })
  : null;

const emailAdapter = new EmailNotificationAdapter(
  emailTransporter,
  process.env.EMAIL_FROM,
  process.env.EMAIL_PASSWORD
);
const discordAdapter = new DiscordNotificationAdapter(
  process.env.DISCORD_WEBHOOK_URL
);
const telegramAdapter = new TelegramNotificationAdapter(
  process.env.TELEGRAM_BOT_TOKEN,
  process.env.TELEGRAM_CHAT_ID
);
const notificationDeliveryRepository =
  new PrismaNotificationDeliveryRepository(prisma);

// IR_TEAM_EMAIL / SOC_EMAIL / ADMIN_EMAIL: the server default per role (Settings value wins).
const roleEmail: Partial<Record<NotificationRole, string>> = {
  IR_TEAM: process.env.IR_TEAM_EMAIL,
  SOC: process.env.SOC_EMAIL,
  ADMIN: process.env.ADMIN_EMAIL,
};

// Role emails: the admin's Settings value wins, else the .env default above (resolved at send time).
const notificationRecipientRepository = new PrismaNotificationRecipientRepository(prisma);
const roleEmailDirectory = new RoleEmailDirectory(notificationRecipientRepository, roleEmail);

const deliveryDispatcher: INotificationDispatcherPort =
  new MultiChannelNotificationDispatcher(
    emailAdapter,
    discordAdapter,
    telegramAdapter,
    notificationDeliveryRepository,
    roleEmailDirectory
  );

// Header bell: every workflow event is also recorded as a persistent, role-aware in-app notification.
const inAppNotificationRepository = new PrismaInAppNotificationRepository(prisma);
const inAppNotifier = new InAppNotifier(inAppNotificationRepository);
const notificationDispatcher: INotificationDispatcherPort = new InAppRecordingDispatcher(deliveryDispatcher, inAppNotifier);

const vigixBaseUrl =
  process.env.VIGIX_BASE_URL ?? "http://localhost:5173";

// Vector store — points at the Qdrant instance (see infra/docker/docker-compose.yml).
// ONE collection ("knowledge_embeddings") holding every indexed document,
// disambiguated by payload.metadata.sourceType (PLAYBOOK/KNOWLEDGE) — matches
// how apps/ai-orchestrator's retriever.py actually filters today, not the
// unused 3-collection naming in that repo's own (never-called) qdrant_provider.ts.
const qdrantUrl =
  process.env.QDRANT_URL ?? "http://localhost:6333";

const EMBEDDING_VECTOR_SIZE = 384;
// BAAI/bge-small-en-v1.5 — must match apps/ai-orchestrator's embedding_model
const qdrantProvider = new QdrantProvider(
  qdrantUrl,
  EMBEDDING_VECTOR_SIZE
);

export const KNOWLEDGE_COLLECTION = "knowledge_embeddings";

const vectorSearchService = new VectorSearchService(
  qdrantProvider,
  KNOWLEDGE_COLLECTION
);

// Recommendation agent — selectable via RECOMMENDATION_AGENT=fake|llm.
// "llm": LlmRecommendationAgent -> apps/ai-orchestrator POST /recommendations/generate
// (RAG grounding + one LLM call; errors instead of any fallback candidate).
// "fake" (the default when unset) is the deterministic, no-AI stand-in used by
// tests and environments without an orchestrator — not a real recommendation.
// "openrouter": OpenRouterRecommendationAgent only (no orchestrator).
// With OPENROUTER_API_KEY set, "llm" falls back to OpenRouter when the orchestrator is down (unreachable / 503 / 504).
const recommendationAgentMode =
  process.env.RECOMMENDATION_AGENT === "llm" ? "llm" : process.env.RECOMMENDATION_AGENT === "openrouter" ? "openrouter" : "fake";
const openRouterKey = process.env.OPENROUTER_API_KEY?.trim() ?? "";
const openRouterModel = process.env.OPENROUTER_MODEL?.trim() || "openrouter/auto";
if (recommendationAgentMode === "openrouter" && !openRouterKey) throw new Error("RECOMMENDATION_AGENT=openrouter needs OPENROUTER_API_KEY");

const recommendationAgent: IRecommendationAgentPort =
  recommendationAgentMode === "openrouter"
    ? new OpenRouterRecommendationAgent(openRouterKey, openRouterModel)
    : recommendationAgentMode === "llm"
      ? openRouterKey
        ? new FallbackRecommendationAgent(new LlmRecommendationAgent(aiOrchestratorUrl), new OpenRouterRecommendationAgent(openRouterKey, openRouterModel))
        : new LlmRecommendationAgent(aiOrchestratorUrl)
      : new FakeRecommendationAgent();

const recommendationAgentVersion =
  recommendationAgentMode === "openrouter"
    ? `OpenRouterRecommendationAgent/v1.0.0 (${openRouterModel})`
    : recommendationAgentMode === "llm"
      ? openRouterKey
        ? `LlmRecommendationAgent/v2.0.0 (OpenRouter fallback: ${openRouterModel})`
        : "LlmRecommendationAgent/v2.0.0"
      : "FakeRecommendationAgent/v1.0.0";

// One shared Policy-evaluation + approval-opening path for
// CreateResponsePlan, RequestApproval and the Recommendation context
// (per-Action Policy result, Task 10.3).
const approvalService =
  new ApprovalService(
    recommendationContextRepository,
    actionRepository,
    policyEvaluator,
    approvalRepository,
    auditLogger,
    notificationDispatcher,
    vigixBaseUrl,
    new ResourceAssetCriticalityProvider()
  );

// Policy assignment (responsibleRole) recorded after each completed AI analysis — read-only (INCIDENT_ASSIGNED).
const incidentAssignmentService = new IncidentAssignmentService(approvalService, auditLogger);

const recommendationContextBuilder =
  new RecommendationContextBuilder(
    recommendationContextRepository,
    actionRepository,
    runbookRepository,
    playbookRepository,
    approvalService,
    undefined,
    // Late-bound: the setup service is built further down (it needs the Policy use cases).
    { resolve: (incidentId: string, tenantId: string) => incidentResponseSetupService.resolve(incidentId, tenantId) }
  );

const recommendationValidator =
  new RecommendationValidator(
    actionRepository,
    runbookRepository
  );

// Use-cases
const listAlertsUseCase =
  new ListAlertsUseCase(alertRepository);

const getAlertByIdUseCase =
  new GetAlertByIdUseCase(alertRepository);

// Pipeline A: DB-backed AI analysis queue (agent_executions) + in-process worker. The worker runs the existing
// pipeline through the same orchestrator adapter (analysis_only, execution_id = the queued row).
const envInt = (name: string, fallback: number) => {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
};
export const aiAnalysisJobService = new AiAnalysisJobService(
  new PrismaAiAnalysisJobRepository(prisma),
  aiOrchestrator,
  investigationRepository,
  auditLogger,
  {
    maxAttempts: envInt("AI_JOB_MAX_ATTEMPTS", DEFAULT_AI_JOB_POLICY.maxAttempts),
    baseBackoffMs: envInt("AI_JOB_BACKOFF_MS", DEFAULT_AI_JOB_POLICY.baseBackoffMs),
    staleRunningMs: envInt("AI_JOB_STALE_MS", DEFAULT_AI_JOB_POLICY.staleRunningMs),
    busyDelayMs: DEFAULT_AI_JOB_POLICY.busyDelayMs,
  },
  undefined,
  (job) => incidentAssignmentService.assign({ tenantId: job.tenantId, incidentId: job.incidentId, actor: "policy-engine", trigger: `AI_JOB_${job.trigger ?? "UNKNOWN"}` })
);
export const aiAnalysisWorker = new AiAnalysisWorker(aiAnalysisJobService, {
  pollMs: envInt("AI_WORKER_POLL_MS", 3000),
  recoveryMs: envInt("AI_WORKER_RECOVERY_MS", 60_000),
});

const ingestAlertFromSiemUseCase =
  new IngestAlertFromSiemUseCase(
    alertRepository,
    incidentRepository,
    aiAnalysisJobService,
    auditLogger,
    new PolicyIncidentIntake(policyEvaluator),
    // HIGH / CRITICAL open their incident at ingestion (same use case the SOC uses; declared below, called at runtime).
    { execute: (input) => createIncidentUseCase.execute(input) }
  );

const listIncidentsUseCase =
  new ListIncidentsUseCase(incidentRepository);

const getIncidentByIdUseCase =
  new GetIncidentByIdUseCase(incidentRepository);

const getIncidentTimelineUseCase =
  new GetIncidentTimelineUseCase(incidentRepository);

const updateIncidentStatusUseCase =
  new UpdateIncidentStatusUseCase(incidentRepository, auditLogger);

const listIocsByIncidentUseCase =
  new ListIocsByIncidentUseCase(
    incidentRepository,
    recommendationContextRepository,
    new PrismaThreatIntelVerdictReader(prisma)
  );

const listMitreMappingsByIncidentUseCase =
  new ListMitreMappingsByIncidentUseCase(
    incidentRepository,
    recommendationContextRepository
  );

const createPolicyUseCase =
  new CreatePolicyUseCase(
    policyRepository,
    policyAuditLogger
  );

const updatePolicyUseCase =
  new UpdatePolicyUseCase(
    policyRepository,
    policyAuditLogger
  );

const enablePolicyUseCase =
  new EnablePolicyUseCase(
    policyRepository,
    policyAuditLogger
  );

// SOC response setup before a Recommendation: incident type (-> playbook) + case / group (RESPONSE_GUIDANCE) guidance.
const incidentResponseSetupService = new IncidentResponseSetupService(
  new PrismaIncidentResponseSetupStore(prisma),
  recommendationContextRepository,
  incidentRepository,
  playbookRepository,
  actionRepository,
  policyEvaluator,
  auditLogger,
  { repository: policyRepository, create: createPolicyUseCase, update: updatePolicyUseCase, enable: enablePolicyUseCase }
);

const disablePolicyUseCase =
  new DisablePolicyUseCase(
    policyRepository,
    policyAuditLogger
  );

const getPolicyUseCase =
  new GetPolicyUseCase(policyRepository);

const listPoliciesUseCase =
  new ListPoliciesUseCase(policyRepository);

const evaluatePolicyUseCase =
  new EvaluatePolicyUseCase(policyEvaluator);

const createActionUseCase =
  new CreateActionUseCase(actionRepository);

const updateActionUseCase =
  new UpdateActionUseCase(actionRepository);

const enableActionUseCase =
  new EnableActionUseCase(actionRepository);

const disableActionUseCase =
  new DisableActionUseCase(actionRepository);

const getActionUseCase =
  new GetActionUseCase(actionRepository);

const listActionsUseCase =
  new ListActionsUseCase(actionRepository);

const createRunbookUseCase =
  new CreateRunbookUseCase(runbookRepository);

const updateRunbookUseCase =
  new UpdateRunbookUseCase(runbookRepository);

const getRunbookUseCase =
  new GetRunbookUseCase(runbookRepository);

const listRunbooksUseCase =
  new ListRunbooksUseCase(runbookRepository);

const createPlaybookUseCase =
  new CreatePlaybookUseCase(playbookRepository, auditLogger);

const updatePlaybookUseCase =
  new UpdatePlaybookUseCase(playbookRepository, auditLogger);

const getPlaybookUseCase =
  new GetPlaybookUseCase(playbookRepository);

const listPlaybooksUseCase =
  new ListPlaybooksUseCase(playbookRepository);

const generateRecommendationUseCase =
  new GenerateRecommendationUseCase(
    recommendationContextBuilder,
    recommendationAgent,
    recommendationAgentVersion,
    recommendationValidator,
    recommendationRepository,
    auditLogger
  );

const getRecommendationUseCase =
  new GetRecommendationUseCase(recommendationRepository);

const listRecommendationsUseCase =
  new ListRecommendationsUseCase(recommendationRepository);

const validateRecommendationUseCase =
  new ValidateRecommendationUseCase(
    recommendationRepository,
    actionRepository,
    runbookRepository,
    auditLogger
  );

const loginUseCase =
  new LoginUseCase(authRepository);

const requestApprovalUseCase =
  new RequestApprovalUseCase(
    recommendationRepository,
    responsePlanRepository,
    approvalRepository,
    actionRepository,
    runbookRepository,
    approvalService
  );

const decideApprovalUseCase =
  new DecideApprovalUseCase(
    approvalRepository,
    auditLogger,
    recommendationRepository,
    recommendationContextRepository,
    responsePlanRepository,
    notificationDispatcher,
    vigixBaseUrl
  );

const getApprovalUseCase =
  new GetApprovalUseCase(approvalRepository);

const listApprovalsByRecommendationUseCase =
  new ListApprovalsByRecommendationUseCase(
    approvalRepository
  );

const createResponsePlanUseCase =
  new CreateResponsePlanUseCase(
    recommendationRepository,
    actionRepository,
    runbookRepository,
    approvalService,
    responsePlanRepository,
    auditLogger,
    notificationDispatcher,
    vigixBaseUrl
  );

const startResponseUseCase =
  new StartResponseUseCase(
    responsePlanRepository,
    approvalRepository,
    auditLogger,
    inAppNotifier
  );

const completeResponseUseCase =
  new CompleteResponseUseCase(
    responsePlanRepository,
    auditLogger,
    incidentRepository,
    actionRepository,
    recommendationContextRepository,
    notificationDispatcher,
    vigixBaseUrl
  );

const failResponseUseCase =
  new FailResponseUseCase(
    responsePlanRepository,
    auditLogger
  );

const getResponseUseCase =
  new GetResponseUseCase(responsePlanRepository);

const listResponsePlansUseCase =
  new ListResponsePlansUseCase(responsePlanRepository);

const createVerificationUseCase =
  new CreateVerificationUseCase(
    verificationRepository,
    responsePlanRepository,
    incidentRepository,
    policyEvaluator,
    auditLogger,
    recommendationContextRepository,
    notificationDispatcher,
    vigixBaseUrl,
    generateRecommendationUseCase,
    inAppNotifier
  );

const getVerificationUseCase =
  new GetVerificationUseCase(verificationRepository);

const listVerificationsUseCase =
  new ListVerificationsUseCase(verificationRepository);

const listAllVerificationsUseCase =
  new ListAllVerificationsUseCase(verificationRepository);

// Controllers
// Alert Inbox: database-backed SOC review queue (MEDIUM / HIGH / CRITICAL; filters / SLA ordering / paging in SQL).
// Review SLA targets come from Policy (TRIAGE_SLA) via the PolicyEvaluator — never hardcoded.
const alertInboxQuery = new PrismaAlertInboxQuery(prisma);

export const alertController =
  new AlertController(
    listAlertsUseCase,
    getAlertByIdUseCase,
    ingestAlertFromSiemUseCase,
    new ListAlertInboxUseCase(alertInboxQuery, policyEvaluator),
    new GetAlertViewUseCase(alertRepository, incidentRepository, policyEvaluator, alertScenarioRepository)
  );

const createIncidentUseCase =
  new CreateIncidentUseCase(
    incidentRepository,
    alertRepository,
    auditLogger,
    aiAnalysisJobService,
    inAppNotifier
  );

const listAlertsByIncidentUseCase =
  new ListAlertsByIncidentUseCase(
    incidentRepository
  );

// Policy-derived SLA (read-only; no audit) — Incident Detail, Ticket page and dashboard.
const incidentSlaService =
  new IncidentSlaService(recommendationContextRepository, policyEvaluator, responsePlanRepository, new ResourceAssetCriticalityProvider());

export const incidentController =
  new IncidentController(
    listIncidentsUseCase,
    getIncidentByIdUseCase,
    getIncidentTimelineUseCase,
    updateIncidentStatusUseCase,
    listIocsByIncidentUseCase,
    listMitreMappingsByIncidentUseCase,
    createIncidentUseCase,
    listAlertsByIncidentUseCase,
    new MergeAlertsIntoIncidentUseCase(incidentRepository, alertRepository, investigationRepository, auditLogger),
    new GetIncidentAiAnalysisUseCase(recommendationContextRepository),
    incidentSlaService,
    new GetIncidentAlertFactsUseCase(listAlertsByIncidentUseCase, listMitreMappingsByIncidentUseCase, playbookRepository, incidentResponseSetupService),
    incidentResponseSetupService
  );

export const policyController =
  new PolicyController(
    createPolicyUseCase,
    updatePolicyUseCase,
    enablePolicyUseCase,
    disablePolicyUseCase,
    getPolicyUseCase,
    listPoliciesUseCase,
    new DeletePolicyUseCase(policyRepository, policyAuditLogger)
  );

export const policyEvaluationController =
  new PolicyEvaluationController(
    evaluatePolicyUseCase
  );

export const actionController =
  new ActionController(
    createActionUseCase,
    updateActionUseCase,
    enableActionUseCase,
    disableActionUseCase,
    getActionUseCase,
    listActionsUseCase
  );

export const runbookController =
  new RunbookController(
    createRunbookUseCase,
    updateRunbookUseCase,
    getRunbookUseCase,
    listRunbooksUseCase
  );

export const playbookController =
  new PlaybookController(
    createPlaybookUseCase,
    updatePlaybookUseCase,
    getPlaybookUseCase,
    listPlaybooksUseCase,
    new DeletePlaybookUseCase(playbookRepository, auditLogger)
  );

export const recommendationController =
  new RecommendationController(
    generateRecommendationUseCase,
    getRecommendationUseCase,
    listRecommendationsUseCase,
    validateRecommendationUseCase,
    new SendRecommendationToIrUseCase(recommendationRepository, responsePlanRepository, createResponsePlanUseCase, auditLogger)
  );

export const authController =
  new AuthController(loginUseCase);

export const approvalController =
  new ApprovalController(
    requestApprovalUseCase,
    decideApprovalUseCase,
    getApprovalUseCase,
    listApprovalsByRecommendationUseCase
  );

export const knowledgeSearchController =
  new KnowledgeSearchController(vectorSearchService);

// Wazuh Indexer (evidence source for re-hunt).
// All settings come from the environment; nothing is hardcoded.
// From the host use https://localhost:9200
// (+ WAZUH_INDEXER_TLS_SERVERNAME=wazuh.indexer);
// from a container on the Wazuh docker network use
// https://wazuh.indexer:9200.
// Credentials are never sent to the frontend or logged.
// Re-hunt provider: REHUNT_PROVIDER=mock selects the deterministic fixture provider (dev/test only,
// resources/mock-attacks; REHUNT_MOCK_MODE=FIXTURE|ERROR|TIMEOUT|INDEXER_UNAVAILABLE). Default: real Wazuh Indexer.
const rehuntProvider = createRehuntProvider(process.env);

const runRehuntVerificationUseCase =
  new RunRehuntVerificationUseCase(
    rehuntProvider,
    createVerificationUseCase,
    incidentRepository,
    alertRepository,
    responsePlanRepository,
    verificationRepository,
    recommendationContextRepository,
    investigationRepository,
    auditLogger
  );

export const investigationController =
  new InvestigationController(
    new ListInvestigationsByIncidentUseCase(
      investigationRepository,
      incidentRepository
    ),
    new GetInvestigationUseCase(
      investigationRepository
    ),
    new ListEvidenceUseCase(
      investigationRepository
    ),
    new GetEvidenceUseCase(
      investigationRepository
    ),
    new ListIocsByInvestigationUseCase(
      investigationRepository
    ),
    new CreateEvidenceUseCase(
      investigationRepository,
      incidentRepository,
      auditLogger
    ),
    new CreateIocUseCase(
      investigationRepository,
      auditLogger,
      alertRepository
    )
  );

export const listRelatedAlertEvidenceUseCase = new ListRelatedAlertEvidenceUseCase(new PrismaRelatedAlertEvidenceReader(prisma));

export const verificationController =
  new VerificationController(
    createVerificationUseCase,
    getVerificationUseCase,
    listVerificationsUseCase,
    listAllVerificationsUseCase,
    runRehuntVerificationUseCase,
    rehuntProvider
  );

export const responseController =
  new ResponseController(
    createResponsePlanUseCase,
    startResponseUseCase,
    completeResponseUseCase,
    failResponseUseCase,
    getResponseUseCase,
    listResponsePlansUseCase
  );

export const siemWebhookController =
  new SiemInboundWebhookController(
    ingestAlertFromSiemUseCase,
    siemAdapters
  );

export const orchestratorCallbackController =
  // Records/acknowledges the AI decision only — never triggers n8n (AI decisions are advisory).
  new OrchestratorCallbackController(auditLogger);

export const notificationTestController =
  new NotificationTestController(
    emailAdapter,
    discordAdapter,
    telegramAdapter
  );

export const irHandoffController =
  new IrHandoffController(
    emailAdapter,
    roleEmailDirectory
  );

// Knowledge article / incident response guide -> IR Team email: same adapter, recipient directory, delivery log, audit.
const irEmailService = new IrEmailService(emailAdapter, roleEmailDirectory, notificationDeliveryRepository, auditLogger, inAppNotifier);

export const inAppNotificationController = new InAppNotificationController(inAppNotificationRepository);
const getKnowledgeArticleUseCase = new GetKnowledgeArticleUseCase(playbookRepository, runbookRepository);
const getResponseGuideUseCase = new GetResponseGuideUseCase(
  recommendationContextRepository,
  recommendationRepository,
  runbookRepository,
  new PrismaPlaybookSnapshotReader(prisma),
  responsePlanRepository
);
export const irEmailController =
  new IrEmailController(
    new PreviewArticleEmailUseCase(getKnowledgeArticleUseCase, irEmailService, vigixBaseUrl),
    new SendArticleToIrUseCase(getKnowledgeArticleUseCase, irEmailService, vigixBaseUrl),
    new PreviewResponseGuideUseCase(getResponseGuideUseCase, irEmailService, vigixBaseUrl),
    new SendResponseGuideToIrUseCase(getResponseGuideUseCase, irEmailService, vigixBaseUrl)
  );

// SOC case handling: alert review, incident email SEND/SKIP (same IR email path + duplicate protection), severity validation.
const notificationDecisionService = new NotificationDecisionService(irEmailService, auditLogger);
const transactionalAlertWorkflow = alertWorkflow(prisma, aiAnalysisJobService);
export const socTriageController = new SocTriageController(
  // Alert review: no claim, no email (notification belongs to the incident / ticket workflow).
  transactionalAlertWorkflow.triage,
  new DecideIncidentNotificationUseCase(recommendationContextRepository, notificationDecisionService),
  new ValidateIncidentSeverityUseCase(recommendationContextRepository, new PrismaIncidentSeverityWriter(prisma), auditLogger, (i) =>
    incidentAssignmentService.assign({ ...i, trigger: "SEVERITY_VALIDATED" })
  ),
  new GetIncidentSeverityUseCase(new PrismaIncidentSeverityReader(prisma))
);

/** Periodic job (main.ts): legacy monitored alerts whose review date passed go back to the review queue. */
export const returnDueMonitoredAlertsUseCase = transactionalAlertWorkflow.review;

// Run / Re-run AI Analysis for an existing incident: the same orchestrator adapter (analysis-only mode).
export const runIncidentAiAnalysisUseCase = new RunIncidentAiAnalysisUseCase(
  incidentRepository,
  new PrismaAiAnalysisRunGuard(prisma),
  aiOrchestrator,
  investigationRepository,
  new GetIncidentAiAnalysisUseCase(recommendationContextRepository),
  auditLogger
);

export const setAlertScenarioUseCase = new SetAlertScenarioUseCase(alertRepository, alertScenarioRepository, auditLogger);

export const settingsController =
  new SettingsController(
    new ListNotificationRecipientsUseCase(notificationRecipientRepository, roleEmailDirectory),
    new UpdateNotificationRecipientUseCase(notificationRecipientRepository, auditLogger)
  );
export const mitreController =
  new MitreController(
    new ListMitreTechniquesUseCase(mitreTechniqueRepository)
  );

// Operations dashboard: real aggregates + SLA watchlist + live integration health.
async function probeAiOrchestrator(): Promise<{ reachable: boolean; latencyMs: number | null }> {
  const started = Date.now();
  try {
    const res = await fetch(`${aiOrchestratorUrl}/health`, { signal: AbortSignal.timeout(2500) });
    return { reachable: res.ok, latencyMs: Date.now() - started };
  } catch {
    return { reachable: false, latencyMs: null };
  }
}

/** The in-process AI queue worker plus the oldest job still waiting (a stuck queue is DEGRADED, never "healthy"). */
async function probeAiWorker(): Promise<{ status: HealthItem["status"]; detail: string | null; latencyMs: number | null }> {
  const w = aiAnalysisWorker.status();
  if (!w.running) return { status: "DOWN", detail: process.env.AI_WORKER_ENABLED === "false" ? "Disabled (AI_WORKER_ENABLED=false)" : "Not running", latencyMs: null };
  const oldest = await prisma.agentExecution.findFirst({ where: { status: "QUEUED" }, orderBy: { queuedAt: "asc" }, select: { queuedAt: true, nextAttemptAt: true } });
  const due = oldest ? Math.max(oldest.queuedAt?.getTime() ?? 0, oldest.nextAttemptAt?.getTime() ?? 0) : null;
  const waitingMin = due ? Math.floor((Date.now() - due) / 60000) : 0;
  if (waitingMin >= 15) return { status: "DEGRADED", detail: `Oldest due job waiting ${waitingMin} min`, latencyMs: null };
  return { status: "UP", detail: w.busy ? "Processing a job" : w.lastTickAt ? `Idle · last poll ${w.lastTickAt}` : "Idle", latencyMs: null };
}

async function probeQdrant(): Promise<{ status: HealthItem["status"]; detail: string | null; latencyMs: number | null }> {
  const url = process.env.QDRANT_URL;
  if (!url) return { status: "NOT_CONFIGURED", detail: "QDRANT_URL not set", latencyMs: null };
  const started = Date.now();
  try {
    const res = await fetch(`${url.replace(/\/$/, "")}/healthz`, { signal: AbortSignal.timeout(2500) });
    return { status: res.ok ? "UP" : "DOWN", detail: res.ok ? null : `HTTP ${res.status}`, latencyMs: Date.now() - started };
  } catch {
    return { status: "DOWN", detail: "Unreachable", latencyMs: null };
  }
}

/** Which delivery channels have credentials (values are never exposed) + the last delivery outcome. */
async function probeNotification(): Promise<{ status: HealthItem["status"]; detail: string | null; latencyMs: number | null }> {
  const channels = [
    ["email", emailAdapter.isConfigured()],
    ["discord", discordAdapter.isConfigured()],
    ["telegram", telegramAdapter.isConfigured()],
  ].filter(([, ok]) => ok).map(([name]) => name);
  if (!channels.length) return { status: "NOT_CONFIGURED", detail: "No delivery channel configured", latencyMs: null };
  const last = await prisma.notificationDelivery.findFirst({ orderBy: { createdAt: "desc" }, select: { status: true, createdAt: true } });
  const failed = last && /FAIL/i.test(last.status);
  return {
    status: failed ? "DEGRADED" : "UP",
    detail: `Channels: ${channels.join(", ")}${last ? ` · last delivery ${last.status} ${last.createdAt.toISOString()}` : " · no delivery yet"}`,
    latencyMs: null,
  };
}

/** Wazuh manager through its REST API (read-only): daemons VIGIX needs + agent summary. Unset WAZUH_API_* -> NOT_CONFIGURED. */
const wazuhManagerApi = wazuhManagerConfigFromEnv(process.env);
async function probeWazuhManager(): Promise<{ status: HealthItem["status"]; detail: string | null; latencyMs: number | null }> {
  return probeWazuhManagerApi(wazuhManagerApi);
}

export const dashboardController =
  new DashboardController(
    new GetDashboardSummaryUseCase(
      new PrismaDashboardReadRepository(prisma),
      incidentSlaService,
      rehuntProvider,
      process.env.REHUNT_PROVIDER === "mock" ? "mock" : "wazuh-indexer",
      probeAiOrchestrator,
      [
        { key: "ai-worker", label: "AI Worker", probe: probeAiWorker },
        { key: "qdrant", label: "Qdrant", probe: probeQdrant },
        { key: "notification", label: "Notification", probe: probeNotification },
        { key: "wazuh", label: "Wazuh Manager", probe: probeWazuhManager },
      ]
    )
  );

// Role workspaces (read-only): ticket / approval / incident queues, incident audit trail and AI jobs.
export const workQueries = new WorkQueries(new PrismaWorkReadRepository(prisma));

// Role-context incident email (SOC investigation / IR response) — same delivery path as IR email.
export const incidentContextEmailUseCase = new IncidentContextEmailUseCase(
  new PrismaIncidentEmailContextReader(prisma),
  irEmailService,
  auditLogger,
  vigixBaseUrl
);
