import { prisma } from "../database/postgres/client";

// Repositories (infrastructure implements domain ports)
import { PrismaAlertRepository } from "../database/postgres/repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "../database/postgres/repositories/IncidentRepository.prisma";

// SIEM adapters (infrastructure implements ISiemAdapter per vendor)
import { WazuhAdapter } from "../external-services/siem/WazuhAdapter";
import { SplunkAdapter } from "../external-services/siem/SplunkAdapter";
import { DefenderAdapter } from "../external-services/siem/DefenderAdapter";
import { ElkAdapter } from "../external-services/siem/ElkAdapter";
import { SiemSource } from "../../domain/alert/entities/Alert.entity";
import { ISiemAdapter } from "../external-services/siem/ISiemAdapter";

// AI orchestrator adapter (infrastructure implements IAiOrchestratorPort)
import { LangGraphOrchestratorAdapter } from "../ai/LangGraphOrchestratorAdapter";

// Use-cases (application layer, depends only on the ports)
import { ListAlertsUseCase } from "../../application/alert/use-cases/ListAlerts.usecase";
import { GetAlertByIdUseCase } from "../../application/alert/use-cases/GetAlertById.usecase";
import { IngestAlertFromSiemUseCase } from "../../application/alert/use-cases/IngestAlertFromSiem.usecase";
import { ListIncidentsUseCase } from "../../application/incident/use-cases/ListIncidents.usecase";
import { GetIncidentByIdUseCase } from "../../application/incident/use-cases/GetIncidentById.usecase";
import { GetIncidentTimelineUseCase } from "../../application/incident/use-cases/GetIncidentTimeline.usecase";
import { UpdateIncidentStatusUseCase } from "../../application/incident/use-cases/UpdateIncidentStatus.usecase";

// Controllers (presentation layer)
import { AlertController } from "../../presentation/http/controllers/AlertController";
import { IncidentController } from "../../presentation/http/controllers/IncidentController";
import { SiemInboundWebhookController } from "../../presentation/http/webhooks/siem-inbound.webhook";

/**
 * container.ts — composition root.
 * This is the ONLY file in the codebase allowed to know about every layer at once.
 * Everything upstream (domain, application) stays ignorant of how it's wired together.
 * Swap PrismaAlertRepository, a SIEM adapter, or the orchestrator adapter here —
 * nothing else in the codebase changes.
 */

// Repositories
const alertRepository = new PrismaAlertRepository(prisma);
const incidentRepository = new PrismaIncidentRepository(prisma);

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

// Use-cases
const listAlertsUseCase = new ListAlertsUseCase(alertRepository);
const getAlertByIdUseCase = new GetAlertByIdUseCase(alertRepository);
const ingestAlertFromSiemUseCase = new IngestAlertFromSiemUseCase(alertRepository, aiOrchestrator);

const listIncidentsUseCase = new ListIncidentsUseCase(incidentRepository);
const getIncidentByIdUseCase = new GetIncidentByIdUseCase(incidentRepository);
const getIncidentTimelineUseCase = new GetIncidentTimelineUseCase(incidentRepository);
const updateIncidentStatusUseCase = new UpdateIncidentStatusUseCase(incidentRepository);

// Controllers
export const alertController = new AlertController(listAlertsUseCase, getAlertByIdUseCase);
export const incidentController = new IncidentController(
  listIncidentsUseCase,
  getIncidentByIdUseCase,
  getIncidentTimelineUseCase,
  updateIncidentStatusUseCase
);
export const siemWebhookController = new SiemInboundWebhookController(
  ingestAlertFromSiemUseCase,
  siemAdapters
);

