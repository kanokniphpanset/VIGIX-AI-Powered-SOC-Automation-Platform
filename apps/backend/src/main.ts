import "reflect-metadata";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

import {
  alertController,
  incidentController,
  policyController,
  policyEvaluationController,
  actionController,
  runbookController,
  mitreController,
  playbookController,
  playbookRevisionController,
  recommendationController,
  authController,
  approvalController,
  responseController,
  verificationController,
  siemWebhookController,
  orchestratorCallbackController,
  knowledgeSearchController,
  notificationTestController,
  irHandoffController,
  investigationController,
  listRelatedAlertEvidenceUseCase,
  dashboardController,
  settingsController,
  inAppNotificationController,
  irEmailController,
  socTriageController,
  setAlertScenarioUseCase,
  runIncidentAiAnalysisUseCase,
  aiAnalysisWorker,
  returnDueMonitoredAlertsUseCase,
  workQueries,
  incidentContextEmailUseCase,
} from "./infrastructure/config/container";
import { buildDashboardRoutes } from "./presentation/http/routes/dashboard.routes";
import { buildKnowledgeRoutes } from "./presentation/http/routes/knowledge.routes";
import { buildAuthRoutes } from "./presentation/http/routes/auth.routes";
import { buildApprovalRoutes, buildRecommendationApprovalRoutes } from "./presentation/http/routes/approval.routes";
import { buildResponseRoutes } from "./presentation/http/routes/response.routes";
import { buildVerificationRoutes, buildIncidentVerificationRoutes } from "./presentation/http/routes/verification.routes";
import { buildAlertRoutes } from "./presentation/http/routes/alert.routes";
import { buildIncidentRoutes } from "./presentation/http/routes/incident.routes";
import { buildPolicyRoutes } from "./presentation/http/routes/policy.routes";
import { buildActionRoutes } from "./presentation/http/routes/action.routes";
import { buildRunbookRoutes } from "./presentation/http/routes/runbook.routes";
import { buildMitreRoutes } from "./presentation/http/routes/mitre.routes";
import { buildPlaybookRoutes } from "./presentation/http/routes/playbook.routes";
import { buildRecommendationRoutes, buildIncidentRecommendationRoutes } from "./presentation/http/routes/recommendation.routes";
import { buildWebhookRoutes } from "./presentation/http/routes/webhook.routes";
import { buildInvestigationRoutes, buildIncidentInvestigationRoutes, buildEvidenceRoutes, buildRelatedAlertEvidenceRoutes } from "./presentation/http/routes/investigation.routes";
import { buildNotificationRoutes } from "./presentation/http/routes/notification.routes";
import { buildSettingsRoutes } from "./presentation/http/routes/settings.routes";
import { buildInAppNotificationRoutes } from "./presentation/http/routes/in-app-notification.routes";
import { buildIrEmailRoutes } from "./presentation/http/routes/ir-email.routes";
import { buildSocTriageRoutes } from "./presentation/http/routes/soc-triage.routes";
import { buildAlertScenarioRoutes } from "./presentation/http/routes/alert-scenario.routes";
import { buildAiAnalysisRoutes } from "./presentation/http/routes/ai-analysis.routes";
import { buildWorkRoutes, buildIncidentWorkRoutes } from "./presentation/http/routes/work.routes";
import { buildIncidentEmailRoutes } from "./presentation/http/routes/incident-email.routes";
import { errorHandler } from "./presentation/http/middlewares/error-handler.middleware";
import { keepRawBody } from "./presentation/http/middlewares/webhookAuth.middleware";

const app = express();
app.use(cors());
// keepRawBody: the SIEM webhook verifies its HMAC signature over the exact bytes received.
app.use(express.json({ verify: keepRawBody }));

app.use("/api/auth", buildAuthRoutes(authController));
app.use("/api/v1/dashboard", buildDashboardRoutes(dashboardController));
// Before the alert router: "/scenarios" must not be read as an alert id.
app.use("/api/v1/alerts", buildAlertScenarioRoutes(setAlertScenarioUseCase));
app.use("/api/v1/alerts", buildAlertRoutes(alertController));
app.use("/api/v1/incidents", buildIncidentWorkRoutes(workQueries));
app.use("/api/v1/incidents", buildIncidentEmailRoutes(incidentContextEmailUseCase));
app.use("/api/v1/incidents", buildIncidentRoutes(incidentController));
app.use("/api/v1/work", buildWorkRoutes(workQueries));
// POST /api/v1/incidents/:incidentId/ai-analysis/run (path not used by the incident router).
app.use("/api/v1/incidents", buildAiAnalysisRoutes(runIncidentAiAnalysisUseCase));
app.use("/api/v1/incidents/:incidentId/investigations", buildIncidentInvestigationRoutes(investigationController));
app.use("/api/v1/incidents/:incidentId/related-alert-evidence", buildRelatedAlertEvidenceRoutes(listRelatedAlertEvidenceUseCase));
app.use("/api/v1/investigations", buildInvestigationRoutes(investigationController));
app.use("/api/v1/evidence", buildEvidenceRoutes(investigationController));
app.use("/api/policies", buildPolicyRoutes(policyController, policyEvaluationController));
app.use("/api/actions", buildActionRoutes(actionController));
app.use("/api/runbooks", buildRunbookRoutes(runbookController));
app.use("/api/playbooks", buildPlaybookRoutes(playbookController, playbookRevisionController));
app.use("/api/recommendations", buildRecommendationRoutes(recommendationController));
// Spec-literal path (distinct prefix from the legacy /api/v1/incidents mount above —
// versioning is already inconsistent across this codebase; not introduced here).
app.use("/api/incidents/:incidentId/recommendations", buildIncidentRecommendationRoutes(recommendationController));
app.use("/api/approvals", buildApprovalRoutes(approvalController));
app.use("/api/recommendations/:id/approvals", buildRecommendationApprovalRoutes(approvalController));
app.use("/api/responses", buildResponseRoutes(responseController));
app.use("/api/verifications", buildVerificationRoutes(verificationController));
app.use("/api/incidents/:incidentId/verifications", buildIncidentVerificationRoutes(verificationController));
app.use("/api/v1/webhooks", buildWebhookRoutes(siemWebhookController, orchestratorCallbackController));
app.use("/api/v1/knowledge", buildKnowledgeRoutes(knowledgeSearchController));
app.use("/api/v1/mitre", buildMitreRoutes(mitreController));
app.use("/api/notifications", buildNotificationRoutes(notificationTestController, irHandoffController));
app.use("/api/v1/settings", buildSettingsRoutes(settingsController));
app.use("/api/v1/notifications", buildInAppNotificationRoutes(inAppNotificationController));
// Article / response-guide emails to IR (paths not used by the knowledge or incident routers above).
app.use("/api/v1", buildIrEmailRoutes(irEmailController));
app.use("/api/v1", buildSocTriageRoutes(socTriageController));

app.get("/api/v1/health", (_req, res) => {
  res.json({ status: "ok", service: "soar-backend", timestamp: new Date().toISOString() });
});

app.use(errorHandler);

const PORT = process.env.BACKEND_PORT ? Number(process.env.BACKEND_PORT) : 4000;

app.listen(PORT, () => {
  console.log(`soar-backend listening on http://localhost:${PORT}`);
  // Pipeline A: background AI analysis worker (DB queue on agent_executions). AI_WORKER_ENABLED=false disables it.
  if (process.env.AI_WORKER_ENABLED !== "false") {
    aiAnalysisWorker
      .start()
      .then(() => console.log("[ai-worker] started"))
      .catch((err) => console.error("[ai-worker] failed to start", err instanceof Error ? err.message : err));
  }
  // Alert Inbox: monitored alerts whose review date passed go back to the triage queue (idempotent, one run at a time).
  // MONITOR_REVIEW_CHECK_MS=0 disables it.
  const reviewEveryMs = Number(process.env.MONITOR_REVIEW_CHECK_MS ?? 60_000);
  if (reviewEveryMs > 0) {
    let running = false;
    const checkReviews = async () => {
      if (running) return;
      running = true;
      try {
        const { returned } = await returnDueMonitoredAlertsUseCase.execute();
        if (returned.length) console.log(`[alert-review] ${returned.length} monitored alert(s) due for review returned to triage`);
      } catch (err) {
        console.error("[alert-review] check failed", err instanceof Error ? err.message : err);
      } finally {
        running = false;
      }
    };
    void checkReviews();
    setInterval(() => void checkReviews(), reviewEveryMs).unref();
  }
});
