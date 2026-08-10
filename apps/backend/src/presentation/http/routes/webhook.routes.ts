import { Router } from "express";
import { SiemInboundWebhookController } from "../webhooks/siem-inbound.webhook";
import { OrchestratorCallbackController } from "../webhooks/orchestrator-callback.webhook";

export function buildWebhookRoutes(
  siemWebhookController: SiemInboundWebhookController,
  orchestratorCallbackController: OrchestratorCallbackController
): Router {
  const router = Router();

  // Wazuh, Splunk, Defender, and ELK all POST here, differentiated by :source.
  // e.g. POST /api/v1/webhooks/siem/wazuh
  router.post("/siem/:source", siemWebhookController.handle);

  // The AI orchestrator (apps/ai-orchestrator) calls this after a pipeline run
  // completes, to trigger the appropriate n8n playbook.
  router.post("/orchestrator/callback", orchestratorCallbackController.handle);

  return router;
}
