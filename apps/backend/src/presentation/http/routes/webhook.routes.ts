import { asyncHandler } from "../middlewares/async-handler.middleware";
import { Router } from "express";
import { SiemInboundWebhookController } from "../webhooks/siem-inbound.webhook";
import { OrchestratorCallbackController } from "../webhooks/orchestrator-callback.webhook";
import { webhookAuth } from "../middlewares/webhookAuth.middleware";
import { authenticateService } from "../middlewares/auth.middleware";

export function buildWebhookRoutes(
  siemWebhookController: SiemInboundWebhookController,
  orchestratorCallbackController: OrchestratorCallbackController
): Router {
  const router = Router();

  // Wazuh, Splunk, Defender, and ELK all POST here, differentiated by :source.
  // e.g. POST /api/v1/webhooks/siem/wazuh — the Wazuh manager calls this itself (infra/wazuh-integration).
  // Signed with SIEM_WEBHOOK_SECRET (X-Webhook-Signature: sha256=<hmac of body>); unsigned alerts get 401.
  router.post("/siem/:source", webhookAuth, asyncHandler(siemWebhookController.handle));

  // Advisory callback only; signed service identity and explicit job grant are required.
  router.post("/orchestrator/callback", authenticateService("orchestrator:callback"), orchestratorCallbackController.handle);

  return router;
}
