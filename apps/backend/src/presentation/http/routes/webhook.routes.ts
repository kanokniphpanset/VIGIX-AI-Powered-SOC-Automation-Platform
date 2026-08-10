import { Router } from "express";
import { SiemInboundWebhookController } from "../webhooks/siem-inbound.webhook";

export function buildWebhookRoutes(siemWebhookController: SiemInboundWebhookController): Router {
  const router = Router();

  // Wazuh, Splunk, Defender, and ELK all POST here, differentiated by :source.
  // e.g. POST /api/v1/webhooks/siem/wazuh
  router.post("/siem/:source", siemWebhookController.handle);

  return router;
}
