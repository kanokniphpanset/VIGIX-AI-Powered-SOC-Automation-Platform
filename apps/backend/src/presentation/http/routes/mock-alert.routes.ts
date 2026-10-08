import { Request, Response, Router } from "express";
import { authenticate, requireRole } from "../middlewares/auth.middleware";
import { isMockAlertKey } from "../../../domain/alert/mockAlerts";
import { IMockAlertCatalog } from "../../../infrastructure/mock-alerts/FileMockAlertCatalog";
import { SendMockAlertUseCase } from "../../../application/alert/use-cases/SendMockAlert.usecase";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

/** Sending test data into the Alert Inbox is a SOC (lab) action; admin passes every gate. */
export const MOCK_ALERT_SENDER_ROLES = ["SOC"] as const;

/**
 * Mock alerts are lab / test tooling: on unless MOCK_ALERTS_ENABLED=false, and off by default in production
 * (NODE_ENV=production) unless MOCK_ALERTS_ENABLED=true. The catalog (GET) stays readable so the inbox filter works.
 */
export const mockAlertSendingEnabled = (env: NodeJS.ProcessEnv = process.env) =>
  env.MOCK_ALERTS_ENABLED === "true" || (env.MOCK_ALERTS_ENABLED !== "false" && env.NODE_ENV !== "production");

/**
 * Mounted at /api/v1/alerts BEFORE the alert router (so "/mock" is never read as an alert id).
 *   GET  /mock             — the fixture catalog (no payloads) + whether sending is enabled
 *   POST /mock/:key/send   — send one fixture through the normal Wazuh ingestion path (SOC)
 */
export function buildMockAlertRoutes(catalog: IMockAlertCatalog, send: SendMockAlertUseCase, enabled = mockAlertSendingEnabled()): Router {
  const router = Router();
  router.get("/mock", authenticate, (_req: Request, res: Response) => {
    res.json({ sendEnabled: enabled, items: catalog.list().map(({ alert: _payload, ...c }) => c) });
  });
  router.post("/mock/:key/send", authenticate, requireRole(...MOCK_ALERT_SENDER_ROLES), async (req: Request, res: Response) => {
    if (!enabled) {
      res.status(403).json({ error: "MOCK_ALERTS_DISABLED" });
      return;
    }
    const key = req.params.key.toUpperCase();
    if (!isMockAlertKey(key)) {
      res.status(404).json({ error: "UNKNOWN_MOCK_ALERT" });
      return;
    }
    try {
      const result = await send.execute({ tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID, key, actor: req.user!.id });
      if (result.isFailure) {
        res.status(result.error === "UNKNOWN_MOCK_ALERT" ? 404 : 422).json({ error: result.error });
        return;
      }
      res.status(201).json(result.value);
    } catch (e) {
      console.error("[mock-alerts] send failed", e instanceof Error ? e.message : e);
      res.status(500).json({ error: "MOCK_ALERT_SEND_FAILED" });
    }
  });
  return router;
}
