import { Request, Response, Router } from "express";
import { z } from "zod";
import { authenticate, requireRole } from "../middlewares/auth.middleware";
import { ATTACK_SCENARIOS } from "../../../domain/alert/attackScenarios";
import { SetAlertScenarioUseCase } from "../../../application/alert/use-cases/AlertScenario.usecases";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
const setSchema = z.object({ scenarioId: z.string().max(20).nullable() }).strict();

/** Labelling alerts is a triage action — the same role that triages the Alert Inbox (admin passes every gate). */
export const ALERT_SCENARIO_EDITOR_ROLES = ["SOC"] as const;

/**
 * Mounted at /api/v1/alerts BEFORE the alert router (so "/scenarios" is never read as an alert id).
 * GET /scenarios — the scenario catalog (read-only); PUT /:id/scenario — label an alert (null removes the label).
 */
export function buildAlertScenarioRoutes(setScenario: SetAlertScenarioUseCase): Router {
  const router = Router();
  router.get("/scenarios", authenticate, (_req: Request, res: Response) => {
    res.json({ items: ATTACK_SCENARIOS });
  });
  router.put("/:id/scenario", authenticate, requireRole(...ALERT_SCENARIO_EDITOR_ROLES), async (req: Request, res: Response) => {
    const body = validateBody(setSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await setScenario.execute({ tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID, alertId: req.params.id, scenarioId: body.scenarioId, actor: req.user.id });
    if (result.isFailure) {
      res.status(result.error === "ALERT_NOT_FOUND" ? 404 : 400).json({ error: result.error });
      return;
    }
    res.json(result.value);
  });
  return router;
}
