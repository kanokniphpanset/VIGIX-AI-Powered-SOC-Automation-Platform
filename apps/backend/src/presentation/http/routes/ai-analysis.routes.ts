import { Request, Response, Router } from "express";
import { authenticate, requireRole } from "../middlewares/auth.middleware";
import { RunIncidentAiAnalysisUseCase } from "../../../application/incident/use-cases/RunIncidentAiAnalysis.usecase";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

/** Who may run the AI analysis for an incident — the roles that already work the investigation (generate recommendations). */
export const AI_ANALYSIS_RUN_ROLES = ["SOC", "IR_TEAM"] as const;

const STATUS: Record<string, number> = {
  INCIDENT_NOT_FOUND: 404,
  INCIDENT_HAS_NO_ALERT: 422,
  ALERT_OWNED_BY_OTHER_INCIDENT: 409,
  ANALYSIS_IN_PROGRESS: 409,
  AI_UNAVAILABLE: 503,
  AI_FAILED: 502,
  AI_ANALYSIS_FAILED: 502,
};

/** Mounted at /api/v1/incidents. POST /:incidentId/ai-analysis/run — Run / Re-run AI Analysis (existing pipeline). */
export function buildAiAnalysisRoutes(runAnalysis: RunIncidentAiAnalysisUseCase): Router {
  const router = Router();
  router.post("/:incidentId/ai-analysis/run", authenticate, requireRole(...AI_ANALYSIS_RUN_ROLES), async (req: Request, res: Response) => {
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await runAnalysis.execute({ tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.incidentId, actor: req.user.id });
    if (result.isFailure) {
      res.status(STATUS[result.error] ?? 400).json({ error: result.error });
      return;
    }
    res.json(result.value);
  });
  return router;
}
