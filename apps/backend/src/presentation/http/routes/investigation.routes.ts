import { Router } from "express";
import { InvestigationController } from "../controllers/InvestigationController";
import { Request, Response } from "express";
import { authenticate, requireRole } from "../middlewares/auth.middleware";
import { ListRelatedAlertEvidenceUseCase } from "../../../application/investigation/use-cases/RelatedAlertEvidence.usecase";

/**
 * Reads need any authenticated user. Recording evidence or an IOC is investigative
 * work, so it needs SOC or IR_TEAM (admin passes as super-role), matching who may already generate recommendations.
 */

/** Mounted at /api/v1/investigations. */
export function buildInvestigationRoutes(controller: InvestigationController): Router {
  const router = Router();
  router.get("/:investigationId", authenticate, controller.getById);
  router.get("/:investigationId/evidence", authenticate, controller.evidenceList);
  router.post("/:investigationId/evidence", authenticate, requireRole("SOC", "IR_TEAM"), controller.evidenceCreate);
  router.get("/:investigationId/iocs", authenticate, controller.iocList);
  router.post("/:investigationId/iocs", authenticate, requireRole("SOC", "IR_TEAM"), controller.iocCreate);
  return router;
}

/** Mounted at /api/v1/incidents/:incidentId/investigations. */
export function buildIncidentInvestigationRoutes(controller: InvestigationController): Router {
  const router = Router({ mergeParams: true });
  router.get("/", authenticate, controller.listForIncident);
  return router;
}

/**
 * Mounted at /api/v1/incidents/:incidentId/related-alert-evidence — READ ONLY list of other Wazuh alerts (same host /
 * shared indicator) whose indicators the SOC may record on this incident with sourceAlertId + reason. Groups nothing.
 */
export function buildRelatedAlertEvidenceRoutes(useCase: ListRelatedAlertEvidenceUseCase): Router {
  const router = Router({ mergeParams: true });
  router.get("/", authenticate, requireRole("SOC", "IR_TEAM"), async (req: Request, res: Response) => {
    const r = await useCase.execute({ tenantId: req.user?.tenantId ?? "00000000-0000-0000-0000-000000000001", incidentId: req.params.incidentId });
    if (r.isFailure) return void res.status(404).json({ error: r.error });
    res.json(r.value);
  });
  return router;
}

/** Mounted at /api/v1/evidence. */
export function buildEvidenceRoutes(controller: InvestigationController): Router {
  const router = Router();
  router.get("/:evidenceId", authenticate, controller.evidenceById);
  return router;
}
