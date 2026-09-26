
import { Router } from "express";
import { VerificationController } from "../controllers/VerificationController";
import { authenticate, requireOperationalRole, requireRole } from "../middlewares/auth.middleware";

/** Mounted at /api/verifications (direct lookup by id). */
export function buildVerificationRoutes(
  controller: VerificationController
): Router {
  const router = Router();

  router.get("/", authenticate, controller.list);

  router.get(
    "/rehunt-health",
    authenticate,
    requireRole("SOC", "IR_TEAM"),
    controller.rehuntHealth
  );

  router.get("/:id", authenticate, controller.getById);

  return router;
}

/**
 * Mounted at /api/incidents/:incidentId/verifications.
 * RBAC: recording a Wazuh re-hunt verification requires IR_TEAM
 * (the team that performed the containment is also who confirms it worked).
 */
export function buildIncidentVerificationRoutes(
  controller: VerificationController
): Router {
  const router = Router({ mergeParams: true });

  router.post(
    "/",
    authenticate,
    requireOperationalRole("IR_TEAM"),
    controller.create
  );

  router.post(
    "/rehunt",
    authenticate,
    requireOperationalRole("IR_TEAM"),
    controller.rehunt
  );

  router.get(
    "/",
    authenticate,
    controller.listByIncident
  );

  return router;
}
