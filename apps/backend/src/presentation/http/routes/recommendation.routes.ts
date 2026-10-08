import { asyncHandler } from "../middlewares/async-handler.middleware";
import { Router } from "express";
import { RecommendationController } from "../controllers/RecommendationController";
import { authenticate, requireOperationalRole, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/recommendations (see main.ts). RBAC foundation:
 * generate/validate require SOC or IR_TEAM (the investigation roles) — an
 * AI service has no token of its own and can never call these directly;
 * only a human-authenticated SOC/IR_TEAM session can trigger generation.
 */
export function buildRecommendationRoutes(controller: RecommendationController): Router {
  const router = Router();
  router.post("/generate", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.generate));
  // Recommendation Preview with SIMULATED data (RECOMMENDATION_PREVIEW_FIXTURES=true only); before "/:id" so it is not read as an id.
  router.get("/preview-fixtures", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.previewFixtures));
  router.get("/preview-fixtures/:fixtureId", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.previewFixture));
  router.get("/:id", authenticate, controller.getById);
  // Internal audit of the subtype-knowledge evaluation - never part of the user-facing recommendation.
  router.get("/:id/audit", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.getAudit));
  router.post("/:id/validate", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.validate));
  // SOC reviewed the recommendation -> Send to IR (tickets first, then the notification with the ticket links).
  router.post("/:id/send-to-ir", authenticate, requireOperationalRole("SOC"), asyncHandler(controller.sendToIr));
  // SOC Validation REJECT -> Close Incident.
  router.post("/:id/reject", authenticate, requireOperationalRole("SOC"), asyncHandler(controller.reject));
  return router;
}

/** Mounted at /api/incidents/:incidentId/recommendations (see main.ts). */
export function buildIncidentRecommendationRoutes(controller: RecommendationController): Router {
  const router = Router({ mergeParams: true });
  router.get("/", authenticate, controller.listByIncident);
  // Recommendation Preview (subtype knowledge): read-only, never persisted, never sent to IR.
  router.get("/preview", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.preview));
  return router;
}
