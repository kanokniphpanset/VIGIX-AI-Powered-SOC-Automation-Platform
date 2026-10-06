import { asyncHandler } from "../middlewares/async-handler.middleware";
import { Router } from "express";
import { IncidentController } from "../controllers/IncidentController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/v1/incidents. RBAC foundation: read access requires any
 * authenticated user; the status mutation additionally requires an
 * operational role (SOC drives investigation, IR_TEAM drives response;
 * "admin" always passes per requireRole's super-role rule).
 */
export function buildIncidentRoutes(controller: IncidentController): Router {
  const router = Router();

  router.get("/", authenticate, controller.list);
  // Grouping alerts into a new Incident is the SOC analyst's action (admin passes as super-role).
  router.post("/", authenticate, requireRole("SOC"), asyncHandler(controller.create));
  router.get("/:id", authenticate, controller.getById);
  router.get("/:id/timeline", authenticate, controller.getTimeline);
  router.get("/:id/alerts", authenticate, controller.getAlerts);
  router.get("/:id/alert-facts", authenticate, controller.getAlertFacts);
  // Set Group (analyst correlation) is a SOC action, like creating an incident from alerts.
  router.post("/:id/alerts", authenticate, requireRole("SOC"), asyncHandler(controller.addAlerts));
  router.get("/:id/iocs", authenticate, controller.getIocs);
  router.get("/:id/mitre-mappings", authenticate, controller.getMitreMappings);
  router.get("/:id/ai-analysis", authenticate, controller.getAiAnalysis);
  router.get("/:id/sla", authenticate, controller.getSla);
  // SOC response setup before a Recommendation: incident type, case guidance, group (RESPONSE_GUIDANCE) policy.
  router.get("/:id/response-setup", authenticate, controller.getResponseSetup);
  router.put("/:id/incident-type", authenticate, requireRole("SOC"), asyncHandler(controller.setIncidentType));
  router.put("/:id/response-guidance", authenticate, requireRole("SOC"), asyncHandler(controller.setCaseGuidance));
  router.delete("/:id/response-guidance", authenticate, requireRole("SOC"), asyncHandler(controller.clearCaseGuidance));
  router.put("/:id/response-guidance/group", authenticate, requireRole("SOC"), controller.saveGroupGuidance);
  router.patch("/:id/status", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.updateStatus));

  return router;
}
