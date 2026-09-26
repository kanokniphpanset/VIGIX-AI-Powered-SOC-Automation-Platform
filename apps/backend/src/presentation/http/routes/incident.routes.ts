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
  router.post("/", authenticate, requireRole("SOC"), controller.create);
  router.get("/:id", authenticate, controller.getById);
  router.get("/:id/timeline", authenticate, controller.getTimeline);
  router.get("/:id/alerts", authenticate, controller.getAlerts);
  // Set Group (analyst correlation) is a SOC action, like creating an incident from alerts.
  router.post("/:id/alerts", authenticate, requireRole("SOC"), controller.addAlerts);
  router.get("/:id/iocs", authenticate, controller.getIocs);
  router.get("/:id/mitre-mappings", authenticate, controller.getMitreMappings);
  router.get("/:id/ai-analysis", authenticate, controller.getAiAnalysis);
  router.get("/:id/sla", authenticate, controller.getSla);
  router.patch("/:id/status", authenticate, requireRole("SOC", "IR_TEAM"), controller.updateStatus);

  return router;
}
