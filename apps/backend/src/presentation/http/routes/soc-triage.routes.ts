import { Router } from "express";
import { SocTriageController } from "../controllers/SocTriageController";
import { authenticate, requireOperationalRole, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/v1. SOC owns alert review, the incident notification choice and the incident severity validation
 * (from the Wazuh rule severity). "admin" passes every requireRole() check. AI has no token for any of these.
 */
export function buildSocTriageRoutes(controller: SocTriageController): Router {
  const router = Router();
  // Alert review is SOC work (admin is a system role and does not triage). No claim: any SOC analyst decides an open alert.
  router.post("/alerts/:id/triage", authenticate, requireOperationalRole("SOC"), controller.triage);
  router.post("/incidents/:id/notification-decision", authenticate, requireRole("SOC"), controller.notificationDecision);
  // SOC severity validation (confirm the Wazuh-rule severity, or correct it with a reason). AI never sets it.
  router.post("/incidents/:id/severity-validation", authenticate, requireRole("SOC"), controller.severityValidation);
  router.get("/incidents/:id/severity", authenticate, controller.severity);
  return router;
}
