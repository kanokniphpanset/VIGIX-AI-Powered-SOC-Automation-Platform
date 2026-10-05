import { Router } from "express";
import { PolicyController } from "../controllers/PolicyController";
import { PolicyEvaluationController } from "../controllers/PolicyEvaluationController";
import { authenticate, requireAdmin, requireRole } from "../middlewares/auth.middleware";

/** Roles that may READ Policy (list / get / evaluate). admin always passes (requireRole super-role). */
export const POLICY_READ_ROLES = ["SOC", "IR_TEAM"] as const;

/**
 * Mounted at /api/policies (see main.ts). Policy rules are organizational security configuration: nothing here is
 * public. Every route requires a valid JWT (401 without one). Reads (list / get / evaluate) are for the operational
 * roles SOC and IR_TEAM (+ admin) — any other role gets 403; create and delete are open to SOC / IR_TEAM (+ admin) and
 * audited with the actor (delete with a copy of the policy); edit / enable / disable remain admin-only. evaluate stays read-only /
 * non-mutating by construction (see PolicyEvaluator.ts).
 */
export function buildPolicyRoutes(controller: PolicyController, evaluationController: PolicyEvaluationController): Router {
  const router = Router();

  const canRead = [authenticate, requireRole(...POLICY_READ_ROLES)];
  router.post("/evaluate", ...canRead, evaluationController.evaluate);

  router.get("/", ...canRead, controller.list);
  router.get("/:id", ...canRead, controller.getById);
  // Create (Knowledge → Policies → Add): SOC / IR_TEAM / admin; audited with the signed-in actor.
  router.post("/", authenticate, requireRole(...POLICY_READ_ROLES), controller.create);
  router.put("/:id", authenticate, requireAdmin(), controller.update);
  router.patch("/:id/enable", authenticate, requireAdmin(), controller.enable);
  router.patch("/:id/disable", authenticate, requireAdmin(), controller.disable);
  // Delete: SOC / IR_TEAM / admin; confirmation in the UI, audited with a full copy of the policy (DELETE_POLICY).
  router.delete("/:id", authenticate, requireRole("SOC", "IR_TEAM"), controller.remove);

  return router;
}
