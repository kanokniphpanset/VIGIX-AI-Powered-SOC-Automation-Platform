import { Router } from "express";
import { ActionController } from "../controllers/ActionController";
import { authenticate, requireAdmin, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/actions. RBAC: adding an action (Knowledge → Actions → Add) is open to SOC / IR_TEAM (+ admin), like
 * playbooks, and audited as CREATE_ACTION with the actor. Editing / enabling / disabling existing entries stays admin-only.
 */
export function buildActionRoutes(controller: ActionController): Router {
  const router = Router();
  router.get("/", controller.list);
  router.get("/:id", controller.getById);
  router.post("/", authenticate, requireRole("SOC", "IR_TEAM"), controller.create);
  router.put("/:id", authenticate, requireAdmin(), controller.update);
  router.patch("/:id/enable", authenticate, requireAdmin(), controller.enable);
  router.patch("/:id/disable", authenticate, requireAdmin(), controller.disable);
  return router;
}
