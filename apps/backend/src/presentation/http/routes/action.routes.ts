import { Router } from "express";
import { ActionController } from "../controllers/ActionController";
import { authenticate, requireAdmin } from "../middlewares/auth.middleware";

/** Mounted at /api/actions. RBAC: catalog mutations are configuration — admin only (SOC / IR_TEAM read). */
export function buildActionRoutes(controller: ActionController): Router {
  const router = Router();
  router.get("/", authenticate, controller.list);
  router.get("/:id", authenticate, controller.getById);
  router.post("/", authenticate, requireAdmin(), controller.create);
  router.put("/:id", authenticate, requireAdmin(), controller.update);
  router.patch("/:id/enable", authenticate, requireAdmin(), controller.enable);
  router.patch("/:id/disable", authenticate, requireAdmin(), controller.disable);
  return router;
}
