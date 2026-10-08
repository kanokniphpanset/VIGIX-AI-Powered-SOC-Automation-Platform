import { Router } from "express";
import { ActionController } from "../controllers/ActionController";
import { authenticate, requireAdmin, requireRole } from "../middlewares/auth.middleware";

/** Mounted at /api/actions. SOC / IR_TEAM / admin create and edit; enable/disable remains admin only. */
export function buildActionRoutes(controller: ActionController): Router {
  const router = Router();
  router.get("/", authenticate, controller.list);
  router.get("/:id", authenticate, controller.getById);
  router.post("/", authenticate, requireRole("SOC", "IR_TEAM"), controller.create);
  router.put("/:id", authenticate, requireRole("SOC", "IR_TEAM"), controller.update);
  router.patch("/:id/enable", authenticate, requireAdmin(), controller.enable);
  router.patch("/:id/disable", authenticate, requireAdmin(), controller.disable);
  return router;
}
