import { Router } from "express";
import { RunbookController } from "../controllers/RunbookController";
import { authenticate, requireAdmin } from "../middlewares/auth.middleware";

/** Mounted at /api/runbooks. RBAC: catalog mutations are configuration — admin only (SOC / IR_TEAM read). */
export function buildRunbookRoutes(controller: RunbookController): Router {
  const router = Router();
  router.get("/", controller.list);
  router.get("/:id", controller.getById);
  router.post("/", authenticate, requireAdmin(), controller.create);
  router.put("/:id", authenticate, requireAdmin(), controller.update);
  return router;
}
