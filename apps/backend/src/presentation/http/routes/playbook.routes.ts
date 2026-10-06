import { asyncHandler } from "../middlewares/async-handler.middleware";
import { Router } from "express";
import { PlaybookController } from "../controllers/PlaybookController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/playbooks. RBAC: SOC, IR_TEAM and admin manage playbooks (create / edit / activate / deactivate /
 * delete, audited with a copy);
 * every change is audited with the actor. Other Knowledge libraries (policies, actions, runbooks) stay admin-only.
 */
export function buildPlaybookRoutes(controller: PlaybookController): Router {
  const router = Router();
  router.get("/", authenticate, controller.list);
  router.get("/:id", authenticate, controller.getById);
  router.post("/", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.create));
  router.put("/:id", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.update));
  router.delete("/:id", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.remove));
  return router;
}
