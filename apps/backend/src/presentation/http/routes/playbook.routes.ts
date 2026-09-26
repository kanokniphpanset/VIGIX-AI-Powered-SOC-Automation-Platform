import { Router } from "express";
import { PlaybookController } from "../controllers/PlaybookController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/playbooks. RBAC: SOC, IR_TEAM and admin manage playbooks (create / edit / activate / deactivate /
 * delete — a reason is required to delete);
 * every change is audited with the actor. Other Knowledge libraries (policies, actions, runbooks) stay admin-only.
 */
export function buildPlaybookRoutes(controller: PlaybookController): Router {
  const router = Router();
  router.get("/", controller.list);
  router.get("/:id", controller.getById);
  router.post("/", authenticate, requireRole("SOC", "IR_TEAM"), controller.create);
  router.put("/:id", authenticate, requireRole("SOC", "IR_TEAM"), controller.update);
  router.delete("/:id", authenticate, requireRole("SOC", "IR_TEAM"), controller.remove);
  return router;
}
