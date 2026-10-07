import { asyncHandler } from "../middlewares/async-handler.middleware";
import { Router } from "express";
import { PlaybookController } from "../controllers/PlaybookController";
import { PlaybookRevisionController } from "../controllers/PlaybookRevisionController";
import { authenticate, requireOperationalRole, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/playbooks. RBAC: SOC, IR_TEAM and admin manage playbooks (create / edit / activate / deactivate /
 * delete, audited with a copy);
 * every change is audited with the actor. Other Knowledge libraries (policies, actions, runbooks) stay admin-only.
 *
 * Versions (Phase 1D): create / edit a DRAFT follows the same management roles; publish and rollback are SOC and IR_TEAM
 * only (no admin stand-in, no approval step). Service tokens never reach these routes (authenticate rejects them).
 */
export function buildPlaybookRoutes(controller: PlaybookController, revisions?: PlaybookRevisionController): Router {
  const router = Router();
  router.get("/", authenticate, controller.list);
  router.get("/:id", authenticate, controller.getById);
  router.post("/", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.create));
  router.put("/:id", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.update));
  router.delete("/:id", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.remove));
  if (revisions) {
    router.get("/:id/revisions", authenticate, asyncHandler(revisions.list));
    router.post("/:id/revisions", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(revisions.create));
    router.put("/:id/revisions/:revisionId", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(revisions.update));
    router.post("/:id/revisions/:revisionId/publish", authenticate, requireOperationalRole("SOC", "IR_TEAM"), asyncHandler(revisions.publish));
    router.post("/:id/revisions/:revisionId/rollback", authenticate, requireOperationalRole("SOC", "IR_TEAM"), asyncHandler(revisions.rollback));
  }
  return router;
}
