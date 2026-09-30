import { Router } from "express";
import { ResponseController } from "../controllers/ResponseController";
import { authenticate, requireOperationalRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/responses. RBAC: creating a ticket (Send to IR for one step) is SOC work; start/complete/fail (the
 * manual-execution lifecycle, only after the IR APPROVE) require IR_TEAM — "IR Team executes manually".
 */
export function buildResponseRoutes(controller: ResponseController): Router {
  const router = Router();
  router.get("/", authenticate, controller.list);
  router.post("/", authenticate, requireOperationalRole("SOC"), controller.create);
  router.get("/:id", authenticate, controller.getById);
  // IR Decision REJECT -> Manual Decision: IR approves its own manual response -> READY_FOR_EXECUTION.
  router.post("/:id/manual-decision", authenticate, requireOperationalRole("IR_TEAM"), controller.decideManually);
  router.post("/:id/start", authenticate, requireOperationalRole("IR_TEAM"), controller.start);
  router.post("/:id/complete", authenticate, requireOperationalRole("IR_TEAM"), controller.complete);
  router.post("/:id/fail", authenticate, requireOperationalRole("IR_TEAM"), controller.fail);
  return router;
}
