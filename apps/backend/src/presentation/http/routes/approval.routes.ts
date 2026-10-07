import { asyncHandler } from "../middlewares/async-handler.middleware";
import { Router } from "express";
import { ApprovalController } from "../controllers/ApprovalController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";

/**
 * Mounted at /api/approvals. The IR decision on a Response Ticket: APPROVE or REJECT (note mandatory), IR_TEAM only —
 * DecideApprovalUseCase additionally enforces the approval's role and audits a denied admin attempt. Re-opening a
 * missing IR decision for a ticket (/request) is SOC / IR_TEAM.
 */
export function buildApprovalRoutes(controller: ApprovalController): Router {
  const router = Router();
  router.post("/request", authenticate, requireRole("SOC", "IR_TEAM"), asyncHandler(controller.request));
  router.get("/:id", authenticate, controller.getById);
  router.post("/:id/approve", authenticate, requireRole("IR_TEAM"), asyncHandler(controller.approve));
  router.post("/:id/reject", authenticate, requireRole("IR_TEAM"), asyncHandler(controller.reject));
  return router;
}

/** Mounted at /api/recommendations/:id/approvals (see main.ts) — read-only, powers the Ticket Detail Policy & Approval section. */
export function buildRecommendationApprovalRoutes(controller: ApprovalController): Router {
  const router = Router({ mergeParams: true });
  router.get("/", authenticate, controller.listByRecommendation);
  return router;
}
