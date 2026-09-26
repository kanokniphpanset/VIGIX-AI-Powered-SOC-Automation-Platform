import { Router } from "express";
import { IrEmailController } from "../controllers/IrEmailController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";

/**
 * Who may email content to the IR Team — the same gate as the existing IR hand-off (POST /api/notifications/ir-handoff),
 * shared here so both paths always agree. "admin" passes every requireRole() check.
 */
export const IR_HANDOFF_SENDER_ROLES = ["SOC"] as const;

/**
 * Mounted at /api/v1 (after the existing knowledge and incident routers, which do not define these paths).
 * Previews are read-only for any signed-in role; sending is gated by IR_HANDOFF_SENDER_ROLES.
 */
export function buildIrEmailRoutes(controller: IrEmailController): Router {
  const router = Router();
  router.get("/knowledge/articles/:articleId", authenticate, controller.article);
  router.post("/knowledge/articles/:articleId/send-to-ir", authenticate, requireRole(...IR_HANDOFF_SENDER_ROLES), controller.sendArticleToIr);
  router.get("/incidents/:incidentId/response-guide", authenticate, controller.responseGuide);
  router.post("/incidents/:incidentId/send-response-guide", authenticate, requireRole(...IR_HANDOFF_SENDER_ROLES), controller.sendResponseGuideToIr);
  return router;
}
