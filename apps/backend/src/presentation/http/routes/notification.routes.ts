import { Router } from "express";
import { NotificationTestController } from "../controllers/NotificationTestController";
import { IrHandoffController } from "../controllers/IrHandoffController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";
import { IR_HANDOFF_SENDER_ROLES } from "./ir-email.routes";

/**
 * Mounted at /api/notifications. Admin-only manual delivery test per
 * channel — bypasses the event pipeline, calls the real adapter directly.
 * requireRole() with no roles listed means only the "admin" super-role
 * passes (see auth.middleware.ts) — not exposed to SOC/IR_TEAM.
 */
export function buildNotificationRoutes(controller: NotificationTestController, irHandoff: IrHandoffController): Router {
  const router = Router();
  router.post("/ir-handoff", authenticate, requireRole(...IR_HANDOFF_SENDER_ROLES), irHandoff.handoff);
  router.post("/test/email", authenticate, requireRole(), controller.testEmail);
  router.post("/test/discord", authenticate, requireRole(), controller.testDiscord);
  router.post("/test/telegram", authenticate, requireRole(), controller.testTelegram);
  return router;
}
