import { Router } from "express";
import { SettingsController } from "../controllers/SettingsController";
import { authenticate, requireRole } from "../middlewares/auth.middleware";

/** Roles that may change the per-role notification email recipients ("admin" passes every requireRole() check). */
export const NOTIFICATION_RECIPIENT_EDITOR_ROLES = ["SOC", "IR_TEAM"] as const;

export const canEditNotificationRecipients = (role: string | undefined) =>
  role === "admin" || (NOTIFICATION_RECIPIENT_EDITOR_ROLES as readonly string[]).includes(role ?? "");

/**
 * Mounted at /api/v1/settings. Reading is open to any signed-in role (addresses masked unless the viewer may edit);
 * changes are limited to NOTIFICATION_RECIPIENT_EDITOR_ROLES.
 */
export function buildSettingsRoutes(controller: SettingsController): Router {
  const router = Router();
  router.get("/notification-recipients", authenticate, controller.notificationRecipients);
  router.put("/notification-recipients/:role", authenticate, requireRole(...NOTIFICATION_RECIPIENT_EDITOR_ROLES), controller.updateNotificationRecipient);
  return router;
}
