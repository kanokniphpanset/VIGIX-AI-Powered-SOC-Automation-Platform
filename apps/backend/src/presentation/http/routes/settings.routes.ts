import { Router } from "express";
import { z } from "zod";
import { emailSettingsStatus, saveEmailSettings } from "../../../infrastructure/notification/EmailSettingsStore";
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
  // SMTP is server-wide, unlike per-tenant recipient settings: admin only.
  router.get("/email-provider", authenticate, requireRole(), (_req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try { res.json(emailSettingsStatus()); }
    catch { res.status(503).json({ error: "EMAIL_SETTINGS_UNAVAILABLE" }); }
  });
  router.put("/email-provider", authenticate, requireRole(), (req, res) => {
    const parsed = z.object({ user: z.string().email().max(254).refine(v => v.toLowerCase().endsWith("@gmail.com")), password: z.string().transform(v => v.replace(/\s/g, "")).pipe(z.string().regex(/^[a-zA-Z0-9]{16}$/)).optional() }).strict().safeParse(req.body);
    if (!parsed.success) { res.status(400).json({ error: "INVALID_GMAIL_SETTINGS" }); return; }
    try { saveEmailSettings(parsed.data.user, parsed.data.password); res.setHeader("Cache-Control", "no-store"); res.json(emailSettingsStatus()); }
    catch { res.status(400).json({ error: "EMAIL_SETTINGS_SAVE_FAILED", message: "กรอก App Password เมื่อเปลี่ยนผู้ส่ง และใช้บัญชี Windows เดียวกับ backend" }); }
  });
  return router;
}
