import { Request, Response, Router } from "express";
import { z } from "zod";
import { authenticate, requireRole } from "../middlewares/auth.middleware";
import { INCIDENT_EMAIL_SENDER_ROLES, IncidentContextEmailUseCase } from "../../../application/notification/use-cases/IncidentContextEmail.usecase";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

// No "recipient"/"to" field: the address always comes from Settings / .env for the chosen role.
const sendSchema = z
  .object({
    recipientRole: z.enum(["SOC", "IR_TEAM", "ADMIN"]),
    note: z.string().trim().max(2000).nullable().optional(),
    idempotencyKey: z.string().uuid(),
  })
  .strict();

const STATUS: Record<string, number> = { INCIDENT_NOT_FOUND: 404, INVALID_RECIPIENT_ROLE: 400, SENDER_ROLE_NOT_ALLOWED: 403 };

/**
 * Mounted at /api/v1/incidents. Role-context incident email (reuses IrEmailService delivery + duplicate protection):
 *   GET  /:incidentId/context-email?recipientRole=IR_TEAM&note=  — exact preview + masked recipient (any signed-in role)
 *   POST /:incidentId/context-email {recipientRole, note?, idempotencyKey} — SOC / IR_TEAM (admin passes)
 * The content follows the SENDER's role: SOC investigation, IR response (with the IR decision), admin administrative.
 */
export function buildIncidentEmailRoutes(useCase: IncidentContextEmailUseCase): Router {
  const router = Router();

  router.get("/:incidentId/context-email", authenticate, async (req: Request, res: Response) => {
    try {
      const recipientRole = typeof req.query.recipientRole === "string" ? req.query.recipientRole : "";
      const note = typeof req.query.note === "string" && req.query.note.trim() ? req.query.note.trim().slice(0, 2000) : null;
      const r = await useCase.preview({ tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.incidentId, senderRole: req.user!.role, recipientRole, note });
      if (r.isFailure) {
        res.status(STATUS[r.error] ?? 400).json({ error: r.error });
        return;
      }
      res.json(r.value);
    } catch (err) {
      console.error("[incident-email] preview failed", err instanceof Error ? err.message : err);
      res.status(500).json({ error: "PREVIEW_FAILED" });
    }
  });

  router.post("/:incidentId/context-email", authenticate, requireRole(...INCIDENT_EMAIL_SENDER_ROLES), async (req: Request, res: Response) => {
    const body = validateBody(sendSchema, req, res);
    if (!body) return;
    try {
      const r = await useCase.send({
        tenantId: req.user!.tenantId ?? DEFAULT_TENANT_ID,
        incidentId: req.params.incidentId,
        actor: req.user!.id,
        senderRole: req.user!.role,
        recipientRole: body.recipientRole,
        note: body.note ?? null,
        idempotencyKey: body.idempotencyKey,
      });
      if (r.isFailure) {
        res.status(STATUS[r.error] ?? 400).json({ error: r.error });
        return;
      }
      const o = r.value;
      const code =
        o.status === "SENT" ? 200 : o.error === "DUPLICATE_IN_PROGRESS" ? 409 : o.error === "DELIVERY_FAILED" ? 502 : 400;
      res.status(code).json(o.status === "SENT" ? o : { ...o, error: o.error });
    } catch (err) {
      console.error("[incident-email] send failed", err instanceof Error ? err.message : err);
      res.status(500).json({ error: "SEND_FAILED" });
    }
  });

  return router;
}
