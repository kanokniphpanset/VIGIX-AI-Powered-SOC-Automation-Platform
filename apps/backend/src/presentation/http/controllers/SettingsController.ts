import { Request, Response } from "express";
import { z } from "zod";
import {
  ListNotificationRecipientsUseCase,
  UpdateNotificationRecipientUseCase,
} from "../../../application/settings/use-cases/NotificationRecipients.usecases";
import { validateBody } from "../validators/validateBody";
import { canEditNotificationRecipients } from "../routes/settings.routes";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
const updateSchema = z.object({ email: z.string().max(254).nullable() }).strict();

export class SettingsController {
  constructor(
    private readonly listRecipients: ListNotificationRecipientsUseCase,
    private readonly updateRecipient: UpdateNotificationRecipientUseCase
  ) {}

  /** Any signed-in role may see who is notified; only roles that may edit see full addresses. */
  notificationRecipients = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const items = await this.listRecipients.execute({ tenantId, viewerCanEdit: canEditNotificationRecipients(req.user?.role) });
    res.json({ items });
  };

  /** SOC / IR_TEAM / admin (route gate). email = null clears the Settings value (falls back to the server default). */
  updateNotificationRecipient = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(updateSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.updateRecipient.execute({
      tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID,
      role: req.params.role,
      email: body.email,
      updatedBy: req.user.id,
    });
    if (result.isFailure) {
      res.status(result.error === "INVALID_ROLE" ? 404 : 400).json({ error: result.error });
      return;
    }
    const items = await this.listRecipients.execute({ tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID, viewerCanEdit: true });
    res.json({ items });
  };
}
