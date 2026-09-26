import { Request, Response } from "express";
import { z } from "zod";
import { IInAppNotificationRepository } from "../../../domain/notification/repositories/IInAppNotificationRepository";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
const markReadSchema = z.object({ ids: z.array(z.string().min(1)).max(200).optional() }).strict();

/**
 * The header bell. Role-aware: each workflow role reads its own notifications; admin (system role) sees every role's.
 * Read state is per user. Nothing here creates notifications — the workflow use cases / dispatcher / email service do.
 */
export class InAppNotificationController {
  constructor(private readonly repository: IInAppNotificationRepository) {}

  private scope(req: Request) {
    const user = req.user!;
    return { tenantId: user.tenantId ?? DEFAULT_TENANT_ID, roles: user.role === "admin" ? null : [user.role], userId: user.id };
  }

  list = async (req: Request, res: Response): Promise<void> => {
    if (!req.user) return void res.status(401).json({ error: "UNAUTHENTICATED" });
    const { tenantId, roles, userId } = this.scope(req);
    const limit = Math.min(Math.max(Number(req.query.limit) || 30, 1), 100);
    const out = await this.repository.list(tenantId, roles, userId, limit);
    res.json({ items: out.items.map((n) => ({ ...n, createdAt: n.createdAt.toISOString() })), unread: out.unread });
  };

  markRead = async (req: Request, res: Response): Promise<void> => {
    if (!req.user) return void res.status(401).json({ error: "UNAUTHENTICATED" });
    const parsed = markReadSchema.safeParse(req.body ?? {});
    if (!parsed.success) return void res.status(400).json({ error: "VALIDATION_ERROR", details: parsed.error.issues });
    const { tenantId, roles, userId } = this.scope(req);
    const marked = await this.repository.markRead(tenantId, roles, userId, parsed.data.ids ?? null);
    res.json({ marked });
  };
}
