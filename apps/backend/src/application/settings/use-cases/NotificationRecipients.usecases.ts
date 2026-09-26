import { z } from "zod";
import { Result } from "../../../shared/result/Result";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { INotificationRecipientRepository } from "../../../domain/notification/repositories/INotificationRecipientRepository";
import { NotificationRole } from "../../notification/events/NotificationEvent";
import { NOTIFICATION_ROLES, RoleEmailDirectory, RoleEmailSource } from "../../notification/services/RoleEmailDirectory";

export interface NotificationRecipientView {
  role: NotificationRole;
  /** Full address for roles that may edit recipients; masked (e.g. s***@example.com) for everyone else. */
  email: string | null;
  masked: boolean;
  source: RoleEmailSource;
  /** The server (.env) default is never revealed — only whether one exists. */
  hasServerDefault: boolean;
  updatedBy: string | null;
  updatedAt: string | null;
}

export function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!domain) return "***";
  return `${local.slice(0, 1)}***@${domain}`;
}

/** Lists the effective notification email of every role (Settings value, else the server default). */
export class ListNotificationRecipientsUseCase {
  constructor(private readonly repository: INotificationRecipientRepository, private readonly directory: RoleEmailDirectory) {}

  async execute(input: { tenantId: string; viewerCanEdit: boolean }): Promise<NotificationRecipientView[]> {
    const rows = new Map((await this.repository.findAll(input.tenantId)).map((r) => [r.role, r]));
    return NOTIFICATION_ROLES.map((role) => {
      const row = rows.get(role);
      const server = this.directory.serverDefault(role);
      const email = row?.email ?? server;
      const source: RoleEmailSource = row ? "settings" : server ? "server" : "none";
      return {
        role,
        email: email ? (input.viewerCanEdit ? email : maskEmail(email)) : null,
        masked: !!email && !input.viewerCanEdit,
        source,
        hasServerDefault: !!server,
        updatedBy: row?.updatedBy ?? null,
        updatedAt: row?.updatedAt.toISOString() ?? null,
      };
    });
  }
}

const emailSchema = z.string().trim().toLowerCase().email().max(254);

export type UpdateNotificationRecipientError = "INVALID_ROLE" | "INVALID_EMAIL";

/**
 * Sets (or clears, with email = null) the notification email of one role. Gated at the route (SOC, IR_TEAM, admin). Every change is
 * audited with the previous and new value; clearing reverts the role to its server (.env) default.
 */
export class UpdateNotificationRecipientUseCase {
  constructor(private readonly repository: INotificationRecipientRepository, private readonly auditLogger: AuditLogger) {}

  async execute(input: { tenantId: string; role: string; email: string | null; updatedBy: string }): Promise<Result<{ role: NotificationRole; email: string | null }, UpdateNotificationRecipientError>> {
    if (!NOTIFICATION_ROLES.includes(input.role as NotificationRole)) return Result.fail("INVALID_ROLE");
    const role = input.role as NotificationRole;
    let email: string | null = null;
    if (input.email !== null && input.email.trim() !== "") {
      const parsed = emailSchema.safeParse(input.email);
      if (!parsed.success) return Result.fail("INVALID_EMAIL");
      email = parsed.data;
    }

    const previous = await this.repository.findByRole(input.tenantId, role);
    if (email) await this.repository.upsert(input.tenantId, role, email, input.updatedBy);
    else await this.repository.remove(input.tenantId, role);

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.updatedBy,
      action: email ? "NOTIFICATION_RECIPIENT_UPDATED" : "NOTIFICATION_RECIPIENT_CLEARED",
      entity: "NotificationRecipient",
      entityId: role,
      metadata: { role, previousEmail: previous?.email ?? null, newEmail: email },
    });
    return Result.ok({ role, email });
  }
}
