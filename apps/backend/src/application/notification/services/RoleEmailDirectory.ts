import { NotificationRole } from "../events/NotificationEvent";
import { INotificationRecipientRepository } from "../../../domain/notification/repositories/INotificationRecipientRepository";

export const NOTIFICATION_ROLES: readonly NotificationRole[] = ["SOC", "IR_TEAM", "ADMIN"];

export type RoleEmailSource = "settings" | "server" | "none";

/** Where a role's email address comes from when a notification is sent. */
export interface IRoleEmailResolver {
  resolve(tenantId: string, role: NotificationRole): Promise<{ email: string | null; source: RoleEmailSource }>;
}

/**
 * RoleEmailDirectory — resolves a role's notification email at send time: the admin's Settings value (per tenant)
 * wins; otherwise the server default (SOC_EMAIL / IR_TEAM_EMAIL / ADMIN_EMAIL, unchanged behaviour when nothing
 * was set in Settings). A failure to read Settings falls back to the server default, so notifications never
 * silently stop because of the lookup.
 */
export class RoleEmailDirectory implements IRoleEmailResolver {
  constructor(
    private readonly repository: INotificationRecipientRepository,
    private readonly serverDefaults: Partial<Record<NotificationRole, string>>
  ) {}

  serverDefault(role: NotificationRole): string | null {
    return this.serverDefaults[role]?.trim() || null;
  }

  async resolve(tenantId: string, role: NotificationRole): Promise<{ email: string | null; source: RoleEmailSource }> {
    try {
      const row = await this.repository.findByRole(tenantId, role);
      if (row?.email) return { email: row.email, source: "settings" };
    } catch (err) {
      console.error("Failed to read notification recipient from Settings; using the server default", role, err);
    }
    const fallback = this.serverDefault(role);
    return fallback ? { email: fallback, source: "server" } : { email: null, source: "none" };
  }
}
