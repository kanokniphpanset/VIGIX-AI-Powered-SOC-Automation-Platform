export interface NotificationRecipientRecord {
  role: string;
  email: string;
  updatedBy: string | null;
  updatedAt: Date;
}

/** Per-role notification email recipients set by an admin in Settings (one row per tenant + role). */
export interface INotificationRecipientRepository {
  findAll(tenantId: string): Promise<NotificationRecipientRecord[]>;
  findByRole(tenantId: string, role: string): Promise<NotificationRecipientRecord | null>;
  upsert(tenantId: string, role: string, email: string, updatedBy: string): Promise<NotificationRecipientRecord>;
  /** Removes the override so the role falls back to its server (.env) default. */
  remove(tenantId: string, role: string): Promise<void>;
}
