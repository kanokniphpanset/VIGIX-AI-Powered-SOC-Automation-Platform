export interface CreateInAppNotificationData {
  tenantId: string;
  eventType: string;
  recipientRole: string;
  incidentId: string | null;
  responseId: string | null;
  alertId?: string | null;
  title: string;
  body: string | null;
  link: string | null;
}

export interface InAppNotificationRow extends CreateInAppNotificationData {
  id: string;
  createdAt: Date;
  /** Read by the viewing user (per-user read state). */
  read: boolean;
}

/** Persistent in-app notifications (header bell): one row per recipient role, read state per user. */
export interface IInAppNotificationRepository {
  createMany(rows: CreateInAppNotificationData[]): Promise<void>;
  /** Newest first. `roles` null = every role (admin system visibility). */
  list(tenantId: string, roles: string[] | null, userId: string, limit: number): Promise<{ items: InAppNotificationRow[]; unread: number }>;
  /** Marks the given notifications (or, with ids null, every visible one) read for this user. */
  markRead(tenantId: string, roles: string[] | null, userId: string, ids: string[] | null): Promise<number>;
}
