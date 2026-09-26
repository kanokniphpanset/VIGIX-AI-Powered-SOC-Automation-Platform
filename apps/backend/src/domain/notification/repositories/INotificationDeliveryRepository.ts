import { NotificationDelivery, NotificationDeliveryChannel, NotificationDeliveryStatus } from "../entities/NotificationDelivery.entity";

export interface CreateNotificationDeliveryData {
  tenantId: string;
  eventId: string;
  eventType: string;
  incidentId: string | null;
  channel: NotificationDeliveryChannel;
  recipientRole: string;
  recipient: string;
  status: NotificationDeliveryStatus;
}

export interface INotificationDeliveryRepository {
  create(data: CreateNotificationDeliveryData): Promise<NotificationDelivery>;
  updateStatus(
    id: string,
    data: { status: NotificationDeliveryStatus; providerMessageId?: string | null; errorMessage?: string | null; sentAt?: Date | null }
  ): Promise<NotificationDelivery>;
  findById(id: string, tenantId: string): Promise<NotificationDelivery | null>;
  findByEventId(eventId: string, tenantId: string): Promise<NotificationDelivery[]>;
}
