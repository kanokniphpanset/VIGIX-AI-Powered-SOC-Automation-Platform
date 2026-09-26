import { NotificationDelivery as PrismaNotificationDelivery } from "@prisma/client";
import { NotificationDelivery, NotificationDeliveryChannel, NotificationDeliveryStatus } from "../../../../domain/notification/entities/NotificationDelivery.entity";

export class NotificationDeliveryMapper {
  static toDomain(raw: PrismaNotificationDelivery): NotificationDelivery {
    return NotificationDelivery.create({
      id: raw.id,
      tenantId: raw.tenantId,
      eventId: raw.eventId,
      eventType: raw.eventType,
      incidentId: raw.incidentId,
      channel: raw.channel as NotificationDeliveryChannel,
      recipientRole: raw.recipientRole,
      recipient: raw.recipient,
      status: raw.status as NotificationDeliveryStatus,
      providerMessageId: raw.providerMessageId,
      errorMessage: raw.errorMessage,
      sentAt: raw.sentAt,
      createdAt: raw.createdAt,
    });
  }
}
