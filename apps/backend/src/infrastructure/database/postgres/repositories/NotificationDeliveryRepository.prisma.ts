import { PrismaClient } from "@prisma/client";
import {
  INotificationDeliveryRepository,
  CreateNotificationDeliveryData,
} from "../../../../domain/notification/repositories/INotificationDeliveryRepository";
import { NotificationDelivery, NotificationDeliveryStatus } from "../../../../domain/notification/entities/NotificationDelivery.entity";
import { NotificationDeliveryMapper } from "../mappers/NotificationDelivery.mapper";

export class PrismaNotificationDeliveryRepository implements INotificationDeliveryRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async create(data: CreateNotificationDeliveryData): Promise<NotificationDelivery> {
    const raw = await this.prisma.notificationDelivery.create({
      data: {
        tenantId: data.tenantId,
        eventId: data.eventId,
        eventType: data.eventType,
        incidentId: data.incidentId,
        channel: data.channel,
        recipientRole: data.recipientRole,
        recipient: data.recipient,
        status: data.status,
      },
    });
    return NotificationDeliveryMapper.toDomain(raw);
  }

  async updateStatus(
    id: string,
    data: { status: NotificationDeliveryStatus; providerMessageId?: string | null; errorMessage?: string | null; sentAt?: Date | null }
  ): Promise<NotificationDelivery> {
    const raw = await this.prisma.notificationDelivery.update({
      where: { id },
      data: {
        status: data.status,
        providerMessageId: data.providerMessageId,
        errorMessage: data.errorMessage,
        sentAt: data.sentAt,
      },
    });
    return NotificationDeliveryMapper.toDomain(raw);
  }

  async findById(id: string, tenantId: string): Promise<NotificationDelivery | null> {
    const raw = await this.prisma.notificationDelivery.findFirst({ where: { id, tenantId } });
    return raw ? NotificationDeliveryMapper.toDomain(raw) : null;
  }

  async findByEventId(eventId: string, tenantId: string): Promise<NotificationDelivery[]> {
    const rows = await this.prisma.notificationDelivery.findMany({ where: { eventId, tenantId }, orderBy: { createdAt: "asc" } });
    return rows.map(NotificationDeliveryMapper.toDomain);
  }
}
