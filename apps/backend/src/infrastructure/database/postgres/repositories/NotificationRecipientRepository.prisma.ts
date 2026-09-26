import { PrismaClient } from "@prisma/client";
import {
  INotificationRecipientRepository,
  NotificationRecipientRecord,
} from "../../../../domain/notification/repositories/INotificationRecipientRepository";

const toRecord = (r: { role: string; email: string; updatedBy: string | null; updatedAt: Date }): NotificationRecipientRecord => ({
  role: r.role,
  email: r.email,
  updatedBy: r.updatedBy,
  updatedAt: r.updatedAt,
});

export class PrismaNotificationRecipientRepository implements INotificationRecipientRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findAll(tenantId: string): Promise<NotificationRecipientRecord[]> {
    return (await this.prisma.notificationRecipient.findMany({ where: { tenantId } })).map(toRecord);
  }

  async findByRole(tenantId: string, role: string): Promise<NotificationRecipientRecord | null> {
    const row = await this.prisma.notificationRecipient.findUnique({ where: { tenantId_role: { tenantId, role } } });
    return row ? toRecord(row) : null;
  }

  async upsert(tenantId: string, role: string, email: string, updatedBy: string): Promise<NotificationRecipientRecord> {
    const row = await this.prisma.notificationRecipient.upsert({
      where: { tenantId_role: { tenantId, role } },
      create: { tenantId, role, email, updatedBy },
      update: { email, updatedBy },
    });
    return toRecord(row);
  }

  async remove(tenantId: string, role: string): Promise<void> {
    await this.prisma.notificationRecipient.deleteMany({ where: { tenantId, role } });
  }
}
