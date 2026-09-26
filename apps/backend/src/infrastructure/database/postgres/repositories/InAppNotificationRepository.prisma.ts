import { PrismaClient, Prisma } from "@prisma/client";
import {
  CreateInAppNotificationData,
  IInAppNotificationRepository,
  InAppNotificationRow,
} from "../../../../domain/notification/repositories/IInAppNotificationRepository";

export class PrismaInAppNotificationRepository implements IInAppNotificationRepository {
  constructor(private readonly prisma: PrismaClient | Prisma.TransactionClient) {}

  async createMany(rows: CreateInAppNotificationData[]): Promise<void> {
    if (rows.length) await this.prisma.inAppNotification.createMany({ data: rows });
  }

  async list(tenantId: string, roles: string[] | null, userId: string, limit: number): Promise<{ items: InAppNotificationRow[]; unread: number }> {
    const where = { tenantId, ...(roles ? { recipientRole: { in: roles } } : {}) };
    const [rows, unread] = await Promise.all([
      this.prisma.inAppNotification.findMany({
        where,
        orderBy: { createdAt: "desc" },
        take: limit,
        include: { reads: { where: { userId }, select: { userId: true } } },
      }),
      this.prisma.inAppNotification.count({ where: { ...where, reads: { none: { userId } } } }),
    ]);
    return {
      items: rows.map(({ reads, ...r }) => ({ ...r, read: reads.length > 0 })),
      unread,
    };
  }

  async markRead(tenantId: string, roles: string[] | null, userId: string, ids: string[] | null): Promise<number> {
    const unread = await this.prisma.inAppNotification.findMany({
      where: { tenantId, ...(roles ? { recipientRole: { in: roles } } : {}), ...(ids ? { id: { in: ids } } : {}), reads: { none: { userId } } },
      select: { id: true },
    });
    if (!unread.length) return 0;
    const res = await this.prisma.inAppNotificationRead.createMany({ data: unread.map((n) => ({ notificationId: n.id, userId })), skipDuplicates: true });
    return res.count;
  }
}
