import { PrismaClient } from "@prisma/client";
import { IAlertRepository } from "../../../../domain/alert/repositories/IAlertRepository";
import { Alert } from "../../../../domain/alert/entities/Alert.entity";
import { AlertMapper } from "../mappers/Alert.mapper";

/**
 * AlertRepository.prisma.ts — infrastructure (Ring 3).
 * Implements the IAlertRepository port declared in the domain.
 * This is the ONLY class in the codebase allowed to import PrismaClient for Alert data.
 */
export class PrismaAlertRepository implements IAlertRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Alert | null> {
    const raw = await this.prisma.alert.findFirst({ where: { id, tenantId } });
    return raw ? AlertMapper.toDomain(raw) : null;
  }

  async findAll(tenantId: string, limit = 25, offset = 0): Promise<Alert[]> {
    const rows = await this.prisma.alert.findMany({
      where: { tenantId },
      orderBy: { receivedAt: "desc" },
      take: limit,
      skip: offset,
    });
    return rows.map(AlertMapper.toDomain);
  }

  async countAll(tenantId: string): Promise<number> {
    return this.prisma.alert.count({ where: { tenantId } });
  }

  async save(alert: Alert): Promise<Alert> {
    const data = alert.toJSON();
    const raw = await this.prisma.alert.upsert({
      where: { id: data.id },
      update: {
        severity: data.severity,
        status: data.status,
        rawPayload: data.rawPayload,
      },
      create: {
        id: data.id,
        tenantId: data.tenantId,
        externalAlertId: data.externalAlertId,
        siemSource: data.siemSource,
        rawPayload: data.rawPayload,
        severity: data.severity,
        status: data.status,
        receivedAt: data.receivedAt,
      },
    });
    return AlertMapper.toDomain(raw);
  }
}
