import { OPEN_WORKFLOW_STATES } from "../../../../domain/alert/triageWorkflow";
import { PrismaClient, Prisma } from "@prisma/client";
import {
  IAlertRepository,
  AlertListOptions,
  CommitTriageData,
} from "../../../../domain/alert/repositories/IAlertRepository";
import {
  Alert,
  AlertStatus,
  AlertTriage,
  SiemSource,
} from "../../../../domain/alert/entities/Alert.entity";
import { AlertMapper } from "../mappers/Alert.mapper";

export class PrismaAlertRepository implements IAlertRepository {
  constructor(private readonly prisma: PrismaClient | Prisma.TransactionClient) {}

  async findById(
    id: string,
    tenantId: string
  ): Promise<Alert | null> {
    const raw = await this.prisma.alert.findFirst({
      where: {
        id,
        tenantId,
      },
    });

    return raw ? AlertMapper.toDomain(raw) : null;
  }

  private where(
    tenantId: string,
    options?: AlertListOptions
  ): Prisma.AlertWhereInput {
    if (options?.unlinked) {
      return {
        tenantId,
        incidents: {
          none: {},
        },
        incidentLinks: {
          is: null,
        },
      };
    }

    return {
      tenantId,
    };
  }

  async findByExternalId(
    siemSource: SiemSource,
    externalAlertId: string,
    tenantId: string
  ): Promise<Alert[]> {
    const rows = await this.prisma.alert.findMany({
      where: {
        tenantId,
        siemSource,
        externalAlertId,
      },
      orderBy: {
        receivedAt: "asc",
      },
    });

    return rows.map(AlertMapper.toDomain);
  }

  async findAll(
    tenantId: string,
    limit = 25,
    offset = 0,
    options?: AlertListOptions
  ): Promise<Alert[]> {
    const rows = await this.prisma.alert.findMany({
      where: this.where(tenantId, options),
      orderBy: {
        receivedAt: "desc",
      },
      take: limit,
      skip: offset,
    });

    return rows.map(AlertMapper.toDomain);
  }

  async countAll(
    tenantId: string,
    options?: AlertListOptions
  ): Promise<number> {
    return this.prisma.alert.count({
      where: this.where(tenantId, options),
    });
  }

  async recordTriage(id: string, tenantId: string, triage: AlertTriage, status: AlertStatus): Promise<Alert> {
    await this.prisma.alert.findFirstOrThrow({ where: { id, tenantId } });
    const raw = await this.prisma.alert.update({
      where: { id },
      data: { status, triageDisposition: triage.disposition, triageNote: triage.note, triagedBy: triage.triagedBy, triagedAt: triage.triagedAt },
    });
    return AlertMapper.toDomain(raw);
  }

  async commitTriage(id: string, tenantId: string, actor: string, d: CommitTriageData): Promise<Alert | null> {
    // One statement: Postgres re-checks the WHERE after taking the row lock, so exactly one concurrent decision wins.
    const r = await this.prisma.alert.updateMany({
      where: { id, tenantId, workflowState: { in: [...OPEN_WORKFLOW_STATES] }, incidentLinks: null },
      data: {
        triageDisposition: d.disposition,
        triageNote: d.reason,
        triagedBy: actor,
        triagedAt: d.at,
        // Legacy status kept in step for existing consumers (dashboard counts).
        status: "closed",
        workflowState: "TRIAGED",
        closedAt: d.at,
      },
    });
    if (r.count !== 1) return null;
    return this.findById(id, tenantId);
  }

  async findDueMonitors(now: Date, limit: number): Promise<Alert[]> {
    const rows = await this.prisma.alert.findMany({
      where: { workflowState: "MONITORING", reviewAt: { lte: now } },
      orderBy: { reviewAt: "asc" },
      take: limit,
    });
    return rows.map(AlertMapper.toDomain);
  }

  async returnDueMonitor(id: string, tenantId: string, now: Date): Promise<Alert | null> {
    const row = await this.prisma.alert.findFirst({ where: { id, tenantId } });
    if (!row) return null;
    const r = await this.prisma.alert.updateMany({
      where: { id, tenantId, workflowState: "MONITORING", reviewAt: { lte: now } },
      data: { workflowState: "NEW", status: "received" },
    });
    if (r.count !== 1) return null;
    return this.findById(id, tenantId);
  }

  async save(alert: Alert): Promise<Alert> {
    const data = alert.toJSON();

    const raw = await this.prisma.alert.upsert({
      where: {
        id: data.id,
      },
      update: {
        severity: data.severity,
        status: data.status,
        rawPayload: data.rawPayload as Prisma.InputJsonValue,
      },
      create: {
        id: data.id,
        tenantId: data.tenantId,
        externalAlertId: data.externalAlertId,
        siemSource: data.siemSource,
        rawPayload: data.rawPayload as Prisma.InputJsonValue,
        severity: data.severity,
        status: data.status,
        receivedAt: data.receivedAt,
      },
    });

    return AlertMapper.toDomain(raw);
  }
}
