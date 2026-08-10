import { PrismaClient } from "@prisma/client";
import {
  IIncidentRepository,
  IncidentTimelineEntry,
} from "../../../../domain/incident/repositories/IIncidentRepository";
import { Incident, IncidentStatus } from "../../../../domain/incident/entities/Incident.entity";
import { IncidentMapper } from "../mappers/Incident.mapper";

export class PrismaIncidentRepository implements IIncidentRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Incident | null> {
    const raw = await this.prisma.incident.findFirst({ where: { id, tenantId } });
    return raw ? IncidentMapper.toDomain(raw) : null;
  }

  async findAll(tenantId: string, limit = 25, offset = 0): Promise<Incident[]> {
    const rows = await this.prisma.incident.findMany({
      where: { tenantId },
      orderBy: { openedAt: "desc" },
      take: limit,
      skip: offset,
    });
    return rows.map(IncidentMapper.toDomain);
  }

  async countAll(tenantId: string): Promise<number> {
    return this.prisma.incident.count({ where: { tenantId } });
  }

  async findTimeline(incidentId: string): Promise<IncidentTimelineEntry[]> {
    const rows = await this.prisma.incidentTimeline.findMany({
      where: { incidentId },
      orderBy: { occurredAt: "asc" },
    });
    return rows.map(IncidentMapper.timelineToDomain);
  }

  async updateStatus(id: string, tenantId: string, status: IncidentStatus): Promise<Incident> {
    const raw = await this.prisma.incident.update({
      where: { id },
      data: {
        status,
        closedAt: status === "resolved" || status === "dismissed" ? new Date() : null,
      },
    });
    return IncidentMapper.toDomain(raw);
  }
}
