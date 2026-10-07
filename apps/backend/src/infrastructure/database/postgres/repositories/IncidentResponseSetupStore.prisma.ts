import { Prisma, PrismaClient } from "@prisma/client";
import { CaseGuidance, IIncidentResponseSetupStore } from "../../../../application/incident/ports/IIncidentResponseSetupStore";

function toGuidance(v: Prisma.JsonValue | null): CaseGuidance | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const g = v as Record<string, unknown>;
  if (!Array.isArray(g.allowedActions)) return null;
  return {
    allowedActions: g.allowedActions.filter((a): a is string => typeof a === "string"),
    instructions: typeof g.instructions === "string" ? g.instructions : null,
    setBy: typeof g.setBy === "string" ? g.setBy : "",
    setAt: typeof g.setAt === "string" ? g.setAt : "",
  };
}

/** incidents.incident_type / incidents.response_guidance (tenant-scoped). */
export class PrismaIncidentResponseSetupStore implements IIncidentResponseSetupStore {
  constructor(private readonly prisma: PrismaClient) {}

  async get(incidentId: string, tenantId: string) {
    const r = await this.prisma.incident.findFirst({
      where: { id: incidentId, tenantId },
      select: { priority: true, status: true, incidentType: true, responseGuidance: true },
    });
    return r ? { severity: r.priority, status: r.status, incidentType: r.incidentType, guidance: toGuidance(r.responseGuidance) } : null;
  }

  async setIncidentType(incidentId: string, tenantId: string, incidentType: string | null): Promise<void> {
    await this.prisma.incident.updateMany({ where: { id: incidentId, tenantId }, data: { incidentType } });
  }

  async setGuidance(incidentId: string, tenantId: string, guidance: CaseGuidance | null): Promise<void> {
    await this.prisma.incident.updateMany({
      where: { id: incidentId, tenantId },
      data: { responseGuidance: guidance ? (guidance as unknown as Prisma.InputJsonValue) : Prisma.DbNull },
    });
  }
}
