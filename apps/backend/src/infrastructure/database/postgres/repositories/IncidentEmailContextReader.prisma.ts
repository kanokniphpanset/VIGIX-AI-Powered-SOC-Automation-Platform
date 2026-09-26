import { PrismaRecommendationContextRepository } from "./RecommendationContextRepository.prisma";
import { PrismaClient } from "@prisma/client";
import { incidentSeverity } from "../../../../domain/incident/severity";
import { IIncidentEmailContextReader, IncidentEmailContext } from "../../../../application/notification/use-cases/IncidentContextEmail.usecase";

/** Reads the stored facts of one incident for the role-context email (tenant-scoped, read-only). */
export class PrismaIncidentEmailContextReader implements IIncidentEmailContextReader {
  constructor(private readonly prisma: PrismaClient) {}

  async read(tenantId: string, incidentId: string): Promise<IncidentEmailContext | null> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, tenantId } });
    if (!incident) return null;

    const [assigned, ai, mitre, iocs, recommendation, plans] = await Promise.all([
      this.prisma.auditLog.findFirst({ where: { tenantId, entity: "Incident", entityId: incidentId, action: "INCIDENT_ASSIGNED" }, orderBy: { createdAt: "desc" } }),
      new PrismaRecommendationContextRepository(this.prisma).getLatestAiAnalysis(incidentId),
      this.prisma.mitreMapping.findMany({ where: { incidentId }, select: { techniqueId: true } }),
      this.prisma.threatIntelIoc.findMany({
        where: { incidentId, investigation: { investigationNumber: incident.investigationNumber } },
        select: { iocType: true, iocValue: true },
        take: 50,
      }),
      this.prisma.recommendation.findFirst({
        where: { incidentId, investigationNumber: incident.investigationNumber },
        orderBy: { recommendationNumber: "desc" },
        select: { recommendationNumber: true, status: true, summary: true },
      }),
      this.prisma.responsePlan.findMany({
        where: { incidentId, tenantId },
        orderBy: { createdAt: "asc" },
        include: { action: { select: { name: true } }, approvals: { orderBy: { stepOrder: "asc" } }, verification: { select: { result: true } } },
      }),
    ]);

    const meta = assigned?.metadata && typeof assigned.metadata === "object" ? (assigned.metadata as Record<string, unknown>) : null;
    return {
      id: incident.id,
      title: incident.title,
      status: incident.status,
      priority: incident.priority,
      investigationNumber: incident.investigationNumber,
      openedAt: incident.openedAt.toISOString(),
      severity: incidentSeverity(incident),
      responsibleRole: typeof meta?.responsibleRole === "string" ? meta.responsibleRole : null,
      aiSummary: ai?.grounding.status === "GROUNDED" ? ai.summary : null,
      mitre: [...new Set(mitre.map((m) => m.techniqueId))],
      iocs: iocs.map((i) => ({ type: i.iocType, value: i.iocValue })),
      recommendation: recommendation ? { number: recommendation.recommendationNumber, status: recommendation.status, summary: recommendation.summary } : null,
      tickets: plans.map((p) => ({
        id: p.id,
        action: p.action?.name ?? null,
        target: p.target,
        status: p.status,
        executorRole: p.assignedRole,
        approvals: p.approvals.map((a) => ({ role: a.approvalRole, stepOrder: a.stepOrder, status: a.status, decidedAt: a.decidedAt?.toISOString() ?? null })),
        verification: p.verification?.result ?? null,
      })),
    };
  }
}
