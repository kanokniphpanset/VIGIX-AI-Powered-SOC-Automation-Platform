import { PrismaClient, Prisma } from "@prisma/client";
import { Alert } from "../../../../domain/alert/entities/Alert.entity";
import { AlertMapper } from "../mappers/Alert.mapper";
import { buildAlertEvidence } from "../../../../domain/investigation/alertEvidence";
import {
  IIncidentRepository,
  IncidentTimelineEntry,
  CreateIncidentWithAlertsData,
  AlertAlreadyLinkedError,
  AlertAlreadyClosedError,
  AbsorbIntoIncidentData,
  MergeBlockedError,
} from "../../../../domain/incident/repositories/IIncidentRepository";
import { Incident, IncidentStatus } from "../../../../domain/incident/entities/Incident.entity";
import { IncidentMapper } from "../mappers/Incident.mapper";

export class PrismaIncidentRepository implements IIncidentRepository {
  constructor(private readonly prisma: PrismaClient | Prisma.TransactionClient) {}

  private transaction<T>(run: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    return "$transaction" in this.prisma ? this.prisma.$transaction(run) : run(this.prisma);
  }

  async createWithAlerts(data: CreateIncidentWithAlertsData): Promise<Incident> {
    try {
      const raw = await this.transaction(async (tx) => {
        // Row-locking re-check: an alert a SOC analyst closed (FALSE_POSITIVE / INFORMATIONAL) in the meantime is never
        // escalated. Undecided alerts record who escalated them.
        const open = await tx.alert.updateMany({
          where: {
            id: { in: data.alertIds },
            tenantId: data.tenantId,
            OR: [{ workflowState: { not: "TRIAGED" } }, { triageDisposition: null }, { triageDisposition: { notIn: ["FALSE_POSITIVE", "INFORMATIONAL"] } }],
          },
          data: { status: "escalated" },
        });
        if (open.count !== data.alertIds.length) throw new AlertAlreadyClosedError();
        await tx.alert.updateMany({
          where: { id: { in: data.alertIds }, tenantId: data.tenantId, triagedAt: null },
          data: { triagedBy: data.createdBy, triagedAt: new Date(), triageNote: data.note },
        });
        const incident = await tx.incident.create({
          data: { tenantId: data.tenantId, alertId: data.alertIds[0], title: data.title, priority: data.priority, status: "open" },
        });
        await tx.incidentAlert.createMany({ data: data.alertIds.map((alertId) => ({ incidentId: incident.id, alertId })) });
        await tx.alert.updateMany({ where: { id: { in: data.alertIds }, tenantId: data.tenantId }, data: { status: "escalated", workflowState: "TRIAGED" } });
        // Escalated = triage decided: closed_at is when it became part of an incident (kept if already set).
        await tx.alert.updateMany({ where: { id: { in: data.alertIds }, tenantId: data.tenantId, closedAt: null }, data: { closedAt: new Date() } });
        // Investigation #1 opens with the incident; each grouped alert becomes factual Evidence in it (Alert -> Evidence).
        const investigation = await tx.investigation.create({
          data: { incidentId: incident.id, investigationNumber: 1, status: "ACTIVE", createdBy: data.createdBy },
        });
        const alerts = await tx.alert.findMany({ where: { id: { in: data.alertIds }, tenantId: data.tenantId } });
        for (const a of alerts) {
          const d = buildAlertEvidence(a, investigation.id, "system");
          await tx.evidence.create({
            data: {
              investigationId: d.investigationId,
              alertId: d.alertId,
              type: d.type,
              source: d.source,
              origin: d.origin,
              timestamp: d.timestamp,
              title: d.title,
              description: d.description,
              structuredData: d.structuredData as Prisma.InputJsonValue,
              createdBy: d.createdBy,
            },
          });
        }
        await tx.incidentTimeline.create({
          data: {
            incidentId: incident.id,
            eventType: "created",
            description: data.timelineDescription ?? `Incident created manually from ${data.alertIds.length} alert(s)${data.note ? `: ${data.note}` : "."}`,
            actor: data.createdBy,
          },
        });
        return incident;
      });
      return IncidentMapper.toDomain(raw);
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") throw new AlertAlreadyLinkedError();
      throw err;
    }
  }

  async findByIds(ids: string[], tenantId: string): Promise<Incident[]> {
    if (ids.length === 0) return [];
    const rows = await this.prisma.incident.findMany({ where: { id: { in: [...new Set(ids)] }, tenantId } });
    return rows.map(IncidentMapper.toDomain);
  }

  async absorbIntoIncident(data: AbsorbIntoIncidentData): Promise<string[]> {
    return this.transaction(async (tx) => {
      const target = await tx.incident.findFirst({ where: { id: data.targetIncidentId, tenantId: data.tenantId } });
      if (!target || (target.status !== "open" && target.status !== "investigating")) {
        throw new MergeBlockedError("TARGET_NOT_OPEN", data.targetIncidentId);
      }

      const moved: string[] = [];
      for (const sourceId of [...new Set(data.sourceIncidentIds)]) {
        if (sourceId === target.id) throw new MergeBlockedError("SOURCE_IS_TARGET", sourceId);
        const source = await tx.incident.findFirst({ where: { id: sourceId, tenantId: data.tenantId } });
        if (!source) throw new MergeBlockedError("SOURCE_NOT_FOUND", sourceId);
        if (source.status === "resolved") throw new MergeBlockedError("SOURCE_RESOLVED", sourceId);
        if ((await tx.responsePlan.count({ where: { incidentId: sourceId } })) > 0) throw new MergeBlockedError("SOURCE_HAS_RESPONSE", sourceId);

        // Every alert of the source (its link rows plus its originating alert) moves to the target.
        const links = await tx.incidentAlert.findMany({ where: { incidentId: sourceId }, select: { alertId: true } });
        const alertIds = [...new Set([source.alertId, ...links.map((l) => l.alertId)])];
        await tx.incidentAlert.deleteMany({ where: { alertId: { in: alertIds } } });
        await tx.incidentAlert.createMany({ data: alertIds.map((alertId) => ({ incidentId: target.id, alertId })) });
        moved.push(...alertIds);

        const sourceAlerts = await tx.alert.findMany({ where: { id: { in: alertIds } }, select: { externalAlertId: true } });
        await tx.incident.update({ where: { id: sourceId }, data: { status: "dismissed", closedAt: new Date() } });
        await tx.incidentTimeline.create({
          data: {
            incidentId: sourceId,
            eventType: "merged",
            description: `Merged into incident ${target.id} by Set Group (alerts ${sourceAlerts.map((a) => a.externalAlertId).join(", ")} moved).`,
            actor: data.actor,
          },
        });
      }

      const unlinked = [...new Set(data.unlinkedAlertIds)];
      if (unlinked.length > 0) {
        await tx.incidentAlert.createMany({ data: unlinked.map((alertId) => ({ incidentId: target.id, alertId })) });
        moved.push(...unlinked);
      }

      const added = await tx.alert.findMany({ where: { id: { in: moved }, tenantId: data.tenantId }, select: { id: true, externalAlertId: true } });
      await tx.alert.updateMany({ where: { id: { in: moved }, tenantId: data.tenantId }, data: { status: "escalated", workflowState: "TRIAGED" } });
        // Escalated = triage decided: closed_at is when it became part of an incident (kept if already set).
        await tx.alert.updateMany({ where: { id: { in: moved }, tenantId: data.tenantId, closedAt: null }, data: { closedAt: new Date() } });
      for (const a of added) {
        await tx.incidentTimeline.create({
          data: {
            incidentId: target.id,
            eventType: "alert_added",
            description: data.timelineDescription?.(a.externalAlertId) ?? `Alert ${a.externalAlertId} added to the incident (Set Group).`,
            actor: data.actor,
          },
        });
      }
      return moved;
    });
  }

  async findLinkedIncidents(alertIds: string[], tenantId: string): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    if (alertIds.length === 0) return out;
    const [links, primaries] = await Promise.all([
      this.prisma.incidentAlert.findMany({ where: { alertId: { in: alertIds }, incident: { tenantId } } }),
      this.prisma.incident.findMany({ where: { alertId: { in: alertIds }, tenantId }, select: { id: true, alertId: true } }),
    ]);
    for (const p of primaries) out.set(p.alertId, p.id);
    for (const l of links) out.set(l.alertId, l.incidentId);
    return out;
  }

  async findAlerts(incidentId: string, tenantId: string): Promise<Alert[]> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, tenantId }, select: { alertId: true } });
    if (!incident) return [];
    const links = await this.prisma.incidentAlert.findMany({ where: { incidentId }, select: { alertId: true } });
    const ids = [...new Set([incident.alertId, ...links.map((l) => l.alertId)])];
    const rows = await this.prisma.alert.findMany({ where: { id: { in: ids }, tenantId }, orderBy: { receivedAt: "asc" } });
    return rows.map(AlertMapper.toDomain);
  }

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
    const finished = status === "resolved" || status === "dismissed";
    // The incident's current Investigation cycle follows its status: closed with the incident, reopened if the incident is.
    const raw = await this.transaction(async (tx) => {
      const updated = await tx.incident.update({ where: { id }, data: { status, closedAt: finished ? new Date() : null } });
      await tx.investigation.updateMany({
        where: { incidentId: id, investigationNumber: updated.investigationNumber },
        data: finished ? { status: "COMPLETED", completedAt: new Date() } : { status: "ACTIVE", completedAt: null },
      });
      return updated;
    });
    return IncidentMapper.toDomain(raw);
  }

  async addTimelineEntry(incidentId: string, entry: { eventType: string; description: string; actor: string }): Promise<void> {
    await this.prisma.incidentTimeline.create({ data: { incidentId, eventType: entry.eventType, description: entry.description, actor: entry.actor } });
  }

  async incrementInvestigationNumber(id: string, tenantId: string): Promise<Incident> {
    await this.prisma.incident.findFirstOrThrow({ where: { id, tenantId } });
    // The reopen and the new Investigation row are one transaction: the cycle that just failed verification is
    // completed and the next cycle starts empty - it does not inherit the previous cycle's evidence or IOCs.
    const raw = await this.transaction(async (tx) => {
      const updated = await tx.incident.update({
        where: { id },
        data: { investigationNumber: { increment: 1 }, status: "investigating", closedAt: null },
      });
      await tx.investigation.updateMany({
        where: { incidentId: id, investigationNumber: updated.investigationNumber - 1, status: "ACTIVE" },
        data: { status: "COMPLETED", completedAt: new Date() },
      });
      await tx.investigation.createMany({
        data: [{ incidentId: id, investigationNumber: updated.investigationNumber, status: "ACTIVE", createdBy: "system" }],
        skipDuplicates: true,
      });
      return updated;
    });
    return IncidentMapper.toDomain(raw);
  }
}
