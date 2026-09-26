import { PrismaClient, Prisma } from "@prisma/client";
import { IInvestigationRepository } from "../../../../domain/investigation/IInvestigationRepository";
import {
  CreateEvidenceData,
  CreateIocData,
  DuplicateIocError,
  EvidenceDetail,
  EvidenceOrigin,
  EvidenceRecord,
  InvestigationRecord,
  InvestigationStatus,
  IocRecord,
} from "../../../../domain/investigation/Investigation.types";
import { buildAlertEvidence } from "../../../../domain/investigation/alertEvidence";
import { extractAlertIocs } from "../../../../domain/investigation/alertIocs";
import { checkIocValue } from "../../../../application/investigation/iocValidation";

type EvidenceRow = Prisma.EvidenceGetPayload<{ include: { iocLinks: true } }>;
type IocRow = Prisma.ThreatIntelIocGetPayload<{ include: { evidenceLinks: true } }>;

const toEvidence = (r: EvidenceRow): EvidenceRecord => ({
  id: r.id,
  investigationId: r.investigationId,
  alertId: r.alertId,
  type: r.type,
  source: r.source,
  origin: r.origin as EvidenceOrigin,
  timestamp: r.timestamp,
  title: r.title,
  description: r.description,
  rawData: r.rawData,
  structuredData: r.structuredData,
  confidence: r.confidence,
  relevance: r.relevance,
  createdBy: r.createdBy,
  createdAt: r.createdAt,
  iocIds: r.iocLinks.map((l) => l.iocId),
});

const toIoc = (r: IocRow): IocRecord => ({
  id: r.id,
  incidentId: r.incidentId,
  investigationId: r.investigationId,
  iocType: r.iocType,
  iocValue: r.iocValue,
  source: r.source,
  reputationScore: r.reputationScore,
  confidence: r.confidence,
  status: r.status,
  firstSeen: r.firstSeen,
  lastSeen: r.lastSeen,
  createdBy: r.createdBy,
  createdAt: r.createdAt,
  sourceAlertId: r.sourceAlertId ?? null,
  addedReason: r.addedReason ?? null,
  evidenceIds: r.evidenceLinks.map((l) => l.evidenceId),
});

const json = (v: unknown): Prisma.InputJsonValue | undefined => (v === null || v === undefined ? undefined : (v as Prisma.InputJsonValue));

export class PrismaInvestigationRepository implements IInvestigationRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async syncIncident(incidentId: string, tenantId: string): Promise<void> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, tenantId } });
    if (!incident) return;

    // 1. A row for every cycle 1..N.
    const have = new Set((await this.prisma.investigation.findMany({ where: { incidentId }, select: { investigationNumber: true } })).map((i) => i.investigationNumber));
    const missing: Prisma.InvestigationCreateManyInput[] = [];
    for (let n = 1; n <= incident.investigationNumber; n++) {
      if (have.has(n)) continue;
      const finished = n < incident.investigationNumber || incident.status === "resolved" || incident.status === "dismissed";
      missing.push({
        incidentId,
        investigationNumber: n,
        status: finished ? "COMPLETED" : "ACTIVE",
        startedAt: incident.openedAt,
        completedAt: finished ? (incident.closedAt ?? new Date()) : null,
        createdBy: "system",
      });
    }
    if (missing.length > 0) await this.prisma.investigation.createMany({ data: missing, skipDuplicates: true });

    const first = await this.prisma.investigation.findUnique({ where: { incidentId_investigationNumber: { incidentId, investigationNumber: 1 } } });
    if (!first) return;

    // The originating alert is part of the incident's alert set too (the orchestrator writes only Incident.alertId).
    await this.prisma.incidentAlert.createMany({ data: [{ incidentId, alertId: incident.alertId }], skipDuplicates: true });

    // 2. IOCs the orchestrator wrote without a cycle belong to cycle #1 (before step 3 adds alert IOCs to that cycle,
    //    so an identical (type, value) is reused rather than colliding). A value already in the cycle stays unassigned.
    const orphans = await this.prisma.threatIntelIoc.findMany({ where: { incidentId, investigationId: null }, select: { id: true } });
    for (const o of orphans) {
      try {
        await this.prisma.threatIntelIoc.update({ where: { id: o.id }, data: { investigationId: first.id } });
      } catch (err) {
        if (!(err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002")) throw err;
      }
    }

    // 3. WAZUH_ALERT-type evidence for every grouped alert (cycle #1), once each, linked to the IOCs the alert states.
    const links = await this.prisma.incidentAlert.findMany({ where: { incidentId }, select: { alertId: true } });
    const alertIds = [...new Set([incident.alertId, ...links.map((l) => l.alertId)])];
    const existing = await this.prisma.evidence.findMany({ where: { investigationId: first.id, type: "WAZUH_ALERT", alertId: { in: alertIds } }, select: { alertId: true } });
    const done = new Set(existing.map((e) => e.alertId));
    const todo = alertIds.filter((id) => !done.has(id));
    if (todo.length > 0) {
      const alerts = await this.prisma.alert.findMany({ where: { id: { in: todo }, tenantId } });
      for (const a of alerts) {
        const d = buildAlertEvidence(a, first.id, "system");
        await this.prisma.evidence.create({
          data: {
            investigationId: d.investigationId,
            alertId: d.alertId,
            type: d.type,
            source: d.source,
            origin: d.origin,
            timestamp: d.timestamp,
            title: d.title,
            description: d.description,
            structuredData: json(d.structuredData),
            createdBy: d.createdBy,
          },
        });
      }
    }
    await this.linkAlertIocs(incidentId, first.id, alertIds, tenantId);

    // 4. Recommendations point at the Investigation row of the cycle they were generated from.
    const all = await this.prisma.investigation.findMany({ where: { incidentId }, select: { id: true, investigationNumber: true } });
    for (const inv of all) {
      await this.prisma.recommendation.updateMany({
        where: { incidentId, investigationNumber: inv.investigationNumber, investigationId: null },
        data: { investigationId: inv.id },
      });
    }
  }

  /**
   * For each alert's WAZUH_ALERT evidence in the cycle: the indicators the alert states (extractAlertIocs,
   * validated by checkIocValue) exist as IOCs of that cycle and are linked to the evidence. Idempotent;
   * an existing IOC with the same (type, value) - e.g. one the orchestrator wrote - is reused.
   */
  private async linkAlertIocs(incidentId: string, investigationId: string, alertIds: string[], tenantId: string): Promise<void> {
    const evidence = await this.prisma.evidence.findMany({
      where: { investigationId, type: "WAZUH_ALERT", alertId: { in: alertIds } },
      select: { id: true, alertId: true, timestamp: true, alert: { select: { rawPayload: true, tenantId: true } } },
    });
    for (const ev of evidence) {
      if (!ev.alert || ev.alert.tenantId !== tenantId) continue;
      const iocIds: string[] = [];
      for (const found of extractAlertIocs(ev.alert.rawPayload)) {
        const checked = checkIocValue(found.iocType, found.value);
        if (!checked.ok) continue;
        const key = { investigationId, iocType: found.iocType, iocValue: checked.value };
        const ioc =
          (await this.prisma.threatIntelIoc.findFirst({ where: key, select: { id: true } })) ??
          (await this.prisma.threatIntelIoc.create({
            data: { ...key, incidentId, source: "ALERT", status: "ACTIVE", firstSeen: ev.timestamp, lastSeen: ev.timestamp, createdBy: "system" },
            select: { id: true },
          }));
        iocIds.push(ioc.id);
      }
      if (iocIds.length > 0) {
        await this.prisma.evidenceIoc.createMany({ data: [...new Set(iocIds)].map((iocId) => ({ evidenceId: ev.id, iocId })), skipDuplicates: true });
      }
    }
  }

  private async toInvestigation(
    row: Prisma.InvestigationGetPayload<{ include: { _count: { select: { evidence: true; iocs: true } } } }>,
    currentNumber: number
  ): Promise<InvestigationRecord> {
    return {
      id: row.id,
      incidentId: row.incidentId,
      investigationNumber: row.investigationNumber,
      status: row.status as InvestigationStatus,
      startedAt: row.startedAt,
      completedAt: row.completedAt,
      createdBy: row.createdBy,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      evidenceCount: row._count.evidence,
      iocCount: row._count.iocs,
      isCurrent: row.investigationNumber === currentNumber,
    };
  }

  async listByIncident(incidentId: string, tenantId: string): Promise<InvestigationRecord[]> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, tenantId }, select: { investigationNumber: true } });
    if (!incident) return [];
    const rows = await this.prisma.investigation.findMany({
      where: { incidentId },
      orderBy: { investigationNumber: "asc" },
      include: { _count: { select: { evidence: true, iocs: true } } },
    });
    return Promise.all(rows.map((r) => this.toInvestigation(r, incident.investigationNumber)));
  }

  async findById(id: string, tenantId: string): Promise<InvestigationRecord | null> {
    const row = await this.prisma.investigation.findFirst({
      where: { id, incident: { tenantId } },
      include: { _count: { select: { evidence: true, iocs: true } }, incident: { select: { investigationNumber: true } } },
    });
    return row ? this.toInvestigation(row, row.incident.investigationNumber) : null;
  }

  async listEvidence(investigationId: string): Promise<EvidenceRecord[]> {
    const rows = await this.prisma.evidence.findMany({ where: { investigationId }, include: { iocLinks: true }, orderBy: [{ timestamp: "desc" }, { createdAt: "desc" }] });
    return rows.map(toEvidence);
  }

  async findEvidence(id: string, tenantId: string): Promise<EvidenceDetail | null> {
    const row = await this.prisma.evidence.findFirst({
      where: { id, investigation: { incident: { tenantId } } },
      include: { iocLinks: { include: { ioc: { include: { evidenceLinks: true } } } }, alert: true },
    });
    if (!row) return null;
    return {
      ...toEvidence(row),
      iocs: row.iocLinks.map((l) => toIoc(l.ioc)),
      alert: row.alert
        ? {
            id: row.alert.id,
            externalAlertId: row.alert.externalAlertId,
            siemSource: row.alert.siemSource,
            severity: row.alert.severity,
            receivedAt: row.alert.receivedAt,
            rawPayload: row.alert.rawPayload,
          }
        : null,
    };
  }

  async createEvidence(data: CreateEvidenceData): Promise<EvidenceRecord> {
    const row = await this.prisma.evidence.create({
      data: {
        investigationId: data.investigationId,
        alertId: data.alertId,
        type: data.type,
        source: data.source,
        origin: data.origin,
        timestamp: data.timestamp,
        title: data.title,
        description: data.description,
        rawData: json(data.rawData),
        structuredData: json(data.structuredData),
        confidence: data.confidence,
        relevance: data.relevance,
        createdBy: data.createdBy,
        iocLinks: { create: [...new Set(data.iocIds)].map((iocId) => ({ iocId })) },
      },
      include: { iocLinks: true },
    });
    return toEvidence(row);
  }

  async listIocs(investigationId: string): Promise<IocRecord[]> {
    const rows = await this.prisma.threatIntelIoc.findMany({ where: { investigationId }, include: { evidenceLinks: true }, orderBy: { createdAt: "asc" } });
    return rows.map(toIoc);
  }

  async findIocsByIds(ids: string[], investigationId: string): Promise<IocRecord[]> {
    if (ids.length === 0) return [];
    const rows = await this.prisma.threatIntelIoc.findMany({ where: { id: { in: ids }, investigationId }, include: { evidenceLinks: true } });
    return rows.map(toIoc);
  }

  async createIoc(data: CreateIocData): Promise<IocRecord> {
    try {
      const row = await this.prisma.threatIntelIoc.create({
        data: {
          incidentId: data.incidentId,
          investigationId: data.investigationId,
          iocType: data.iocType,
          iocValue: data.iocValue,
          source: data.source,
          reputationScore: data.reputationScore,
          confidence: data.confidence,
          status: data.status,
          firstSeen: data.firstSeen,
          lastSeen: data.lastSeen,
          createdBy: data.createdBy,
          sourceAlertId: data.sourceAlertId ?? null,
          addedReason: data.addedReason ?? null,
        },
        include: { evidenceLinks: true },
      });
      return toIoc(row);
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        const existing = await this.prisma.threatIntelIoc.findFirst({
          where: { investigationId: data.investigationId, iocType: data.iocType, iocValue: data.iocValue },
          select: { id: true },
        });
        throw new DuplicateIocError(existing?.id ?? null);
      }
      throw err;
    }
  }
}
