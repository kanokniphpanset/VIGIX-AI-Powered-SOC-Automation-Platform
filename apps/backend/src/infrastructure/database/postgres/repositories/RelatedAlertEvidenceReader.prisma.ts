import { Prisma, PrismaClient } from "@prisma/client";
import { CandidateAlertRow, IncidentAlertFacts, IRelatedAlertEvidenceReader, RelatedAlertQuery } from "../../../../application/investigation/use-cases/RelatedAlertEvidence.usecase";

/** Read-only queries behind ListRelatedAlertEvidenceUseCase. Never writes, never links an alert to an incident. */
export class PrismaRelatedAlertEvidenceReader implements IRelatedAlertEvidenceReader {
  constructor(private readonly prisma: PrismaClient) {}

  async incidentFacts(incidentId: string, tenantId: string): Promise<IncidentAlertFacts | null> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, tenantId }, select: { alertId: true } });
    if (!incident) return null;
    const links = await this.prisma.incidentAlert.findMany({ where: { incidentId }, select: { alertId: true } });
    const alertIds = [...new Set([incident.alertId, ...links.map((l) => l.alertId)].filter((id): id is string => !!id))];
    const [alerts, iocs] = await Promise.all([
      this.prisma.alert.findMany({ where: { id: { in: alertIds }, tenantId }, select: { rawPayload: true, receivedAt: true } }),
      this.prisma.threatIntelIoc.findMany({ where: { incidentId }, select: { iocValue: true } }),
    ]);
    return { alertIds, alerts, iocValues: iocs.map((i) => i.iocValue) };
  }

  async candidates(q: RelatedAlertQuery): Promise<CandidateAlertRow[]> {
    const exclude = q.excludeAlertIds.length ? Prisma.sql`AND a.id NOT IN (${Prisma.join(q.excludeAlertIds)})` : Prisma.empty;
    const byHost = q.hosts.length
      ? Prisma.sql`(lower(a.raw_payload->'agent'->>'name') IN (${Prisma.join(q.hosts)}) AND a.received_at BETWEEN ${q.hostFrom} AND ${q.hostTo})`
      : Prisma.sql`FALSE`;
    // position() — a literal substring test (no LIKE wildcards in indicator values).
    const byIoc = q.iocValues.length
      ? Prisma.sql`(a.received_at BETWEEN ${q.iocFrom} AND ${q.iocTo} AND EXISTS (
          SELECT 1 FROM unnest(ARRAY[${Prisma.join(q.iocValues)}]::text[]) v WHERE position(v IN lower(a.raw_payload::text)) > 0))`
      : Prisma.sql`FALSE`;
    const rows = await this.prisma.$queryRaw<
      { id: string; external_alert_id: string; severity: string; received_at: Date; raw_payload: unknown; incident_id: string | null }[]
    >(Prisma.sql`
      SELECT a.id, a.external_alert_id, a.severity, a.received_at, a.raw_payload,
             COALESCE(ia.incident_id, (SELECT i.id FROM incidents i WHERE i.alert_id = a.id LIMIT 1)) AS incident_id
        FROM alerts a
        LEFT JOIN incident_alerts ia ON ia.alert_id = a.id
       WHERE a.tenant_id = ${q.tenantId} ${exclude}
         AND (${byHost} OR ${byIoc})
       ORDER BY a.received_at DESC
       LIMIT ${q.limit}`);
    return rows.map((r) => ({
      id: r.id,
      externalAlertId: r.external_alert_id,
      severity: r.severity,
      receivedAt: new Date(r.received_at),
      rawPayload: r.raw_payload,
      incidentId: r.incident_id,
    }));
  }
}
