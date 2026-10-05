import { Prisma, PrismaClient } from "@prisma/client";
import { IIncidentCorrelationReader } from "../../../../application/alert/use-cases/IngestAlertFromSiem.usecase";
import { CORRELATION_HOST_WINDOW_MS, CORRELATION_IOC_WINDOW_MS, CorrelationCandidate, correlationLookup } from "../../../../domain/alert/alertCorrelation";

/** Incidents an alert may correlate with: at most this many are loaded (newest first). */
export const CORRELATION_CANDIDATE_LIMIT = 20;
const OPEN_STATUSES = ["open", "investigating"];

/**
 * Read-only lookup behind automatic alert correlation (IngestAlertFromSiem). Pre-filters in SQL to OPEN incidents
 * that hold an alert about the same host (±24 h) or an alert whose payload mentions one of this alert's indicators
 * (±7 days), or that record one of those indicators themselves; domain/alert/alertCorrelation.ts makes the decision.
 */
export class PrismaIncidentCorrelationReader implements IIncidentCorrelationReader {
  constructor(private readonly prisma: PrismaClient) {}

  async openCandidates(input: { tenantId: string; alertId: string; rawPayload: unknown; receivedAt: Date }): Promise<CorrelationCandidate[]> {
    const { host, indicatorValues, payloadNeedles } = correlationLookup({ rawPayload: input.rawPayload, receivedAt: input.receivedAt });
    if (!host && indicatorValues.length === 0) return [];
    const t = input.receivedAt.getTime();
    const byHost = host
      ? Prisma.sql`(lower(a.raw_payload->'agent'->>'name') = ${host} AND a.received_at BETWEEN ${new Date(t - CORRELATION_HOST_WINDOW_MS)} AND ${new Date(t + CORRELATION_HOST_WINDOW_MS)})`
      : Prisma.sql`FALSE`;
    // position() — a literal substring test (no LIKE wildcards in indicator values).
    const byIoc = payloadNeedles.length
      ? Prisma.sql`(a.received_at BETWEEN ${new Date(t - CORRELATION_IOC_WINDOW_MS)} AND ${new Date(t + CORRELATION_IOC_WINDOW_MS)} AND EXISTS (
          SELECT 1 FROM unnest(ARRAY[${Prisma.join(payloadNeedles)}]::text[]) v WHERE position(v IN lower(a.raw_payload::text)) > 0))`
      : Prisma.sql`FALSE`;
    const byRecordedIoc = indicatorValues.length
      ? Prisma.sql`UNION
        SELECT i.id, i.opened_at FROM incidents i
          JOIN threat_intel_iocs t ON t.incident_id = i.id
         WHERE i.tenant_id = ${input.tenantId} AND i.status IN (${Prisma.join(OPEN_STATUSES)})
           AND t.status = 'ACTIVE' AND lower(t.ioc_value) IN (${Prisma.join(indicatorValues)})`
      : Prisma.empty;

    const rows = await this.prisma.$queryRaw<{ id: string; opened_at: Date }[]>(Prisma.sql`
      SELECT DISTINCT c.id, c.opened_at FROM (
        SELECT i.id, i.opened_at
          FROM alerts a
          LEFT JOIN incident_alerts ia ON ia.alert_id = a.id
          JOIN incidents i ON i.id = COALESCE(ia.incident_id, (SELECT p.id FROM incidents p WHERE p.alert_id = a.id LIMIT 1))
         WHERE a.tenant_id = ${input.tenantId} AND a.id <> ${input.alertId}
           AND i.tenant_id = ${input.tenantId} AND i.status IN (${Prisma.join(OPEN_STATUSES)})
           AND (${byHost} OR ${byIoc})
        ${byRecordedIoc}
      ) c
      ORDER BY c.opened_at DESC
      LIMIT ${CORRELATION_CANDIDATE_LIMIT}`);
    if (rows.length === 0) return [];

    const ids = rows.map((r) => r.id);
    const [incidents, links, iocs] = await Promise.all([
      this.prisma.incident.findMany({ where: { id: { in: ids }, tenantId: input.tenantId }, select: { id: true, alertId: true, openedAt: true } }),
      this.prisma.incidentAlert.findMany({ where: { incidentId: { in: ids } }, select: { incidentId: true, alertId: true } }),
      this.prisma.threatIntelIoc.findMany({ where: { incidentId: { in: ids }, status: "ACTIVE" }, select: { incidentId: true, iocType: true, iocValue: true } }),
    ]);
    const alertIdsByIncident = new Map<string, Set<string>>(incidents.map((i) => [i.id, new Set([i.alertId])]));
    for (const l of links) alertIdsByIncident.get(l.incidentId)?.add(l.alertId);
    const alertIds = [...new Set([...alertIdsByIncident.values()].flatMap((s) => [...s]))].filter((id) => id !== input.alertId);
    const alerts = await this.prisma.alert.findMany({ where: { id: { in: alertIds }, tenantId: input.tenantId }, select: { id: true, rawPayload: true, receivedAt: true } });
    const alertById = new Map(alerts.map((a) => [a.id, a]));

    return incidents.map((i) => ({
      incidentId: i.id,
      openedAt: i.openedAt,
      alerts: [...(alertIdsByIncident.get(i.id) ?? [])].map((id) => alertById.get(id)).filter((a): a is NonNullable<typeof a> => !!a).map((a) => ({ rawPayload: a.rawPayload, receivedAt: a.receivedAt })),
      iocs: iocs.filter((x) => x.incidentId === i.id).map((x) => ({ iocType: x.iocType, value: x.iocValue })),
    }));
  }
}
