import { Prisma, PrismaClient } from "@prisma/client";
import { IAlertInboxQuery, InboxQueryParams, InboxQueryRow } from "../../../../application/alert/ports/IAlertInboxQuery";
import { AlertMapper } from "../mappers/Alert.mapper";
import { OPEN_WORKFLOW_STATES, SOC_WORKFLOW_SEVERITIES } from "../../../../domain/alert/triageWorkflow";

const like = (q: string) => `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

/**
 * Alert Inbox in SQL. Filtering, SLA-due computation, ordering and pagination happen in Postgres, so every alert stays
 * discoverable regardless of age and nothing is loaded into memory beyond one page. Only MEDIUM / HIGH / CRITICAL alerts
 * (the SOC workflow) are returned. The review clock starts at received_at, or at review_at for a (legacy) monitored
 * alert that came back to the queue; targets come from Policy (TRIAGE_SLA).
 */
export class PrismaAlertInboxQuery implements IAlertInboxQuery {
  constructor(private readonly prisma: PrismaClient | Prisma.TransactionClient) {}

  async query(p: InboxQueryParams): Promise<{ rows: InboxQueryRow[]; total: number }> {
    if ("$transaction" in this.prisma) {
      return this.prisma.$transaction(tx => new PrismaAlertInboxQuery(tx).query(p), { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead });
    }
    const m = p.slaMinutes;
    const minutes = Prisma.sql`CASE upper(a.severity) WHEN 'CRITICAL' THEN ${m.CRITICAL ?? null}::int WHEN 'HIGH' THEN ${m.HIGH ?? null}::int
      WHEN 'MEDIUM' THEN ${m.MEDIUM ?? null}::int WHEN 'LOW' THEN ${m.LOW ?? null}::int END`;
    const dueAt = Prisma.sql`(CASE WHEN a.workflow_state IN ('NEW','IN_TRIAGE') AND a.review_at IS NOT NULL THEN a.review_at ELSE a.received_at END)
      + make_interval(mins => ${minutes})`;
    const sevRank = Prisma.sql`CASE lower(a.severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`;

    const isOpen = Prisma.sql`(COALESCE(a.workflow_state, 'NEW') IN (${Prisma.join(OPEN_WORKFLOW_STATES)}) AND i.id IS NULL)`;
    const where: Prisma.Sql[] = [Prisma.sql`a.tenant_id = ${p.tenantId}`, Prisma.sql`lower(a.severity) IN (${Prisma.join([...SOC_WORKFLOW_SEVERITIES])})`];
    if (p.status === "needs-review") where.push(isOpen);
    if (p.status === "in-incident") where.push(Prisma.sql`i.id IS NOT NULL`);
    if (p.status === "closed") where.push(Prisma.sql`(a.workflow_state = 'TRIAGED' AND i.id IS NULL)`);
    if (p.severity) where.push(Prisma.sql`lower(a.severity) = ${p.severity.toLowerCase()}`);
    if (p.source) where.push(Prisma.sql`lower(a.siem_source) = ${p.source.toLowerCase()}`);
    if (p.agent) where.push(Prisma.sql`lower(a.raw_payload->'agent'->>'name') = ${p.agent.trim().toLowerCase()}`);
    if (p.mitre) {
      const t = p.mitre.trim();
      where.push(Prisma.sql`EXISTS (SELECT 1 FROM jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(a.raw_payload->'rule'->'mitre'->'id') = 'array' THEN a.raw_payload->'rule'->'mitre'->'id' ELSE '[]'::jsonb END) mt(v)
        WHERE mt.v = ${t} OR mt.v LIKE ${`${t}.%`})`);
    }
    if (p.incident === "linked") where.push(Prisma.sql`i.id IS NOT NULL`);
    if (p.incident === "unlinked") where.push(Prisma.sql`i.id IS NULL`);
    if (p.scenarioIds) where.push(p.scenarioIds.length ? Prisma.sql`st.scenario_id IN (${Prisma.join(p.scenarioIds)})` : Prisma.sql`FALSE`);
    if (p.search?.trim()) {
      const q = like(p.search.trim());
      const byScenario = p.searchScenarioIds?.length ? Prisma.sql` OR st.scenario_id IN (${Prisma.join(p.searchScenarioIds)})` : Prisma.empty;
      where.push(Prisma.sql`(a.id ILIKE ${q} OR a.external_alert_id ILIKE ${q} OR a.raw_payload::text ILIKE ${q}${byScenario})`);
    }
    if (p.from) where.push(Prisma.sql`a.received_at >= ${p.from}`);
    if (p.to) where.push(Prisma.sql`a.received_at <= ${p.to}`);

    // An alert belongs to an incident through incident_alerts, or as the incident's originating alert (incidents.alert_id):
    // an incident opened automatically at ingestion has only the latter until investigation starts. A link row wins
    // (same precedence as IncidentRepository.findLinkedIncidents).
    const from = Prisma.sql`FROM alerts a
      LEFT JOIN LATERAL (
        SELECT inc.id, inc.title, inc.status, inc.priority FROM incidents inc
         WHERE inc.tenant_id = a.tenant_id
           AND (inc.alert_id = a.id OR EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id AND ia.incident_id = inc.id))
         ORDER BY EXISTS (SELECT 1 FROM incident_alerts ia WHERE ia.alert_id = a.id AND ia.incident_id = inc.id) DESC, inc.opened_at ASC
         LIMIT 1) i ON TRUE
      LEFT JOIN alert_scenario_tags st ON st.alert_id = a.id
      WHERE ${Prisma.join(where, " AND ")}`;

    const order =
      p.sort === "severity"
        ? Prisma.sql`${sevRank} DESC, a.received_at ASC, a.id ASC`
        : p.sort === "oldest"
          ? Prisma.sql`a.received_at ASC, a.id ASC`
          : p.sort === "newest"
            ? Prisma.sql`a.received_at DESC, a.id DESC`
            : Prisma.sql`CASE WHEN ${isOpen} THEN 0 ELSE 1 END ASC, due_at ASC NULLS LAST, ${sevRank} DESC, a.received_at ASC, a.id ASC`;

    const [page, count] = await Promise.all([
      this.prisma.$queryRaw<
        { id: string; due_at: Date | null; incident_id: string | null; incident_title: string | null; incident_status: string | null; incident_priority: string | null; scenario_id: string | null }[]
      >(Prisma.sql`SELECT a.id, ${dueAt} AS due_at, i.id AS incident_id, i.title AS incident_title, i.status AS incident_status,
          i.priority AS incident_priority, st.scenario_id
        ${from} ORDER BY ${order} LIMIT ${p.limit} OFFSET ${p.offset}`),
      this.prisma.$queryRaw<{ n: bigint }[]>(Prisma.sql`SELECT count(*) AS n ${from}`),
    ]);

    const alerts = new Map(
      (await this.prisma.alert.findMany({ where: { id: { in: page.map((r) => r.id) }, tenantId: p.tenantId } })).map((r) => [r.id, AlertMapper.toDomain(r)])
    );
    const rows: InboxQueryRow[] = page
      .filter((r) => alerts.has(r.id))
      .map((r) => ({
        alert: alerts.get(r.id)!,
        incident: r.incident_id ? { id: r.incident_id, title: r.incident_title ?? "", status: r.incident_status ?? "", priority: r.incident_priority ?? "" } : null,
        scenarioId: r.scenario_id,
        slaDueAt: r.due_at,
      }));
    return { rows, total: Number(count[0]?.n ?? 0) };
  }
}
