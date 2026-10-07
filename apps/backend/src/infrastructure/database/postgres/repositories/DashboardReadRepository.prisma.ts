import { PrismaClient } from "@prisma/client";
import { DashboardCounts, IDashboardReadRepository, OpenIncidentRow } from "../../../../application/dashboard/ports/IDashboardReadRepository";
import { stripAiSeverity } from "../../../../domain/ai/aiGrounding";

type Row = Record<string, unknown>;
const n = (v: unknown) => Number(v ?? 0);
const toMap = (rows: Row[], key: string) => Object.fromEntries(rows.map((r) => [String(r[key]), n(r.n)]));

/** Dashboard aggregates in SQL (tenant-scoped, read-only). */
export class PrismaDashboardReadRepository implements IDashboardReadRepository {
  constructor(private readonly prisma: PrismaClient) {}

  private q(sql: string, ...params: unknown[]): Promise<Row[]> {
    return this.prisma.$queryRawUnsafe<Row[]>(sql, ...params);
  }

  async counts(tenantId: string, days: number, since?: Date | null): Promise<DashboardCounts> {
    const t = tenantId;
    // Report window: `p` binds $2 = window start, `win(col)` adds the filter. Columns are UTC `timestamp` (no zone).
    const p: unknown[] = since ? [t, since.toISOString()] : [t];
    const win = (col: string) => (since ? ` and ${col} >= ($2::timestamptz at time zone 'utc')` : "");
    const [
      alertTotals,
      alertSev,
      alertDaily,
      incStatus,
      incPriority,
      incTimes,
      respStatus,
      approvals,
      verif,
      techniques,
      sources,
      activity,
      aiJobs,
      triage,
      approvalChain,
      verifDetail,
      severityRows,
      kpiInvestigation,
      kpiDecision,
      workload,
      recReady,
    ] = await Promise.all([
      this.q(
        `select count(*) total,
                count(*) filter (where received_at > now() - interval '24 hours') last24h,
                count(*) filter (where not exists (select 1 from incident_alerts ia where ia.alert_id = a.id)
                                   and not exists (select 1 from incidents i where i.alert_id = a.id)) unlinked
           from alerts a where tenant_id = $1${win("a.received_at")}`,
        ...p
      ),
      this.q(`select lower(severity) k, count(*) n from alerts where tenant_id = $1${win("received_at")} group by 1`, ...p),
      this.q(
        `select to_char(d.day, 'YYYY-MM-DD') date,
                count(a.id) filter (where lower(a.severity) = 'critical') critical,
                count(a.id) filter (where lower(a.severity) = 'high') high,
                count(a.id) filter (where lower(a.severity) = 'medium') medium,
                count(a.id) filter (where lower(a.severity) = 'low') low
           from generate_series((now() at time zone 'utc')::date - ($2::int - 1), (now() at time zone 'utc')::date, interval '1 day') d(day)
           left join alerts a on a.tenant_id = $1 and (a.received_at at time zone 'utc')::date = d.day::date
          group by d.day order by d.day`,
        t,
        days
      ),
      this.q(`select status k, count(*) n from incidents where tenant_id = $1${win("opened_at")} group by 1`, ...p),
      this.q(`select priority k, count(*) n from incidents where tenant_id = $1 and status in ('open','investigating','escalated') group by 1`, t),
      this.q(
        `select avg(extract(epoch from (closed_at - opened_at)) / 60) filter (where status = 'resolved' and closed_at is not null) mttr,
                count(*) filter (where status = 'resolved' and closed_at > now() - interval '7 days') resolved7,
                count(*) filter (where opened_at > now() - interval '7 days') opened7,
                count(*) total
           from incidents where tenant_id = $1${win("opened_at")}`,
        ...p
      ),
      this.q(`select status k, count(*) n from response_plans where tenant_id = $1${win("created_at")} group by 1`, ...p),
      this.q(
        `select a.approval_role k, count(*) n
           from approvals a join recommendations r on r.id = a.recommendation_id
          where r.tenant_id = $1 and a.status = 'pending' group by 1`,
        t
      ),
      this.q(`select result k, count(*) n from verifications where tenant_id = $1${win("verified_at")} group by 1`, ...p),
      this.q(
        `select m.technique_id, min(m.tactic) tactic, count(distinct m.incident_id) n
           from mitre_mappings m join incidents i on i.id = m.incident_id
          where i.tenant_id = $1 and i.status <> 'dismissed'${win("i.opened_at")}
          group by 1 order by n desc, 1 limit 6`,
        ...p
      ),
      this.q(
        `select t.ioc_value v, count(distinct t.incident_id) n
           from threat_intel_iocs t join incidents i on i.id = t.incident_id
           join evidence_iocs ei on ei.ioc_id = t.id
          where i.tenant_id = $1 and i.status <> 'dismissed' and t.ioc_type in ('IPV4','IPV6')${win("i.opened_at")}
          group by 1 order by n desc, 1 limit 6`,
        ...p
      ),
      this.q(
        `select tl.occurred_at, tl.incident_id, i.title, tl.event_type, tl.description, tl.actor
           from incident_timeline tl join incidents i on i.id = tl.incident_id
          where i.tenant_id = $1 order by tl.occurred_at desc limit 12`,
        t
      ),
      this.q(
        `select upper(e.status) k, count(*) n from agent_executions e join incidents i on i.id = e.incident_id
          where i.tenant_id = $1${win("e.queued_at")} group by 1`,
        ...p
      ),
      this.q(
        `select count(*) filter (where a.triage_disposition is null and a.status not in ('closed','escalated','monitoring')) pending,
                count(*) filter (where a.triage_disposition is null and a.status not in ('closed','escalated','monitoring') and lower(a.severity) = 'low') pending_low,
                count(*) filter (where a.status = 'monitoring') monitoring,
                count(*) filter (where a.triage_disposition = 'FALSE_POSITIVE') false_positive,
                count(*) filter (where a.triage_disposition = 'INFORMATIONAL') informational,
                count(*) filter (where a.triage_disposition = 'MONITOR') monitor
           from alerts a
          where a.tenant_id = $1
            and not exists (select 1 from incident_alerts ia where ia.alert_id = a.id)
            and not exists (select 1 from incidents i where i.alert_id = a.id)`,
        t
      ),
      this.q(
        `select coalesce(ap.approval_role, 'UNKNOWN') role, ap.status k, count(*) n
           from approvals ap
           left join response_plans p on p.id = ap.response_id
           left join recommendations r on r.id = coalesce(p.recommendation_id, ap.recommendation_id)
           join incidents i on i.id = coalesce(p.incident_id, r.incident_id)
          where i.tenant_id = $1${win("ap.created_at")} group by 1, 2`,
        ...p
      ),
      this.q(
        `select (select count(*) from verifications v where v.tenant_id = $1 and v.spread_detected${win("v.verified_at")}) spread,
                (select count(*) from response_plans p where p.tenant_id = $1 and p.status = 'COMPLETED'
                    and not exists (select 1 from verifications v where v.response_id = p.id)) awaiting_rehunt,
                (select count(*) from audit_logs al where al.tenant_id = $1 and al.action in ('INCIDENT_ESCALATED','INVESTIGATION_ESCALATED')${win("al.created_at")}) escalation_events,
                (select count(distinct al.entity_id) from audit_logs al where al.tenant_id = $1 and al.action in ('INCIDENT_ESCALATED','INVESTIGATION_ESCALATED')${win("al.created_at")}) escalated_incidents`,
        ...p
      ),
      this.q(
        `select upper(i.priority) k, count(*) n from incidents i where i.tenant_id = $1 and i.status <> 'dismissed'${win("i.opened_at")} group by 1`,
        ...p
      ),
      this.q(
        `select avg(extract(epoch from (fr.first_at - i.opened_at)) / 60) avg_min, count(*) n
           from incidents i
           join lateral (select min(r.created_at) first_at from recommendations r where r.incident_id = i.id) fr on fr.first_at is not null
          where i.tenant_id = $1 and fr.first_at >= i.opened_at${win("i.opened_at")}`,
        ...p
      ),
      this.q(
        `select avg(extract(epoch from (c.decided - c.requested)) / 60) avg_min, count(*) n from (
           select min(ap.created_at) requested, max(ap.decided_at) decided
             from approvals ap join response_plans p on p.id = ap.response_id
            where p.tenant_id = $1
            group by ap.response_id
           having bool_and(ap.status in ('approved','rejected','more_evidence_requested','cancelled'))
              and max(ap.decided_at) is not null${win("min(ap.created_at)")}) c`,
        ...p
      ),
      this.q(
        `select coalesce(u.email, p.assigned_to) assignee, u.role, p.assigned_role, count(*) n
           from response_plans p left join users u on u.id = p.assigned_to
          where p.tenant_id = $1
            and (p.status in ('READY_FOR_EXECUTION','APPROVED','IN_PROGRESS')
                 or (p.status = 'COMPLETED' and not exists (select 1 from verifications v where v.response_id = p.id)))
          group by 1, 2, 3 order by n desc`,
        t
      ),
      this.q(
        `select count(*) n from incidents i
          where i.tenant_id = $1 and i.status in ('open','investigating')
            and exists (select 1 from recommendations r where r.incident_id = i.id and r.investigation_number = i.investigation_number and r.status = 'VALIDATED')
            and not exists (select 1 from response_plans p join recommendations r on r.id = p.recommendation_id
                             where p.incident_id = i.id and r.investigation_number = i.investigation_number)`,
        t
      ),
    ]);

    const byRoleStatus: Record<string, Record<string, number>> = {};
    for (const r of approvalChain) (byRoleStatus[String(r.role)] ??= {})[String(r.k)] = n(r.n);
    const severityDistribution = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, unknown: 0 };
    for (const r of severityRows) {
      const k = String(r.k) as keyof typeof severityDistribution;
      if (k === "LOW" || k === "MEDIUM" || k === "HIGH" || k === "CRITICAL") severityDistribution[k] += n(r.n);
      else severityDistribution.unknown += n(r.n);
    }
    const jobs = toMap(aiJobs, "k");
    const finished = (jobs.SUCCESS ?? 0) + (jobs.PARTIAL_SUCCESS ?? 0) + (jobs.FAILED ?? 0);
    const tr = triage[0] ?? {};
    const vd = verifDetail[0] ?? {};
    const inv = kpiInvestigation[0] ?? {};
    const dec = kpiDecision[0] ?? {};
    const minutes = (v: unknown) => (v == null ? null : Math.round(Number(v)));

    const times = incTimes[0] ?? {};
    return {
      alerts: {
        total: n(alertTotals[0]?.total),
        last24h: n(alertTotals[0]?.last24h),
        unlinked: n(alertTotals[0]?.unlinked),
        bySeverity: toMap(alertSev, "k"),
        daily: alertDaily.map((r) => ({ date: String(r.date), critical: n(r.critical), high: n(r.high), medium: n(r.medium), low: n(r.low) })),
      },
      incidents: {
        total: n(times.total),
        byStatus: toMap(incStatus, "k"),
        openByPriority: toMap(incPriority, "k"),
        mttrMinutes: times.mttr == null ? null : Math.round(Number(times.mttr)),
        resolvedLast7d: n(times.resolved7),
        openedLast7d: n(times.opened7),
      },
      responses: { byStatus: toMap(respStatus, "k"), pendingApprovalsByRole: toMap(approvals, "k") },
      verifications: { byResult: toMap(verif, "k") },
      topTechniques: techniques.map((r) => ({ techniqueId: String(r.technique_id), tactic: String(r.tactic ?? ""), incidents: n(r.n) })),
      topSources: sources.map((r) => ({ value: String(r.v), incidents: n(r.n) })),
      activity: activity.map((r) => ({
        occurredAt: new Date(r.occurred_at as string).toISOString(),
        incidentId: String(r.incident_id),
        incidentTitle: String(r.title),
        eventType: String(r.event_type),
        description: stripAiSeverity(String(r.description)).text,
        actor: String(r.actor),
      })),
      aiJobs: { byStatus: jobs, total: Object.values(jobs).reduce((a, b) => a + b, 0) },
      triage: {
        pending: n(tr.pending),
        pendingLow: n(tr.pending_low),
        monitoring: n(tr.monitoring),
        byDisposition: { FALSE_POSITIVE: n(tr.false_positive), INFORMATIONAL: n(tr.informational), MONITOR: n(tr.monitor) },
      },
      approvals: { byRoleStatus },
      verificationDetail: {
        spread: n(vd.spread),
        awaitingRehunt: n(vd.awaiting_rehunt),
        escalationEvents: n(vd.escalation_events),
        escalatedIncidents: n(vd.escalated_incidents),
      },
      severityDistribution,
      recommendationReady: n(recReady[0]?.n),
      kpi: {
        investigationTimeMinutes: n(inv.n) ? minutes(inv.avg_min) : null,
        investigationSamples: n(inv.n),
        timeToDecisionMinutes: n(dec.n) ? minutes(dec.avg_min) : null,
        decisionSamples: n(dec.n),
        workload: workload.map((r) => ({
          assignee: r.assignee == null ? `Unassigned (${String(r.assigned_role)})` : String(r.assignee),
          role: r.assignee == null ? String(r.assigned_role) : r.role == null ? null : String(r.role),
          open: n(r.n),
        })),
        automationSuccessRate: finished ? Math.round((((jobs.SUCCESS ?? 0) + (jobs.PARTIAL_SUCCESS ?? 0)) / finished) * 100) : null,
        automationFinished: finished,
      },
    };
  }

  async ping(): Promise<number> {
    const started = Date.now();
    await this.q("select 1");
    return Date.now() - started;
  }

  async openIncidents(tenantId: string, limit: number): Promise<OpenIncidentRow[]> {
    const rows = await this.prisma.incident.findMany({
      where: { tenantId, status: { in: ["open", "investigating", "escalated"] } },
      orderBy: { openedAt: "desc" },
      take: limit,
      select: { id: true, title: true, status: true, priority: true, openedAt: true, closedAt: true },
    });
    return rows;
  }
}
