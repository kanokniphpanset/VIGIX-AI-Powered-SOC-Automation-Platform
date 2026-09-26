import { PrismaClient } from "@prisma/client";
import { AiJobRow, AuditEntry, IncidentWorkFilters, IncidentWorkRow, IWorkReadRepository } from "../../../../application/work/ports/IWorkReadRepository";
import { ApprovalQueueRow, ApprovalStepRow, TicketRow } from "../../../../application/work/WorkQueues";
import { stripAiSeverity } from "../../../../domain/ai/aiGrounding";

type Row = Record<string, unknown>;
const iso = (v: unknown): string | null => (v == null ? null : new Date(v as string).toISOString());
const str = (v: unknown): string | null => (v == null ? null : String(v));
const num = (v: unknown): number | null => (v == null ? null : Number(v));


const CHAIN_SQL = (alias: string) => `(select coalesce(json_agg(json_build_object(
      'id', x.id, 'role', x.approval_role, 'status', x.status, 'stepOrder', x.step_order,
      'decidedBy', x.decided_by, 'decidedAt', x.decided_at, 'createdAt', x.created_at) order by x.step_order, x.created_at), '[]'::json)
    from approvals x where x.response_id = ${alias})`;

function chain(v: unknown): ApprovalStepRow[] {
  const arr = (typeof v === "string" ? JSON.parse(v) : v) as Row[] | null;
  return (arr ?? []).map((a) => ({
    id: String(a.id),
    role: str(a.role),
    status: String(a.status),
    stepOrder: Number(a.stepOrder ?? 1),
    decidedBy: str(a.decidedBy),
    decidedAt: iso(a.decidedAt),
    createdAt: iso(a.createdAt) ?? "",
  }));
}

/** Read-only SQL projections for the role workspaces (Tickets / Approvals / Incidents / Audit / AI jobs). */
export class PrismaWorkReadRepository implements IWorkReadRepository {
  constructor(private readonly prisma: PrismaClient) {}

  private q(sql: string, ...params: unknown[]): Promise<Row[]> {
    return this.prisma.$queryRawUnsafe<Row[]>(sql, ...params);
  }

  async tickets(tenantId: string, limit: number): Promise<TicketRow[]> {
    const rows = await this.q(
      `select p.id, p.incident_id, p.recommendation_id, p.recommendation_step_id, p.target, p.status, p.approval_status,
              p.assigned_role, p.assigned_to, u.email assigned_to_email, p.executed_at, p.completed_at, p.created_at, p.updated_at,
              i.title incident_title, i.status incident_status, i.priority incident_priority, i.investigation_number,
              s.title step_title, s.step_order, a.code action_code, a.name action_name,
              v.id verification_id, v.result verification_result, v.spread_detected, v.verified_at,
              ${CHAIN_SQL("p.id")} approvals
         from response_plans p
         join incidents i on i.id = p.incident_id
         left join recommendation_steps s on s.id = p.recommendation_step_id
         left join actions a on a.id = p.action_id
         left join verifications v on v.response_id = p.id
         left join users u on u.id = p.assigned_to
        where p.tenant_id = $1
        order by p.created_at desc
        limit $2`,
      tenantId,
      limit
    );
    return rows.map((r) => ({
      id: String(r.id),
      incidentId: String(r.incident_id),
      incidentTitle: String(r.incident_title),
      incidentStatus: String(r.incident_status),
      incidentPriority: String(r.incident_priority),
      investigationNumber: Number(r.investigation_number ?? 1),
      recommendationId: String(r.recommendation_id),
      recommendationStepId: str(r.recommendation_step_id),
      stepTitle: str(r.step_title),
      stepOrder: num(r.step_order),
      actionCode: str(r.action_code),
      actionName: str(r.action_name),
      target: str(r.target),
      status: String(r.status),
      approvalStatus: String(r.approval_status),
      assignedRole: String(r.assigned_role),
      assignedTo: str(r.assigned_to),
      assignedToEmail: str(r.assigned_to_email),
      executedAt: iso(r.executed_at),
      completedAt: iso(r.completed_at),
      createdAt: iso(r.created_at) ?? "",
      updatedAt: iso(r.updated_at) ?? "",
      approvals: chain(r.approvals),
      verification: r.verification_id
        ? { id: String(r.verification_id), result: String(r.verification_result), spreadDetected: !!r.spread_detected, verifiedAt: iso(r.verified_at) ?? "" }
        : null,
    }));
  }

  async approvals(tenantId: string, limit: number): Promise<ApprovalQueueRow[]> {
    const rows = await this.q(
      `select ap.id, ap.approval_role, ap.status, ap.step_order, ap.reason, ap.comment, ap.decided_by, du.email decided_by_email,
              ap.decided_at, ap.created_at, ap.response_id, coalesce(p.recommendation_id, ap.recommendation_id) recommendation_id,
              i.id incident_id, i.title incident_title, i.priority incident_priority, i.status incident_status,
              p.target, p.status plan_status, s.title step_title, a.name action_name,
              ${CHAIN_SQL("ap.response_id")} chain
         from approvals ap
         left join response_plans p on p.id = ap.response_id
         left join recommendations r on r.id = coalesce(p.recommendation_id, ap.recommendation_id)
         join incidents i on i.id = coalesce(p.incident_id, r.incident_id)
         left join recommendation_steps s on s.id = p.recommendation_step_id
         left join actions a on a.id = p.action_id
         left join users du on du.id = ap.decided_by
        where i.tenant_id = $1
        order by ap.created_at desc, ap.step_order
        limit $2`,
      tenantId,
      limit
    );
    return rows.map((r) => ({
      id: String(r.id),
      role: str(r.approval_role),
      status: String(r.status),
      stepOrder: Number(r.step_order ?? 1),
      reason: str(r.reason),
      comment: str(r.comment),
      decidedBy: str(r.decided_by),
      decidedByEmail: str(r.decided_by_email),
      decidedAt: iso(r.decided_at),
      createdAt: iso(r.created_at) ?? "",
      responseId: str(r.response_id),
      recommendationId: str(r.recommendation_id),
      incidentId: String(r.incident_id),
      incidentTitle: String(r.incident_title),
      incidentPriority: String(r.incident_priority),
      incidentStatus: String(r.incident_status),
      target: str(r.target),
      planStatus: str(r.plan_status),
      stepTitle: str(r.step_title),
      actionName: str(r.action_name),
      chain: chain(r.chain),
    }));
  }

  async incidents(tenantId: string, f: IncidentWorkFilters): Promise<{ items: IncidentWorkRow[]; total: number }> {
    const params: unknown[] = [tenantId];
    const where: string[] = ["i.tenant_id = $1"];
    if (f.status?.length) {
      params.push(f.status.map((s) => s.toLowerCase()));
      where.push(`lower(i.status) = any($${params.length}::text[])`);
    }
    if (f.priority?.length) {
      params.push(f.priority.map((s) => s.toLowerCase()));
      where.push(`lower(i.priority) = any($${params.length}::text[])`);
    }
    if (f.search?.trim()) {
      params.push(`%${f.search.trim().toLowerCase()}%`);
      where.push(`(lower(i.title) like $${params.length} or lower(i.id) like $${params.length})`);
    }
    const whereSql = where.join(" and ");
    const [countRow] = await this.q(`select count(*) n from incidents i where ${whereSql}`, ...params);
    params.push(f.limit, f.offset);
    const rows = await this.q(
      `select * from (
         select i.id, i.title, i.status, i.priority, i.opened_at, i.closed_at, i.investigation_number, i.alert_id,
                st.scenario_id,
                asg.metadata->>'responsibleRole' responsible_role, asg.metadata->>'executorRole' executor_role,
                cap.approval_role current_role, cap.step_order current_step,
                (select p.status from response_plans p where p.incident_id = i.id order by p.updated_at desc limit 1) response_status,
                job.status job_status, job.trigger job_trigger, job.attempt job_attempt, job.at job_at,
                (select v.result from verifications v where v.incident_id = i.id order by v.verified_at desc limit 1) last_verification,
                greatest(i.opened_at,
                         coalesce((select max(t.occurred_at) from incident_timeline t where t.incident_id = i.id), i.opened_at),
                         coalesce((select max(p.updated_at) from response_plans p where p.incident_id = i.id), i.opened_at),
                         coalesce(asg.created_at, i.opened_at)) updated_at
           from incidents i
           left join alert_scenario_tags st on st.alert_id = i.alert_id
           left join lateral (select al.metadata, al.created_at from audit_logs al
                               where al.entity = 'Incident' and al.entity_id = i.id and al.action = 'INCIDENT_ASSIGNED'
                               order by al.created_at desc limit 1) asg on true
           left join lateral (select ap.approval_role, ap.step_order from approvals ap join response_plans p on p.id = ap.response_id
                               where p.incident_id = i.id and ap.status = 'pending' order by ap.created_at limit 1) cap on true
           left join lateral (select e.status, e.trigger, e.attempt, coalesce(e.completed_at, e.started_at) at from agent_executions e
                               where e.incident_id = i.id order by coalesce(e.queued_at, e.started_at) desc limit 1) job on true
          where ${whereSql}) x
        order by x.updated_at desc
        limit $${params.length - 1} offset $${params.length}`,
      ...params
    );
    return {
      total: Number(countRow?.n ?? 0),
      items: rows.map((r) => ({
        id: String(r.id),
        title: String(r.title),
        status: String(r.status),
        priority: String(r.priority),
        openedAt: iso(r.opened_at) ?? "",
        closedAt: iso(r.closed_at),
        investigationNumber: Number(r.investigation_number ?? 1),
        alertId: String(r.alert_id),
        scenario: r.scenario_id ? { id: String(r.scenario_id) } : null,
        responsibleRole: str(r.responsible_role),
        executorRole: str(r.executor_role),
        currentApproval: r.current_step != null ? { role: str(r.current_role), stepOrder: Number(r.current_step) } : null,
        responseStatus: str(r.response_status),
        aiJob: r.job_status ? { status: String(r.job_status).toUpperCase(), trigger: str(r.job_trigger), attempt: Number(r.job_attempt ?? 1), at: iso(r.job_at) ?? "" } : null,
        lastVerification: str(r.last_verification),
        updatedAt: iso(r.updated_at) ?? "",
      })),
    };
  }

  private async incidentExists(tenantId: string, incidentId: string): Promise<boolean> {
    const rows = await this.q(`select 1 from incidents where id = $1 and tenant_id = $2`, incidentId, tenantId);
    return rows.length > 0;
  }

  async incidentAudit(tenantId: string, incidentId: string, limit: number): Promise<AuditEntry[] | null> {
    if (!(await this.incidentExists(tenantId, incidentId))) return null;
    const [audit, timeline] = await Promise.all([
      this.q(
        `select al.id, al.created_at, al.actor, u.email actor_email, u.role actor_role, al.action, al.entity, al.entity_id, al.metadata
           from audit_logs al left join users u on u.id = al.actor
          where al.tenant_id = $1 and (
                (al.entity = 'Incident' and al.entity_id = $2)
             or al.metadata->>'incidentId' = $2
             or (al.entity = 'ResponsePlan' and al.entity_id in (select id from response_plans where incident_id = $2))
             or (al.entity = 'Recommendation' and al.entity_id in (select id from recommendations where incident_id = $2))
             or (al.entity = 'Verification' and al.entity_id in (select id from verifications where incident_id = $2))
             or (al.entity = 'Approval' and al.entity_id in (
                   select ap.id from approvals ap
                     left join response_plans p on p.id = ap.response_id
                     left join recommendations r on r.id = ap.recommendation_id
                    where p.incident_id = $2 or r.incident_id = $2))
             or (al.entity = 'Alert' and al.entity_id in (
                   select alert_id from incident_alerts where incident_id = $2 union select alert_id from incidents where id = $2)))
          order by al.created_at desc
          limit $3`,
        tenantId,
        incidentId,
        limit
      ),
      this.q(
        `select t.id, t.occurred_at, t.event_type, t.description, t.actor, u.email actor_email, u.role actor_role
           from incident_timeline t left join users u on u.id = t.actor
          where t.incident_id = $1 order by t.occurred_at desc limit $2`,
        incidentId,
        limit
      ),
    ]);
    const entries: AuditEntry[] = [
      ...audit.map((r) => ({
        id: String(r.id),
        source: "audit" as const,
        occurredAt: iso(r.created_at) ?? "",
        action: String(r.action),
        actor: String(r.actor),
        actorEmail: str(r.actor_email),
        actorRole: str(r.actor_role),
        entity: str(r.entity),
        entityId: str(r.entity_id),
        description: null,
        metadata: r.metadata ?? null,
      })),
      ...timeline.map((r) => ({
        id: String(r.id),
        source: "timeline" as const,
        occurredAt: iso(r.occurred_at) ?? "",
        action: String(r.event_type),
        actor: String(r.actor),
        actorEmail: str(r.actor_email),
        actorRole: str(r.actor_role),
        entity: "Incident",
        entityId: incidentId,
        description: r.description == null ? null : stripAiSeverity(String(r.description)).text,
        metadata: null,
      })),
    ];
    return entries.sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)).slice(0, limit);
  }

  async incidentAiJobs(tenantId: string, incidentId: string): Promise<AiJobRow[] | null> {
    if (!(await this.incidentExists(tenantId, incidentId))) return null;
    const rows = await this.q(
      `select id, status, trigger, attempt, queued_at, started_at, completed_at, error_code, error_message
         from agent_executions where incident_id = $1
        order by coalesce(queued_at, started_at) desc limit 50`,
      incidentId
    );
    return rows.map((r) => ({
      id: String(r.id),
      status: String(r.status).toUpperCase(),
      trigger: str(r.trigger),
      attempt: Number(r.attempt ?? 1),
      queuedAt: iso(r.queued_at),
      startedAt: iso(r.started_at) ?? "",
      completedAt: iso(r.completed_at),
      errorCode: str(r.error_code),
      errorMessage: str(r.error_message),
    }));
  }
}
