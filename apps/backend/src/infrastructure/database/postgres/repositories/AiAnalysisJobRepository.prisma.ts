import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { AiAnalysisJob, AiJobTrigger, IAiAnalysisJobRepository } from "../../../../application/agent-orchestration/ports/IAiAnalysisJobRepository";

type Row = {
  id: string;
  incident_id: string;
  alert_id: string | null;
  tenant_id: string;
  trigger: string | null;
  attempt: number;
  status: string;
  queued_at: Date | null;
  started_at: Date | null;
  completed_at: Date | null;
  next_attempt_at: Date | null;
  error_code: string | null;
  error_message: string | null;
};

const toJob = (r: Row): AiAnalysisJob => ({
  id: r.id,
  incidentId: r.incident_id,
  alertId: r.alert_id ?? "",
  tenantId: r.tenant_id,
  trigger: (r.trigger as AiJobTrigger | null) ?? null,
  attempt: Number(r.attempt),
  status: r.status,
  queuedAt: r.queued_at,
  startedAt: r.started_at,
  completedAt: r.completed_at,
  nextAttemptAt: r.next_attempt_at,
  errorCode: r.error_code,
  errorMessage: r.error_message,
});

/** Columns selected for a job (tenant comes from the incident — agent_executions has no tenant column). */
const JOB_COLUMNS = `e.id, e.incident_id, e.alert_id, i.tenant_id, e.trigger, e.attempt, e.status, e.queued_at, e.started_at,
  e.completed_at, e.next_attempt_at, e.error_code, e.error_message`;

/** DB-backed AI analysis job queue on agent_executions (no Redis). */
export class PrismaAiAnalysisJobRepository implements IAiAnalysisJobRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: AiJobTrigger; attempt: number; notBefore: Date }): Promise<AiAnalysisJob> {
    const id = randomUUID();
    const now = new Date();
    // started_at is NOT NULL in the existing table: it holds the queue time until the worker claims the job.
    const row = await this.prisma.agentExecution.create({
      data: {
        id,
        incidentId: input.incidentId,
        graphRunId: id,
        status: "QUEUED",
        alertId: input.alertId,
        trigger: input.trigger,
        attempt: input.attempt,
        queuedAt: now,
        nextAttemptAt: input.notBefore,
        startedAt: now,
      },
    });
    return {
      id: row.id, incidentId: row.incidentId, alertId: input.alertId, tenantId: input.tenantId, trigger: input.trigger, attempt: row.attempt,
      status: row.status, queuedAt: row.queuedAt, startedAt: null, completedAt: null, nextAttemptAt: row.nextAttemptAt, errorCode: null, errorMessage: null,
    };
  }

  async claimNext(now: Date): Promise<AiAnalysisJob | null> {
    const rows = await this.prisma.$queryRawUnsafe<Row[]>(
      `WITH next AS (
         SELECT id FROM agent_executions
          WHERE status = 'QUEUED' AND alert_id IS NOT NULL AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
          ORDER BY COALESCE(next_attempt_at, queued_at) ASC, queued_at ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1
       ), claimed AS (
         UPDATE agent_executions e SET status = 'RUNNING', started_at = $1
           FROM next WHERE e.id = next.id
         RETURNING e.*
       )
       SELECT ${JOB_COLUMNS} FROM claimed e JOIN incidents i ON i.id = e.incident_id`,
      now
    );
    return rows[0] ? toJob(rows[0]) : null;
  }

  async release(id: string, notBefore: Date): Promise<void> {
    await this.prisma.agentExecution.updateMany({ where: { id, status: "RUNNING" }, data: { status: "QUEUED", nextAttemptAt: notBefore } });
  }

  async markFailed(id: string, code: string, message: string, now: Date): Promise<boolean> {
    // Keeps the orchestrator's own failure details when it recorded them first; never overrides a completed run.
    const updated = await this.prisma.$executeRawUnsafe(
      `UPDATE agent_executions
          SET status = 'FAILED', error_code = COALESCE(error_code, $2), error_message = COALESCE(error_message, $3),
              completed_at = COALESCE(completed_at, $4)
        WHERE id = $1 AND status NOT IN ('SUCCESS', 'PARTIAL_SUCCESS')`,
      id, code, message.slice(0, 1000), now
    );
    return updated > 0;
  }

  async cancel(id: string, reason: string, now: Date): Promise<void> {
    await this.prisma.agentExecution.updateMany({
      where: { id, status: { notIn: ["SUCCESS", "PARTIAL_SUCCESS"] } },
      data: { status: "CANCELLED", errorCode: "SUPERSEDED", errorMessage: reason.slice(0, 1000), completedAt: now },
    });
  }

  async findStaleRunning(before: Date): Promise<AiAnalysisJob[]> {
    const rows = await this.prisma.$queryRawUnsafe<Row[]>(
      `SELECT ${JOB_COLUMNS} FROM agent_executions e JOIN incidents i ON i.id = e.incident_id
        WHERE e.status = 'RUNNING' AND e.trigger IS NOT NULL AND e.alert_id IS NOT NULL AND e.started_at < $1`,
      before
    );
    return rows.map(toJob);
  }

  async hasOtherActiveRun(incidentId: string, excludeId: string, since: Date): Promise<boolean> {
    const n = await this.prisma.agentExecution.count({
      where: { incidentId, id: { not: excludeId }, status: { in: ["RUNNING", "running"] }, startedAt: { gte: since } },
    });
    return n > 0;
  }

  async hasCompletedSince(incidentId: string, since: Date): Promise<boolean> {
    const n = await this.prisma.agentExecution.count({ where: { incidentId, status: { in: ["SUCCESS", "PARTIAL_SUCCESS"] }, completedAt: { gte: since } } });
    return n > 0;
  }

  async latestForIncident(incidentId: string): Promise<AiAnalysisJob | null> {
    const rows = await this.prisma.$queryRawUnsafe<Row[]>(
      `SELECT ${JOB_COLUMNS} FROM agent_executions e JOIN incidents i ON i.id = e.incident_id
        WHERE e.incident_id = $1 ORDER BY COALESCE(e.queued_at, e.started_at) DESC LIMIT 1`,
      incidentId
    );
    return rows[0] ? toJob(rows[0]) : null;
  }
}
