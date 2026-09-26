import { AiAnalysisJob, AiJobTrigger, IAiAnalysisJobRepository } from "../ports/IAiAnalysisJobRepository";
import { AiAnalysisRunnerError, IAiAnalysisRunnerPort } from "../ports/IAiAnalysisRunnerPort";
import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";

export interface AiJobPolicy {
  /** Total attempts per analysis (the first run + retries). */
  maxAttempts: number;
  /** Backoff before retry n = baseBackoffMs * 2^(n-1). */
  baseBackoffMs: number;
  /** A queue-owned RUNNING job older than this is treated as abandoned. */
  staleRunningMs: number;
  /** How long to wait when another run holds the incident. */
  busyDelayMs: number;
}

export const DEFAULT_AI_JOB_POLICY: AiJobPolicy = { maxAttempts: 3, baseBackoffMs: 30_000, staleRunningMs: 15 * 60_000, busyDelayMs: 30_000 };

export type AiJobOutcome =
  | { outcome: "COMPLETED"; job: AiAnalysisJob; status: string }
  | { outcome: "FAILED"; job: AiAnalysisJob; error: string; retryJob: AiAnalysisJob | null }
  | { outcome: "DEFERRED"; job: AiAnalysisJob }
  | { outcome: "SUPERSEDED"; job: AiAnalysisJob };

/**
 * AI analysis job queue (Pipeline A). The analysis itself is the EXISTING pipeline, reached through the existing
 * IAiAnalysisRunnerPort (orchestrator /pipeline/run, analysis_only) with the queued row as its execution_id — the
 * orchestrator runs LangGraph under that id and writes SUCCESS / PARTIAL_SUCCESS / FAILED on it.
 * The job only analyses: no recommendation, policy, approval, response, notification or n8n here.
 * Retries are bounded (maxAttempts) with exponential backoff; each retry is a new row (fresh LangGraph thread).
 */
export class AiAnalysisJobService {
  constructor(
    private readonly jobs: IAiAnalysisJobRepository,
    private readonly runner: IAiAnalysisRunnerPort,
    private readonly investigations: IInvestigationRepository,
    private readonly auditLogger: AuditLogger,
    private readonly policy: AiJobPolicy = DEFAULT_AI_JOB_POLICY,
    private readonly clock: () => Date = () => new Date(),
    /** After a completed analysis: Policy assignment (INCIDENT_ASSIGNED). Read-only; a failure never fails the job. */
    private readonly onCompleted?: (job: AiAnalysisJob) => Promise<void>
  ) {}

  enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: AiJobTrigger }): Promise<AiAnalysisJob> {
    return this.jobs.enqueue({ ...input, attempt: 1, notBefore: this.clock() });
  }

  latestForIncident(incidentId: string): Promise<AiAnalysisJob | null> {
    return this.jobs.latestForIncident(incidentId);
  }

  /** Claims and runs at most one due job. Returns null when nothing is due. */
  async processNext(): Promise<AiJobOutcome | null> {
    const now = this.clock();
    const job = await this.jobs.claimNext(now);
    if (!job) return null;

    if (await this.jobs.hasOtherActiveRun(job.incidentId, job.id, new Date(now.getTime() - this.policy.staleRunningMs))) {
      await this.jobs.release(job.id, new Date(now.getTime() + this.policy.busyDelayMs));
      return { outcome: "DEFERRED", job };
    }
    // A retry whose earlier attempt finished after all (e.g. only the HTTP wait timed out) has nothing left to do.
    if (job.trigger === "RETRY" && job.queuedAt && (await this.jobs.hasCompletedSince(job.incidentId, job.queuedAt))) {
      await this.jobs.cancel(job.id, "SUPERSEDED: an earlier attempt of this analysis completed.", now);
      return { outcome: "SUPERSEDED", job };
    }

    let run;
    try {
      run = await this.runner.runAnalysis({ alertId: job.alertId, tenantId: job.tenantId, executionId: job.id });
    } catch (err) {
      // The orchestrator's own reason (e.g. LLM_TIMEOUT) is the most useful code for the SOC and the AI jobs table.
      const code = err instanceof AiAnalysisRunnerError ? err.reason ?? err.code : "AI_FAILED";
      const message = err instanceof Error ? err.message : "AI analysis failed";
      return this.fail(job, code, message);
    }
    if (run.incidentId !== job.incidentId) {
      // Never happens on the queued path (the orchestrator uses the row's incident) — refuse, never retry into it.
      await this.jobs.markFailed(job.id, "INCIDENT_MISMATCH", `Pipeline attached results to ${run.incidentId}.`, this.clock());
      await this.audit(job, "AI_ANALYSIS_JOB_FAILED", { error: "INCIDENT_MISMATCH", pipelineIncidentId: run.incidentId, retryJobId: null });
      return { outcome: "FAILED", job, error: "INCIDENT_MISMATCH", retryJob: null };
    }

    // Same follow-up as before the queue existed: attach the pipeline's IOCs / evidence to the current investigation.
    await this.investigations.syncIncident(job.incidentId, job.tenantId).catch((err) =>
      console.error("AI job: investigation sync failed", job.id, err instanceof Error ? err.message : "unknown")
    );
    await this.audit(job, "AI_ANALYSIS_JOB_COMPLETED", { status: run.status, graphRunId: run.graphRunId });
    await this.onCompleted?.(job).catch((err) => console.error("AI job: post-analysis assignment failed", job.id, err instanceof Error ? err.message : "unknown"));
    return { outcome: "COMPLETED", job, status: run.status };
  }

  /** Recovers queue-owned jobs abandoned in RUNNING (backend restart / crash): FAILED + bounded retry. */
  async recoverStale(): Promise<AiAnalysisJob[]> {
    const stale = await this.jobs.findStaleRunning(new Date(this.clock().getTime() - this.policy.staleRunningMs));
    for (const job of stale) await this.fail(job, "STALE_RUNNING", "The run did not finish (backend restarted or the call was lost).");
    return stale;
  }

  private async fail(job: AiAnalysisJob, code: string, message: string): Promise<AiJobOutcome> {
    const now = this.clock();
    const updated = await this.jobs.markFailed(job.id, code, message, now);
    if (!updated) {
      // The orchestrator completed the run after all.
      await this.audit(job, "AI_ANALYSIS_JOB_COMPLETED", { status: "COMPLETED_AFTER_ERROR", clientError: code });
      return { outcome: "COMPLETED", job, status: "COMPLETED_AFTER_ERROR" };
    }
    let retryJob: AiAnalysisJob | null = null;
    if (job.attempt < this.policy.maxAttempts) {
      retryJob = await this.jobs.enqueue({
        tenantId: job.tenantId,
        incidentId: job.incidentId,
        alertId: job.alertId,
        trigger: "RETRY",
        attempt: job.attempt + 1,
        notBefore: new Date(now.getTime() + this.policy.baseBackoffMs * 2 ** (job.attempt - 1)),
      });
    }
    await this.audit(job, "AI_ANALYSIS_JOB_FAILED", {
      error: code,
      message,
      retryJobId: retryJob?.id ?? null,
      nextAttemptAt: retryJob?.nextAttemptAt?.toISOString() ?? null,
      exhausted: !retryJob,
    });
    return { outcome: "FAILED", job, error: code, retryJob };
  }

  private audit(job: AiAnalysisJob, action: string, metadata: Record<string, unknown>): Promise<void> {
    return this.auditLogger.record({
      tenantId: job.tenantId,
      actor: "vigix-ai-worker",
      action,
      entity: "Incident",
      entityId: job.incidentId,
      metadata: { jobId: job.id, alertId: job.alertId, trigger: job.trigger, attempt: job.attempt, ...metadata },
    });
  }
}
