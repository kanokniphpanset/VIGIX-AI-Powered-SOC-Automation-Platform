/**
 * AI analysis job queue, stored on the existing agent_executions table (one row = one pipeline run).
 * Status: QUEUED -> RUNNING -> SUCCESS | PARTIAL_SUCCESS (completed, written by the orchestrator) | FAILED.
 */
export type AiJobTrigger = "INGEST" | "MANUAL" | "RETRY";

export interface AiAnalysisJob {
  id: string;
  incidentId: string;
  alertId: string;
  tenantId: string;
  trigger: AiJobTrigger | null;
  attempt: number;
  status: string;
  queuedAt: Date | null;
  startedAt: Date | null;
  completedAt: Date | null;
  nextAttemptAt: Date | null;
  errorCode: string | null;
  errorMessage: string | null;
}

export interface IAiAnalysisJobRepository {
  enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: AiJobTrigger; attempt: number; notBefore: Date }): Promise<AiAnalysisJob>;
  /** Atomically moves the oldest due QUEUED job to RUNNING (safe with several workers). */
  claimNext(now: Date): Promise<AiAnalysisJob | null>;
  /** Puts a claimed job back to QUEUED (without using an attempt), e.g. while another run holds the incident. */
  release(id: string, notBefore: Date): Promise<void>;
  /** FAILED with the reason, unless the orchestrator already completed it. Returns false when it was already completed. */
  markFailed(id: string, code: string, message: string, now: Date): Promise<boolean>;
  /** CANCELLED (terminal, not an error) — e.g. a retry made unnecessary because an earlier attempt completed. */
  cancel(id: string, reason: string, now: Date): Promise<void>;
  /** Queue-owned (trigger set) jobs stuck in RUNNING since before `before` — e.g. the backend restarted mid-run. */
  findStaleRunning(before: Date): Promise<AiAnalysisJob[]>;
  /** Another run for the incident is RUNNING (any origin, incl. manual) and started after `since`. */
  hasOtherActiveRun(incidentId: string, excludeId: string, since: Date): Promise<boolean>;
  /** A run for the incident completed (SUCCESS / PARTIAL_SUCCESS) at or after `since`. */
  hasCompletedSince(incidentId: string, since: Date): Promise<boolean>;
  latestForIncident(incidentId: string): Promise<AiAnalysisJob | null>;
}
