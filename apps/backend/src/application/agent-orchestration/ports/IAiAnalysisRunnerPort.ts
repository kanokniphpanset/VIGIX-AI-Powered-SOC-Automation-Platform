/**
 * IAiAnalysisRunnerPort — runs the EXISTING AI pipeline for an alert that is already in VIGIX, synchronously and in
 * analysis-only mode (results are persisted; no decision hand-off, no notifications, no response actions).
 * Implemented by the same orchestrator adapter as IAiOrchestratorPort — there is one AI pipeline.
 */
export interface RunAnalysisInput {
  alertId: string;
  tenantId: string;
  /**
   * Queued job (agent_executions row the backend created, with its incident). The orchestrator then runs under this
   * id and uses that row's incident — it never opens an incident itself. Omitted by the direct manual run.
   */
  executionId?: string;
}

export interface RunAnalysisOutput {
  graphRunId: string;
  /** Incident the pipeline attached its results to. */
  incidentId: string;
  status: "SUCCESS" | "PARTIAL_SUCCESS";
  decision: string | null;
}

/**
 * AI_UNAVAILABLE: orchestrator unreachable / no answer. AI_FAILED: the orchestrator call itself failed.
 * AI_ANALYSIS_FAILED: the pipeline ran but produced NO AI analysis (the LLM analysis failed — `reason` carries the
 * orchestrator's code, e.g. LLM_TIMEOUT / LLM_UNAVAILABLE / LLM_INVALID_RESPONSE). Never reported as a success.
 */
export type AiAnalysisRunnerErrorCode = "AI_UNAVAILABLE" | "AI_FAILED" | "AI_ANALYSIS_FAILED";

export class AiAnalysisRunnerError extends Error {
  constructor(readonly code: AiAnalysisRunnerErrorCode, message: string, readonly reason: string | null = null) {
    super(message);
  }
}

export interface IAiAnalysisRunnerPort {
  runAnalysis(input: RunAnalysisInput): Promise<RunAnalysisOutput>;
}
