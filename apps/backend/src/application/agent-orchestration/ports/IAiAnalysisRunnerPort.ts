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
  /** Present when the run is for a re-opened investigation round; omitted for the first analysis of an alert. */
  investigationContext?: InvestigationRoundContext;
}

/**
 * A later investigation round (Investigation #2+): the re-hunt verification that just came back NOT_RESOLVED. Sent to
 * the pipeline so the analysis of the new round reasons over what the response did NOT fix, not only the original alert.
 */
export interface InvestigationRoundContext {
  investigationNumber: number;
  verification: {
    id: string;
    result: string;
    query: string | null;
    timeRangeStart: string | null;
    timeRangeEnd: string | null;
    matchingEvents: number | null;
    affectedHosts: string[];
    iocRecurrence: boolean;
    spreadDetected: boolean;
    threatContained: boolean;
    evidenceSource: string;
  };
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
