import {
  IAiOrchestratorPort,
  DispatchPipelineInput,
  DispatchPipelineOutput,
} from "../../application/agent-orchestration/ports/IAiOrchestratorPort";
import {
  AiAnalysisRunnerError,
  IAiAnalysisRunnerPort,
  RunAnalysisInput,
  RunAnalysisOutput,
} from "../../application/agent-orchestration/ports/IAiAnalysisRunnerPort";

/** A full pipeline run (9 agents incl. the LLM) takes seconds to a few minutes. */
const ANALYSIS_TIMEOUT_MS = 180_000;

/**
 * LangGraphOrchestratorAdapter — infrastructure (Ring 3).
 * Implements IAiOrchestratorPort by calling the ai-orchestrator FastAPI service
 * (apps/ai-orchestrator, POST /pipeline/run). This is the ONLY class in the
 * backend that knows the orchestrator is LangGraph, or that it's even a
 * separate HTTP service at all.
 *
 * Swap this file for e.g. a TemporalOrchestratorAdapter and nothing in
 * application/ or domain/ changes.
 */
export class LangGraphOrchestratorAdapter implements IAiOrchestratorPort, IAiAnalysisRunnerPort {
  constructor(private readonly baseUrl: string) {}

  async dispatch(input: DispatchPipelineInput): Promise<DispatchPipelineOutput> {
    const res = await fetch(`${this.baseUrl}/pipeline/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert_id: input.alertId, tenant_id: input.tenantId }),
    });

    if (!res.ok) {
      throw new Error(`AI orchestrator responded with ${res.status}`);
    }

    const data = (await res.json()) as { graph_run_id: string; status: string };
    return {
      graphRunId: data.graph_run_id,
      status: data.status === "queued" ? "queued" : "started",
    };
  }

  /** Same /pipeline/run, analysis-only: the orchestrator persists the analysis and hands off / notifies nothing. */
  async runAnalysis(input: RunAnalysisInput): Promise<RunAnalysisOutput> {
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/pipeline/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          alert_id: input.alertId,
          tenant_id: input.tenantId,
          analysis_only: true,
          ...(input.executionId ? { execution_id: input.executionId } : {}),
        }),
        signal: AbortSignal.timeout(ANALYSIS_TIMEOUT_MS),
      });
    } catch {
      throw new AiAnalysisRunnerError("AI_UNAVAILABLE", "The AI orchestrator is unreachable or did not answer in time.");
    }
    if (!res.ok) throw new AiAnalysisRunnerError("AI_FAILED", `The AI orchestrator responded with ${res.status}.`);
    // The orchestrator returns no severity: VIGIX's severity is the Wazuh rule-level mapping only.
    const data = (await res.json()) as { graph_run_id: string; incident_id: string; status: string; decision?: string | null; error_code?: string | null; error_message?: string | null };
    // FAILED = the pipeline ran but the LLM analysis failed: there is no AI analysis — never mapped to SUCCESS.
    if (data.status === "FAILED") {
      const reason = data.error_code ?? "AI_ANALYSIS_FAILED";
      throw new AiAnalysisRunnerError("AI_ANALYSIS_FAILED", `${reason}: ${data.error_message ?? "the AI analysis failed"}`, reason);
    }
    return {
      graphRunId: data.graph_run_id,
      incidentId: data.incident_id,
      status: data.status === "PARTIAL_SUCCESS" ? "PARTIAL_SUCCESS" : "SUCCESS",
      decision: data.decision ?? null,
    };
  }
}
