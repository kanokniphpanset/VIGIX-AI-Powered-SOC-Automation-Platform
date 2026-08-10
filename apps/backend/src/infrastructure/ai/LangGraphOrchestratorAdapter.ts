import {
  IAiOrchestratorPort,
  DispatchPipelineInput,
  DispatchPipelineOutput,
} from "../../application/agent-orchestration/ports/IAiOrchestratorPort";

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
export class LangGraphOrchestratorAdapter implements IAiOrchestratorPort {
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
}
