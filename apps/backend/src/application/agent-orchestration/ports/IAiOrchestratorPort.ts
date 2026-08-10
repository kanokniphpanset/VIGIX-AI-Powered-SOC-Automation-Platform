/**
 * IAiOrchestratorPort — port (interface) owned by the application layer.
 * Whatever engine actually runs the multi-agent pipeline (LangGraph today,
 * something else tomorrow) implements this. The application layer never
 * imports LangGraph, FastAPI, or an HTTP client directly.
 */
export interface DispatchPipelineInput {
  alertId: string;
  tenantId: string;
}

export interface DispatchPipelineOutput {
  graphRunId: string;
  status: "started" | "queued";
}

export interface IAiOrchestratorPort {
  dispatch(input: DispatchPipelineInput): Promise<DispatchPipelineOutput>;
}
