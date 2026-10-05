from typing import Any

from pydantic import BaseModel

from src.contracts._base import CamelModel


class RunPipelineRequest(BaseModel):
    alert_id: str
    tenant_id: str
    # Phase 4 — the AgentExecution row the backend webhook already created
    # (see worker.ts). When present, this run updates that existing row
    # instead of creating a new one, and its id becomes the LangGraph
    # checkpoint thread_id. Optional only so direct/manual calls to this
    # endpoint (e.g. during local development) still work without a
    # pre-created execution.
    execution_id: str | None = None
    # Manual "Run / Re-run AI Analysis" for an existing incident (backend
    # RunIncidentAiAnalysisUseCase): run and persist the analysis only — no
    # decision callback to the backend (n8n playbook) and no notification
    # dispatch. Defaults to False, so the ingestion path is unchanged.
    analysis_only: bool = False
    # Investigation #2+ (backend CreateVerificationUseCase): the round number and the re-hunt verification that came
    # back NOT_RESOLVED and opened it. The LLM analyst re-analyses the incident with this as the latest evidence.
    # Omitted for the first analysis of an alert.
    investigation_context: dict[str, Any] | None = None


class RunPipelineResponse(BaseModel):
    graph_run_id: str
    incident_id: str
    status: str  # SUCCESS | PARTIAL_SUCCESS | FAILED (the persisted agent_executions status) | "queued"
    decision: str | None = None
    requires_approval: bool | None = None
    # Set when status is FAILED (e.g. LLM_TIMEOUT / LLM_UNAVAILABLE / LLM_INVALID_RESPONSE): no AI analysis was produced.
    error_code: str | None = None
    error_message: str | None = None


class PipelineStatusResponse(BaseModel):
    graph_run_id: str
    status: str
    trace: list[str] = []


class GenerateEmbeddingRequest(BaseModel):
    text: str


class GenerateEmbeddingResponse(BaseModel):
    embedding: list[float]
    dimension: int
    model: str


class IngestAlertRequest(CamelModel):
    """
    Universal Alert Ingestion (POST /pipeline/alerts) — deliberately
    CamelModel (camelCase JSON), unlike RunPipelineRequest above, to match
    the newer convention already used by every other contract this task
    sequence introduced (NormalizedAlert/EvidenceItem/ErrorItem/
    IncidentClassification) and the task's own explicit request example.
    RunPipelineRequest is left untouched with its original snake_case
    convention — an unrelated, pre-existing endpoint.

    `alert_id`/`tenant_id` both required, mirroring the same "every real
    call site already requires both" precedent NormalizedAlert's own
    docstring establishes for RunPipelineRequest. `alert` is typed `dict`
    (not `dict[str, Any]` vs a stricter schema) so any JSON object is
    accepted regardless of source shape — per-source validation happens in
    the normalizer, not here.
    """

    alert_id: str
    tenant_id: str
    source: str
    alert: dict


class IngestAlertResponse(CamelModel):
    execution_id: str
    normalized_alert: dict | None
    status: str  # "SUCCESS" | "FAILED"
    errors: list[dict] = []
