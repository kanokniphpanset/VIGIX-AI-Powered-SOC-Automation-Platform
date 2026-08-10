from pydantic import BaseModel


class RunPipelineRequest(BaseModel):
    alert_id: str
    tenant_id: str


class RunPipelineResponse(BaseModel):
    graph_run_id: str
    incident_id: str
    status: str  # "completed" | "queued"
    decision: str | None = None
    risk_score: float | None = None
    requires_approval: bool | None = None


class PipelineStatusResponse(BaseModel):
    graph_run_id: str
    status: str
    trace: list[str] = []
