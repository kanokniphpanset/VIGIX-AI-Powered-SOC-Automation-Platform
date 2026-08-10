import logging
from fastapi import APIRouter, HTTPException

from src.config.settings import settings
from src.graph.build_graph import compiled_graph
from src.api.schemas import RunPipelineRequest, RunPipelineResponse
from src.api.database import (
    fetch_alert,
    ensure_incident_for_alert,
    create_agent_execution,
    persist_agent_results,
)

router = APIRouter()
logger = logging.getLogger("soar.ai-orchestrator")


def _flatten_alert_text(alert: dict) -> str:
    """
    Turns the raw SIEM payload into a single text blob for MitreAgent's keyword
    matching and RagAgent/LlmAnalystAgent's context — different SIEMs put the
    interesting text in different fields, so this pulls from all the common ones.
    """
    payload = alert["raw_payload"]
    parts = []
    for key in ("rule", "full_log", "description", "title", "search_name"):
        value = payload.get(key)
        if isinstance(value, dict):
            parts.append(str(value.get("description", value)))
        elif value:
            parts.append(str(value))
    if not parts:
        parts.append(str(payload))
    return " | ".join(parts)


@router.post("/run", response_model=RunPipelineResponse)
async def run_pipeline(request: RunPipelineRequest) -> RunPipelineResponse:
    """
    Entry point the backend's LangGraphOrchestratorAdapter calls after saving
    a new alert. Fetches the alert, ensures an incident exists, runs it
    through all 9 agents via the compiled LangGraph StateGraph, persists every
    agent's output, and returns the final decision synchronously.

    Note: this runs synchronously (awaits the full graph) for now. For
    high-volume production use, swap this for a queue-backed async job and
    have the caller poll GET /pipeline/{run_id} instead — the state schema and
    persistence layer don't need to change, only how this endpoint dispatches.
    """
    alert = fetch_alert(settings.database_url, request.alert_id, request.tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    incident_id = ensure_incident_for_alert(settings.database_url, alert)
    execution_id = create_agent_execution(settings.database_url, incident_id)

    initial_state = {
        "alert_id": alert["id"],
        "tenant_id": alert["tenant_id"],
        "graph_run_id": execution_id,
        "raw_alert": alert["raw_payload"],
        "siem_source": alert["siem_source"],
        "alert_text": _flatten_alert_text(alert),
        "retry_count": 0,
        "trace": [],
    }

    try:
        final_state = await compiled_graph.ainvoke(initial_state)
    except Exception as exc:
        logger.exception("Pipeline run %s failed", execution_id)
        raise HTTPException(status_code=500, detail=f"Pipeline execution failed: {exc}") from exc

    persist_agent_results(settings.database_url, execution_id, incident_id, final_state)

    return RunPipelineResponse(
        graph_run_id=execution_id,
        incident_id=incident_id,
        status="completed",
        decision=final_state.get("decision"),
        risk_score=final_state.get("risk_score"),
        requires_approval=final_state.get("requires_approval"),
    )
