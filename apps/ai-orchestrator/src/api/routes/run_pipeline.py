import logging
from fastapi import APIRouter, HTTPException

from src.config.settings import settings
from src.graph.build_graph import get_checkpointed_graph
from src.api.schemas import RunPipelineRequest, RunPipelineResponse
from src.api.database import (
    final_execution_status,
    fetch_alert,
    ensure_incident_for_alert,
    incident_for_execution,
    ensure_execution_record,
    mark_execution_failed,
    persist_agent_results,
    get_incident_title,
)
from src.api.output_contract import build_output_contract
from src.api.backend_client import notify_backend_of_decision
from src.agents.decision_agent.models import DecisionResult
from src.contracts.normalized_alert import from_agent_state as normalized_alert_from_agent_state
from src.ingestion.agent_state_builder import resolve_asset_id, resolve_asset_criticality_with_metadata, flatten_alert_text
from src.notifications.notification_orchestrator import notification_orchestrator
from src.notifications.models import IncidentContext

router = APIRouter()
logger = logging.getLogger("soar.ai-orchestrator")


@router.post("/run", response_model=RunPipelineResponse)
async def run_pipeline(request: RunPipelineRequest) -> RunPipelineResponse:
    """
    Entry point the backend's worker (worker.ts, Phase 4) calls after
    dequeuing an orchestration job — synchronously from this endpoint's own
    perspective (it awaits the full graph before responding), but that's no
    longer a problem: the *webhook* that originally accepted the alert
    already returned 202 long before this runs, off a background worker,
    not the request/response path a human/SIEM is waiting on.

    Fetches the alert, ensures an incident exists, backfills the
    already-created AgentExecution row (or creates one — backward
    compatible for a manual/local call with no execution_id), runs all 9
    agents via the compiled LangGraph StateGraph with PostgreSQL
    checkpointing keyed on thread_id=execution_id (spec section 9),
    persists every agent's output plus the assembled Output Contract, and
    returns the final decision.
    """
    alert = fetch_alert(settings.database_url, request.alert_id, request.tenant_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Queued run (backend AI job): the backend already created the incident and this
    # execution row for it — use that incident; never open one here. Without an
    # execution_id (legacy/manual direct call) the old lookup-or-create path remains
    # as a safety net.
    if request.execution_id:
        incident_id = incident_for_execution(settings.database_url, request.execution_id)
        if not incident_id:
            raise HTTPException(status_code=404, detail="AgentExecution not found")
    else:
        incident_id = ensure_incident_for_alert(settings.database_url, alert)
    try:
        execution_id = ensure_execution_record(settings.database_url, request.execution_id, incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    asset_id = resolve_asset_id(alert["raw_payload"])
    if not asset_id:
        logger.warning(
            "run_pipeline: no structured source IP found for alert_id=%s — DecisionEngine's targetAsset will fall back to "
            "an internal id, not a real host/IP. Any recommended action targeting a real asset (e.g. NET-001 block-IP) "
            "will be refused by its executor's own IP validation rather than run against the wrong target.",
            alert["id"],
        )

    initial_state = {
        "alert_id": alert["id"],
        "incident_id": incident_id,
        "tenant_id": alert["tenant_id"],
        "graph_run_id": execution_id,
        "raw_alert": alert["raw_payload"],
        "siem_source": alert["siem_source"],
        # The authoritative severity (Wazuh rule.level -> VIGIX mapping). No agent generates or changes it. It lives in its own DB column (see database.py's
        # fetch_alert), computed by the backend's SIEM adapter — not part
        # of the raw payload.
        "severity": alert["severity"],
        "alert_text": flatten_alert_text(alert["raw_payload"]),
        "retry_count": 0,
        "trace": [],
        "errors": [],
    }
    # Root-cause fix (see resolve_asset_id's docstring): AgentState.asset_id
    # existed but was never populated, so DecisionEngine always targeted
    # actions at the alert's own UUID instead of a real host/IP. Key is
    # only added when a real value was found — the TypedDict field is
    # `str`, not `str | None`, and downstream code already treats an
    # absent key exactly like a falsy one (`state.get("asset_id") or ...`).
    if asset_id:
        initial_state["asset_id"] = asset_id
    # A re-opened investigation round: the LLM analyst reasons over the re-hunt that showed the threat was not resolved.
    if request.investigation_context:
        initial_state["investigation_context"] = request.investigation_context

    # asset_criticality always gets a real value (the catalog's own
    # default_tier when the host isn't catalogued) — unlike asset_id, this
    # key is never omitted, since decision_engine.py's own fallback (always
    # tier1_critical) is exactly the bug this resolves.
    asset_criticality, asset_known = resolve_asset_criticality_with_metadata(alert["raw_payload"], asset_id)
    initial_state["asset_criticality"] = asset_criticality
    # Unknown Asset Safety task: threaded through to PolicyContext so the
    # DecisionResult's own rationale can say WHY this tier applied.
    initial_state["asset_known"] = asset_known

    # Universal Alert Schema (contracts/normalized_alert.py) — additive,
    # backfilled from the same fields above so `/pipeline/run` also
    # populates the canonical NormalizedAlert, not only the new /alerts
    # ingestion endpoint. No existing agent reads this key yet, so this is
    # a pure addition to `initial_state`, not a behavior change.
    initial_state["normalized_alert"] = normalized_alert_from_agent_state(initial_state).model_dump(by_alias=True, mode="json")

    try:
        # thread_id=execution_id (spec section 9's own example) — every run
        # is checkpointed under the id the rest of the system already uses
        # to refer to it, so it can be resumed/inspected by that same id.
        graph = await get_checkpointed_graph()
        final_state = await graph.ainvoke(initial_state, config={"configurable": {"thread_id": execution_id}})
    except Exception as exc:
        logger.exception("Pipeline run %s failed", execution_id)
        mark_execution_failed(settings.database_url, execution_id, "GRAPH_EXECUTION_FAILED", str(exc))
        raise HTTPException(status_code=500, detail=f"Pipeline execution failed: {exc}") from exc

    output_contract = build_output_contract(execution_id, alert, incident_id, final_state)
    persist_agent_results(settings.database_url, execution_id, incident_id, final_state, output_contract)

    # A manual analysis-only run (Run / Re-run AI Analysis) stops here: the
    # analysis is persisted, but nothing is handed off or notified.
    # Same status that was persisted on agent_executions (FAILED when the LLM analysis failed, with its code).
    final_status, error_code, error_message = final_execution_status(final_state, output_contract)
    if request.analysis_only:
        return RunPipelineResponse(
            graph_run_id=execution_id,
            incident_id=incident_id,
            status=final_status,
            decision=final_state.get("decision"),
            requires_approval=final_state.get("requires_approval"),
            error_code=error_code,
            error_message=error_message,
        )

    # Hand off the decision to the backend, which triggers the n8n playbook
    # (Teams notification, ticket creation) via IWorkflowEnginePort. "dismiss"
    # decisions are still sent — the backend controller decides to skip n8n
    # for those rather than the orchestrator hardcoding that policy itself.
    if final_state.get("decision"):
        await notify_backend_of_decision(
            backend_url=settings.backend_url,
            incident_id=incident_id,
            title=get_incident_title(settings.database_url, incident_id),
            severity=final_state.get("severity") or "unknown",
            summary=final_state.get("llm_summary", ""),
            decision=final_state["decision"],
            # Real model identity for the backend's audit trail: only the LLM (there is no ML severity model).
            llm_model=settings.llm_model if final_state.get("llm_summary") else None,
            service_token=settings.backend_service_token or None,
        )

    # Notification layer: NotificationPolicy decides which channels (Jira,
    # Email, Teams, LINE) fire for this decision — dismiss/auto_response/
    # human_approval/escalate all get different treatment there, not here.
    # A channel outage is logged, never raised (see each NotificationService's
    # failure contract), so it can't turn a completed pipeline run into a 500
    # response, and one channel failing never blocks another.
    if final_state.get("decision_result"):
        await notification_orchestrator.dispatch(
            decision=DecisionResult.model_validate(final_state["decision_result"]),
            incident=IncidentContext(
                incident_type=get_incident_title(settings.database_url, incident_id),
                asset_criticality=final_state.get("asset_criticality", ""),
                severity=final_state.get("severity") or "unknown",
                iocs=final_state.get("iocs", []),
                mitre_techniques=final_state.get("mitre_techniques", []),
            ),
        )

    return RunPipelineResponse(
        graph_run_id=execution_id,
        incident_id=incident_id,
        status=final_status,
        decision=final_state.get("decision"),
        requires_approval=final_state.get("requires_approval"),
        error_code=error_code,
        error_message=error_message,
    )
