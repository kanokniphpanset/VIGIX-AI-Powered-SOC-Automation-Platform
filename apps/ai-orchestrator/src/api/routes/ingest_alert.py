"""
POST /pipeline/alerts — Universal Alert Ingestion connected to LangGraph.

Raw Alert -> AlertNormalizer -> NormalizedAlert -> build_initial_state()
-> analysis_graph.ainvoke() -> build_output_contract() -> AnalysisResult.

Deliberately stops at Incident Classification (see graph/build_graph.py
::build_analysis_graph's own docstring) — no Decision Agent, no SOAR
execution, no LangGraph retry/validation loop. No database persistence:
this endpoint requires no pre-existing `alerts` row (unlike /pipeline/run,
left completely untouched below it in main.py's router registration).
"""

import logging
import uuid

from fastapi import APIRouter, HTTPException

from src.agents.classification_agent.classification_rules import unknown_classification
from src.api.output_contract import build_output_contract
from src.api.schemas import IngestAlertRequest
from src.contracts.error import ErrorItem
from src.contracts.error_builder import build_error
from src.graph.build_graph import analysis_graph
from src.ingestion.agent_state_builder import build_initial_state
from src.ingestion.alert_normalizer import InvalidAlertPayloadError, SUPPORTED_SOURCES, UnsupportedAlertSourceError

router = APIRouter()
logger = logging.getLogger("soar.ai-orchestrator")


def _normalization_failure_response(execution_id: str, request: IngestAlertRequest, error: ErrorItem) -> dict:
    """
    A pre-graph failure (unsupported source / malformed payload / unexpected
    normalization bug) — nothing ran, so there is no final_state for
    build_output_contract() to introspect (build_errors()/build_evidence()
    both re-derive from threat_intel_report/mitre_mapping_report/rag_result/
    trace, none of which exist yet here). Hand-assembled with the SAME
    top-level shape build_output_contract() produces below, not a second
    contract — every key mirrors its real counterpart, just empty/UNKNOWN
    since no agent ever executed. severity=CRITICAL on the ErrorItem itself
    is what makes `status` naturally read FAILED here, matching
    output_contract.py's own existing severity-driven status computation.
    """
    return {
        "executionId": execution_id,
        "status": "FAILED",
        "errors": [error.model_dump(by_alias=True, mode="json")],
        "input": {"alertId": request.alert_id, "externalAlertId": request.alert_id, "type": "alert"},
        "threatIntel": {},
        "mitreMapping": {},
        "ragContext": {},
        "analysis": {"summary": None, "recommendation": None},
        "classification": unknown_classification().model_dump(by_alias=True, mode="json"),
        "decision": None,
        "evidence": [],
        "validation": {"passed": None, "notes": []},
        "execution": {"executionId": execution_id, "incidentId": execution_id, "errors": [], "agents": []},
    }


@router.post("/alerts")
async def ingest_alert(request: IngestAlertRequest) -> dict:
    execution_id = str(uuid.uuid4())

    try:
        initial_state = build_initial_state(
            source=request.source,
            alert_id=request.alert_id,
            tenant_id=request.tenant_id,
            raw_alert=request.alert,
            graph_run_id=execution_id,
        )
    except UnsupportedAlertSourceError:
        error = build_error(
            agent="ingestion",
            code="AGENT_INPUT_INVALID",
            message=f"Unsupported alert source: {request.source!r}. Supported sources: {', '.join(SUPPORTED_SOURCES)}.",
            retryable=False,
            severity="CRITICAL",
        )
        return _normalization_failure_response(execution_id, request, error)
    except InvalidAlertPayloadError as exc:
        error = build_error(agent="ingestion", code="AGENT_INPUT_INVALID", message=str(exc), retryable=False, severity="CRITICAL")
        return _normalization_failure_response(execution_id, request, error)
    except Exception as exc:  # noqa: BLE001 - last-resort guard; a normalization bug must never 500 this endpoint
        logger.exception("ingest_alert: unexpected normalization failure for alert_id=%s", request.alert_id)
        error = build_error(agent="ingestion", code="AGENT_EXECUTION_FAILED", message=f"Normalization failed: {exc}", retryable=False, severity="CRITICAL")
        return _normalization_failure_response(execution_id, request, error)

    try:
        final_state = await analysis_graph.ainvoke(initial_state)
    except Exception as exc:
        # Every node in analysis_graph already catches its own risky
        # operations (see build_analysis_graph's docstring) — reaching here
        # means a genuinely unexpected bug, not a documented degradation
        # path. Matches run_pipeline.py's own GRAPH_EXECUTION_FAILED
        # handling for /pipeline/run.
        logger.exception("ingest_alert: graph execution failed for execution_id=%s", execution_id)
        raise HTTPException(status_code=500, detail=f"Alert analysis failed: {exc}") from exc

    # No DB alert/incident row exists for this stateless path — execution_id
    # doubles as the incident_id, matching the "no persistence unless
    # required" boundary this task and the ingestion task both set.
    alert_input = {"id": request.alert_id, "external_alert_id": request.alert_id}
    return build_output_contract(execution_id, alert_input, execution_id, final_state)
