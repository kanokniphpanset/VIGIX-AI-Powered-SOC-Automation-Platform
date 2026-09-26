"""ThreatIntelAgent — LangGraph node. Wraps ThreatIntelligenceService.

Writes: threat_intel_report (contract shape read by contracts/evidence.py), iocs.
Never raises out of run(): failure becomes a structured error (Universal Error Contract).
"""
from __future__ import annotations

from src.contracts.error_builder import build_error
from src.graph.state import AgentState

from .result_contract import build_result_contract
from .service import ThreatIntelligenceService

_service: ThreatIntelligenceService | None = None


def _get_service() -> ThreatIntelligenceService:
    global _service
    if _service is None:
        _service = ThreatIntelligenceService()
    return _service


async def run(state: AgentState) -> AgentState:
    try:
        report = await _get_service().analyze_alert(
            state.get("raw_alert"),
            state.get("alert_text", ""),
            execution_id=state.get("graph_run_id"),
        )
        report_dict = report.to_dict()
        # evidence.py reads the build_result_contract() shape (ioc/iocType/evidence),
        # so always rebuild indicators through it.
        indicators = [build_result_contract(i) for i in report.indicators]
        report_dict["indicators"] = indicators

        iocs = [
            {
                "ioc_type": ind.get("iocType"),
                "ioc_value": ind.get("ioc"),
                "verdict": ind.get("verdict"),
                "confidence": ind.get("confidence"),
            }
            for ind in indicators
        ]
        return {
            "threat_intel_report": report_dict,
            "iocs": iocs,
            "trace": [f"ThreatIntelAgent: analyzed {len(indicators)} indicator(s)"],
        }
    except Exception as exc:  # noqa: BLE001 - never crash the graph
        error = build_error(
            agent="threat_intel",
            code="AGENT_EXECUTION_FAILED",
            message=f"ThreatIntelAgent failed: {exc}",
            retryable=True,
            severity="ERROR",
        )
        return {
            "structured_errors": [error.model_dump(by_alias=True, mode="json")],
            "trace": [f"ThreatIntelAgent: execution failed ({type(exc).__name__})"],
        }