"""
ThreatIntelAgent — LangGraph node. Extracts IOCs from the alert, enriches
each one against every configured threat-intel provider, and produces an
explainable ThreatIntelReport.

Runs first in the pipeline's parallel fan-out (see graph/build_graph.py:
START -> [threat_intel, mitre, rag] -> ml_risk -> ...). Never raises: a
provider outage, missing API keys, or an alert with zero extractable IOCs
all degrade gracefully rather than failing the run — MlRiskAgent's
feature_engineering.py and ValidationAgent's rules.py both already treat an
empty/unenriched `iocs` list as a valid (if less confident) input.

State contract (unchanged from before this rewrite):
  reads:  state["alert_text"], state["raw_alert"]
  writes: state["iocs"]                — list[Ioc], backward compatible with
                                          existing consumers (feature_engineering.py,
                                          api/database.py) plus the richer
                                          verdict/score/explanation fields.
          state["threat_intel_report"]  — full ThreatIntelReport, for any
                                          consumer (LlmAnalystAgent prompts,
                                          future IncidentClassificationAgent)
                                          that wants the aggregate view.
          state["trace"]                — one summary entry.
"""

import logging

from src.graph.state import AgentState
from .service import ThreatIntelligenceService

logger = logging.getLogger("soar.ai-orchestrator.threat-intel")

_service = ThreatIntelligenceService()


async def run(state: AgentState) -> AgentState:
    correlation_id = state.get("graph_run_id") or state.get("alert_id")
    alert_id = state.get("alert_id")

    logger.info(
        "threat_intel.analysis.started",
        extra={"agent": "ThreatIntelAgent", "correlationId": correlation_id, "alertId": alert_id},
    )

    report = await _service.analyze_alert(state.get("raw_alert"), state.get("alert_text", ""))

    logger.info(
        "threat_intel.analysis.completed",
        extra={
            "agent": "ThreatIntelAgent",
            "correlationId": correlation_id,
            "alertId": alert_id,
            "durationMs": report.duration_ms,
            "total": report.summary["total"],
            "malicious": report.summary["malicious"],
            "overallRiskLevel": report.overall_risk_level.value,
        },
    )

    legacy_iocs = [indicator.to_legacy_ioc() for indicator in report.indicators]

    return {
        "iocs": legacy_iocs,
        "threat_intel_report": report.to_dict(),
        "trace": [
            f"ThreatIntelAgent: analyzed {report.summary['total']} IOC(s) — "
            f"{report.summary['malicious']} malicious, {report.summary['suspicious']} suspicious, "
            f"{report.summary['clean']} clean, {report.summary['unknown']} unknown "
            f"(overall risk: {report.overall_risk_level.value})"
        ],
    }
