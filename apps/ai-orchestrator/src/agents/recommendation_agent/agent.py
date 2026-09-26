"""
RecommendationAgent — LangGraph node (`async def run`, same convention as
every other agent in src/agents/**). Turns the already-computed analysis
(Evidence[] from contracts/evidence.py::build_evidence, plus
state["classification"]) into an InvestigationRecommendationReport and
writes it to state["investigation_recommendation_report"] — the key
api/database.py and api/output_contract.py already read.

Selection is deterministic (selector.py); the only LLM call is the
whole-report investigation summary (summary.py), which falls back to a
template when the LLM is unavailable.

RecommendationAgent NEVER:
  - executes, dispatches, or schedules any action
  - approves its own output or bypasses Policy/Approval
  - decides whether an action is allowed (DecisionAgent/PolicyEngine own that)
  - invents evidence, MITRE techniques, or NIST citations

When state["classification"] is absent (build_graph()'s pipeline has no
classification node), the incident type is UNKNOWN with confidence 0.0 —
never guessed. Any unexpected failure degrades to an empty report with a
structured error; it never crashes the graph and never fabricates a
successful recommendation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.contracts.error_builder import build_error
from src.contracts.evidence import EvidenceItem, build_evidence
from src.graph.state import AgentState

from .models import (
    InvestigationRecommendationReport,
    NistReference,
    Recommendation,
    RecommendationPriority,
)
from .selector import RecommendationSelector
from .summary import build_summary

_PRIORITY_ORDER = [
    RecommendationPriority.LOW,
    RecommendationPriority.MEDIUM,
    RecommendationPriority.HIGH,
    RecommendationPriority.CRITICAL,
]

_selector: RecommendationSelector | None = None


def _get_selector() -> RecommendationSelector:
    # Lazy so importing this module never touches resource files.
    global _selector
    if _selector is None:
        _selector = RecommendationSelector()
    return _selector


def _get_value(source: Any, key: str, default: Any = None) -> Any:
    """Read a value from either a dict or an object."""
    if isinstance(source, dict):
        return source.get(key, default)

    return getattr(source, key, default)


def _normalize_list(value: Any) -> list[Any]:
    """Normalize None/scalar/list values into a list."""
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def _overall_priority(recommendations: list[Recommendation]) -> RecommendationPriority:
    if not recommendations:
        return RecommendationPriority.LOW
    return max((r.priority for r in recommendations), key=_PRIORITY_ORDER.index)


def _overall_confidence(recommendations: list[Recommendation], classification_confidence: float) -> float:
    if not recommendations:
        return round(min(max(classification_confidence, 0.0), 1.0), 2)
    return round(sum(r.confidence for r in recommendations) / len(recommendations), 2)


def _unique_nist(recommendations: list[Recommendation]) -> list[NistReference]:
    seen: set[tuple] = set()
    unique: list[NistReference] = []
    for r in recommendations:
        key = (r.framework.name, r.framework.function, r.framework.section)
        if key not in seen:
            seen.add(key)
            unique.append(r.framework)
    return unique


def _validation_status(state: AgentState) -> tuple[str, list[str]]:
    notes = [str(n) for n in _normalize_list(state.get("validation_notes"))]
    if state.get("validation_passed") is False:
        return "VALIDATION_FAILED", notes
    return "READY", notes


def _build_report(
    state: AgentState,
    incident_type: str,
    classification_confidence: float,
    evidence: list[EvidenceItem],
    recommendations: list[Recommendation],
    missing_evidence: list[str],
    summary_text: str,
) -> InvestigationRecommendationReport:
    status, validation_notes = _validation_status(state)
    techniques = sorted({t for r in recommendations if r.mitre for t in r.mitre.techniques})
    playbooks = recommendations[0].playbook_references if recommendations else []

    return InvestigationRecommendationReport(
        incident_id=str(state.get("incident_id") or state.get("alert_id") or "unknown"),
        generated_at=datetime.now(timezone.utc),
        incident_type=incident_type,
        classification_confidence=classification_confidence,
        investigation_summary=summary_text,
        recommendation_status=status,
        validation_notes=validation_notes,
        evidence_summary=evidence,
        missing_evidence=missing_evidence,
        recommendations=recommendations,
        mitre_techniques=techniques,
        nist_traceability=_unique_nist(recommendations),
        playbook_references=playbooks,
        overall_confidence=_overall_confidence(recommendations, classification_confidence),
        overall_priority=_overall_priority(recommendations),
        automation_eligible_count=sum(1 for r in recommendations if r.automation.allowed),
    )


async def run(state: AgentState) -> AgentState:
    classification = state.get("classification") or {}
    incident_type = str(_get_value(classification, "category") or "UNKNOWN")
    classification_confidence = float(_get_value(classification, "confidence") or 0.0)

    try:
        evidence = build_evidence(dict(state))
        selection = _get_selector().select(incident_type, classification, evidence, dict(state))
        summary_text, summary_trace = await build_summary(
            dict(state),
            incident_type,
            classification_confidence,
            selection.recommendations,
            selection.missing_evidence,
        )
        report = _build_report(
            state,
            incident_type,
            classification_confidence,
            evidence,
            selection.recommendations,
            selection.missing_evidence,
            summary_text,
        )
    except Exception as exc:  # noqa: BLE001 - last-resort guard; never crash the graph
        error = build_error(
            agent="recommendation",
            code="AGENT_EXECUTION_FAILED",
            message=f"RecommendationAgent failed: {exc}",
            retryable=False,
            severity="ERROR",
        )
        return {
            "investigation_recommendation_report": {},
            "structured_errors": [error.model_dump(by_alias=True, mode="json")],
            "trace": [f"RecommendationAgent: execution failed ({type(exc).__name__}), no recommendations produced"],
        }

    trace = [
        f"RecommendationAgent: incident_type={incident_type} recommendations={len(report.recommendations)} "
        f"missing_evidence={len(report.missing_evidence)} priority={report.overall_priority.value} "
        f"status={report.recommendation_status}"
    ]
    if summary_trace:
        trace.append(summary_trace)

    return {
        "investigation_recommendation_report": report.model_dump(by_alias=True, mode="json"),
        "trace": trace,
    }
