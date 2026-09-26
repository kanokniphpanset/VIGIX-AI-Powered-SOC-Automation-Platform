"""
ClassificationAgent — LangGraph node convention (`async def run`, matching
every other agent in src/agents/**), NOT wired into graph/build_graph.py
yet (section 17/21's own boundary — independently testable first, no
LangGraph orchestration in this task).

Reads Evidence[] (contracts/evidence.py::build_evidence — the same
already-established, cross-agent evidence list every other consumer of
AgentState reads) and scores it via classification_rules.classify(), a
pure function with zero I/O. That function never raises on well-formed
EvidenceItem input; the try/except below is a last-resort guard against a
genuinely malformed AgentState, wired into the Universal Error Contract
exactly like error_builder.py's own adapters (section 15) — never the
primary path.
"""

from __future__ import annotations

from src.contracts.error_builder import build_error
from src.contracts.evidence import build_evidence
from src.graph.state import AgentState

from .classification_rules import classify, unknown_classification


async def run(state: AgentState) -> AgentState:
    try:
        evidence_items = build_evidence(dict(state))
        result = classify(evidence_items)
    except Exception as exc:  # noqa: BLE001 - last-resort guard, see module docstring; never crash the graph
        error = build_error(
            agent="classification",
            code="AGENT_EXECUTION_FAILED",
            message=f"ClassificationAgent failed: {exc}",
            retryable=False,
            severity="ERROR",
        )
        return {
            "classification": unknown_classification().model_dump(by_alias=True, mode="json"),
            "structured_errors": [error.model_dump(by_alias=True, mode="json")],
            "trace": [f"ClassificationAgent: execution failed ({type(exc).__name__}), classification set to UNKNOWN"],
        }

    return {
        "classification": result.model_dump(by_alias=True, mode="json"),
        "trace": [f"ClassificationAgent: category={result.category} confidence={result.confidence} status={result.status}"],
    }
