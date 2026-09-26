"""Graph wiring.

extract_ioc
   -> [threat_intel | mitre | rag | risk]   (run in parallel)
   -> analyst -> validation -+-> decision -> recommendation -> WAIT (people act)
                             +-> analyst    (validation failed, retries left)
                             +-> needs_human (validation failed, retries used up)

Verification is outside this graph: when it returns NOT_RESOLVED the graph is started again with
cycle + 1, trigger="THREAT_SPREAD" and parent_plan_id set.
"""
from __future__ import annotations

from .state import GraphState

MAX_VALIDATION_RETRIES = 2


def route_after_validation(state: GraphState) -> str:
    """Next node after validation."""
    if state.get("validation", {}).get("passed"):
        return "decision"
    if state.get("validation_retries", 0) < MAX_VALIDATION_RETRIES:
        return "analyst"
    return "needs_human"


def build_graph():
    """Register the nodes and edges above with the graph framework used by the project."""
    raise NotImplementedError("TODO: build with the project's graph library")
