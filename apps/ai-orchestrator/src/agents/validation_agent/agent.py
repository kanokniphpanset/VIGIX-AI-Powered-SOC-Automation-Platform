from src.graph.state import AgentState
from .rules import validate


async def run(state: AgentState) -> AgentState:
    """
    ValidationAgent — cross-checks ThreatIntelAgent, MitreAgent, RagAgent, and
    MlRiskAgent's outputs for internal consistency before DecisionAgent acts on
    them. A failed check routes the graph back to re-run enrichment (see
    graph/router.py), up to a retry cap.
    """
    passed, notes = validate(dict(state))

    retry_count = state.get("retry_count", 0)
    if not passed:
        retry_count += 1

    return {
        "validation_passed": passed,
        "validation_notes": notes,
        "retry_count": retry_count,
        "trace": [f"ValidationAgent: passed={passed}, notes={notes}"],
    }
