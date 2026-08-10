from src.graph.state import AgentState

MAX_RETRIES = 2


def after_validation(state: AgentState) -> str:
    """
    ValidationAgent's conditional edge: retry enrichment if validation failed
    and we haven't exceeded MAX_RETRIES, otherwise proceed to DecisionAgent.
    """
    if not state.get("validation_passed", True) and state.get("retry_count", 0) < MAX_RETRIES:
        return "retry"
    return "proceed"


def after_decision(state: AgentState) -> str:
    """
    DecisionAgent's conditional edge. All three outcomes converge on the same
    next node (business_analytics) — the branch exists so n8n dispatch logic
    (added at the backend/n8n integration layer) can key off state["decision"]
    without the graph itself needing separate downstream paths yet.
    """
    return state.get("decision", "dismiss")
