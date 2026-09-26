from src.graph.state import GraphState

MAX_RETRIES = 2


def after_validation(state: GraphState) -> str:
    """
    ValidationAgent's conditional edge: retry enrichment if validation failed
    and we haven't exceeded MAX_RETRIES, otherwise proceed to DecisionAgent.
    """
    if not state.get("validation_passed", True) and state.get("retry_count", 0) < MAX_RETRIES:
        return "retry"
    return "proceed"


def after_decision(state: GraphState) -> str:
    """
    DecisionAgent's conditional edge. All four outcomes (auto_response,
    human_approval, dismiss, escalate) converge on the same next node
    (business_analytics) — the branch exists so n8n dispatch logic (added at
    the backend/n8n integration layer) can key off state["decision"] without
    the graph itself needing separate downstream paths yet.
    """
    return state.get("decision", "dismiss")
