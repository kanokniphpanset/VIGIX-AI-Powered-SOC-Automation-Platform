from src.graph.state import AgentState
from src.config.settings import settings
from .policy_rules import decide


async def run(state: AgentState) -> AgentState:
    """
    DecisionAgent — applies the risk-threshold policy engine to decide whether
    to dismiss, auto-respond (n8n runs unattended), or require human approval.
    Thresholds are configured in config/settings.py (risk_auto_response_threshold,
    risk_human_approval_threshold) so a SOC can tune them without touching code.
    """
    risk_score = state.get("risk_score", 0.0)

    decision, requires_approval = decide(
        risk_score, settings.risk_auto_response_threshold, settings.risk_human_approval_threshold
    )

    return {
        "decision": decision,
        "requires_approval": requires_approval,
        "trace": [f"DecisionAgent: decision={decision}, requires_approval={requires_approval}"],
    }
