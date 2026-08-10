from typing import Literal

Decision = Literal["auto_response", "human_approval", "dismiss"]


def decide(risk_score: float, auto_threshold: float, approval_threshold: float) -> tuple[Decision, bool]:
    """
    Policy engine: three-tier risk threshold.
      - below auto_threshold        -> dismiss (log only, no action)
      - between the two thresholds  -> auto_response (n8n runs the playbook unattended)
      - at/above approval_threshold -> human_approval (n8n pauses for analyst sign-off)

    Returns (decision, requires_approval).
    """
    if risk_score < auto_threshold:
        return "dismiss", False
    if risk_score < approval_threshold:
        return "auto_response", False
    return "human_approval", True
