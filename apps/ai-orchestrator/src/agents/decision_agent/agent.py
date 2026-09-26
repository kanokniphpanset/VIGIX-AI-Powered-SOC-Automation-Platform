"""Decision agent.

ADVISORY ONLY. Suggests who should look at the incident from the classification
and the SEVERITY the ML classifier suggested. The backend Policy Engine is the
only authority for responsibility / approval / execution (it evaluates the
analyst-validated incident severity); this output is recorded for audit and
never approves, executes or triggers anything.

No risk score is used: Severity is VIGIX's primary classification.

Policy decisions are deterministic and never delegated to an LLM.
"""

from __future__ import annotations

from typing import Any

from .schema import DecisionResult

_SEVERITIES = ("low", "medium", "high", "critical")


def _severity(value: Any) -> str:
    """Normalise a severity label; anything else is "" (unknown)."""
    s = str(value or "").strip().lower()
    return s if s in _SEVERITIES else ""


def run_decision(
    classification: str,
    severity: str,
    snapshot: dict,
    evidence_ids: list[str] | None = None,
) -> DecisionResult:
    """Deterministic, severity-based advisory decision.

    Mirrors the backend's two-role policy (SOC + IR_TEAM; the backend remains the authority):
      - false positive           -> dismiss (SOC), nothing to approve
      - any other severity       -> SOC investigates; every Response Ticket needs the IR_TEAM decision
      - critical                 -> additionally escalate
      - unknown severity         -> same (never "no approval" by default)
    """

    classification = str(classification or "").strip().lower()
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    severity = _severity(snapshot.get("severity")) or _severity(severity)

    policy = snapshot.get("policy") or {}
    policy_id = str(policy.get("id") or "")
    policy_version = str(policy.get("version") or "")
    evidence = [str(item) for item in (evidence_ids or []) if item]

    def result(escalate: bool, role: str, approval: bool, approver: str | None) -> DecisionResult:
        return DecisionResult(
            escalate=escalate,
            responsible_role=role,
            approval_required=approval,
            approval_role=approver,
            severity=severity,
            policy_id=policy_id,
            policy_version=policy_version,
            evidence_ids=evidence,
        )

    if classification in {"false_positive", "false-positive", "benign"}:
        return result(False, "SOC", False, None)
    # SOC investigates every incident; IR_TEAM is the only approver (APPROVE / REJECT on each Response Ticket).
    return result(severity == "critical", "SOC", True, "IR_TEAM")


async def run(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph adapter for the Decision Agent."""

    classification_data = state.get("classification") or {}

    if isinstance(classification_data, dict):
        classification = (
            classification_data.get("label")
            or classification_data.get("classification")
            or classification_data.get("type")
            or ""
        )
    else:
        classification = str(classification_data)

    severity = state.get("severity") or ""  # Wazuh rule-level severity; AI never produces one
    snapshot = state.get("runbook_snapshot") or {}

    result = run_decision(
        classification=classification,
        severity=severity,
        snapshot=snapshot,
    )

    if result.approval_required:
        decision = "human_approval"
    elif result.escalate:
        decision = "escalate"
    elif classification.lower() in {
        "false_positive",
        "false-positive",
        "benign",
    }:
        decision = "dismiss"
    else:
        decision = "auto_response"

    return {
        "decision_result": result.__dict__,
        "decision": decision,
        "requires_approval": result.approval_required,
        "trace": [
            (
                "DecisionAgent: completed (advisory); "
                f"decision={decision}; "
                f"severity={result.severity or 'unknown'}; "
                f"approval={result.approval_required}"
            )
        ],
    }
