"""Pure text formatting for the Email channel — no I/O, no policy decisions. Matches the task's section-5 template."""

from __future__ import annotations

from src.notifications.models import NotificationMessage


def build_subject(message: NotificationMessage) -> str:
    tag = "HUMAN APPROVAL REQUIRED" if message.approval_required else message.decision.replace("_", " ")
    return f"[VIGIX][{message.priority}][{tag}] {message.incident_type} Incident {message.incident_id}"


def build_body(message: NotificationMessage) -> str:
    lines = ["VIGIX Security Incident", ""]

    if message.approval_required:
        lines += ["*** HUMAN APPROVAL IS REQUIRED ***", ""]

    lines += [
        "Incident ID:",
        message.incident_id,
        "",
        "Incident Type:",
        message.incident_type,
        "",
        "Severity (suggested):",
        message.priority.upper(),
        "",
        "Confidence:",
        f"{message.confidence:.2f}",
        "",
        "Asset Criticality:",
        message.asset_criticality.upper(),
        "",
        "Decision:",
        message.decision,
        "",
    ]

    if message.approval_tier:
        lines += ["Approval:", message.approval_tier, ""]

    action_lines = [f"- {a.action_name}" for a in message.recommended_actions] or ["- None"]
    lines += ["Recommended Actions:", *action_lines, ""]

    mitre_lines = [
        f"{t.get('technique_id', 'UNKNOWN')} - {t.get('name', 'Unknown technique')}" for t in message.mitre_techniques
    ] or ["None"]
    lines += ["MITRE:", *mitre_lines, ""]

    rationale_lines = [f"- {r}" for r in message.rationale] or ["- No rationale recorded"]
    lines += ["Rationale:", *rationale_lines]

    if message.jira_reference:
        lines += ["", "Jira:", message.jira_reference]

    return "\n".join(lines)
