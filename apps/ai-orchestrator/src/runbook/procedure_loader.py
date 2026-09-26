"""Procedure step loader.

Loads the ordered procedure template used by the Recommendation Agent.

This module only reads procedure resources. It does not:
- select a runbook
- make approval decisions
- execute actions
- write runtime status
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


_REPO_ROOT = Path(__file__).resolve().parents[4]

_PLAYBOOK_ROOT = (
    _REPO_ROOT
    / "apps"
    / "knowledge"
    / "playbooks"
    / "PB-STC-001"
)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and validate a YAML mapping."""
    if not path.exists():
        raise FileNotFoundError(f"Procedure resource not found: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML structure in: {path}")

    return data


def _extract_action_codes(actions: Any) -> list[str]:
    """Extract action codes referenced by human-readable recommendations."""
    if not actions:
        return []

    if not isinstance(actions, list):
        actions = [actions]

    result: list[str] = []

    for action in actions:
        text = str(action).strip()

        if not text:
            continue

        # Expected references such as:
        # "(see containment.yaml: BLOCK_SOURCE_IP)"
        marker = "containment.yaml:"

        if marker in text:
            code = text.split(marker, 1)[1].split(")", 1)[0].strip()

            if code:
                result.append(code.upper())

    return result


def load_procedure_steps(
    incident_type: str,
) -> list[dict[str, Any]]:
    """Load ordered steps for an incident type.

    The returned structure is normalized for Recommendation Agent use.
    """
    code = incident_type.strip().upper()

    procedure_dir = _PLAYBOOK_ROOT / "procedures" / code
    steps_path = procedure_dir / "steps.yaml"

    data = _load_yaml(steps_path)

    procedure_code = str(data.get("procedureCode", "")).strip().upper()

    if procedure_code != code:
        raise ValueError(
            f"Procedure code mismatch: expected {code}, "
            f"found {procedure_code or '<missing>'}"
        )

    raw_steps = data.get("steps", [])

    if not isinstance(raw_steps, list):
        raise ValueError(f"Invalid steps structure in: {steps_path}")

    result: list[dict[str, Any]] = []

    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue

        result.append(
            {
                "step_order": int(raw_step.get("stepOrder", 0)),
                "phase": str(raw_step.get("phase", "")),
                "title": str(raw_step.get("title", "")),
                "objective": str(raw_step.get("objective", "")),
                "recommended_actions": [
                    str(action)
                    for action in raw_step.get("recommendedAction", [])
                ],
                "action_codes": _extract_action_codes(
                    raw_step.get("recommendedAction", [])
                ),
                "reason": str(raw_step.get("reason", "")),
                "evidence_required": [
                    str(item)
                    for item in raw_step.get("evidenceRequired", [])
                ],
                "expected_result": str(
                    raw_step.get("expectedResult", "")
                ),
                "decision_ref": raw_step.get("decisionRef"),
                "responsible_role": str(
                    raw_step.get("responsibleRole", "")
                ),
                "responsible_duty": str(
                    raw_step.get("responsibleDuty", "")
                ),
                "approval_required": bool(
                    raw_step.get("approvalRequired", False)
                ),
                "approval_role": raw_step.get("approvalRole"),
            }
        )

    result.sort(key=lambda step: step["step_order"])

    return result