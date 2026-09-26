"""Runbook resolver. Rules, not AI.

Incident type + severity -> policy + playbook + procedure
-> RunbookSnapshot (versions pinned).

The same input must always give the same output, so a plan can be audited
later. The snapshot is created here and only here; a later edit to a runbook
never changes a plan that already exists.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from src.schemas.runbook import (
    PolicyRef,
    PlaybookRef,
    ProcedureRef,
    RunbookSnapshot,
)


_REPO_ROOT = Path(__file__).resolve().parents[4]

_POLICY_PATH = _REPO_ROOT / "resources" / "policies" / "incident-response-policy.yaml"
_PLAYBOOK_ROOT = _REPO_ROOT / "apps" / "knowledge" / "playbooks" / "PB-STC-001"
_MANIFEST_PATH = _PLAYBOOK_ROOT / "manifest.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Runbook resource not found: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML structure in: {path}")

    return data


def _resolve_policy() -> PolicyRef:
    data = _load_yaml(_POLICY_PATH)

    return PolicyRef(
        id=str(data.get("id", "")),
        name=str(data.get("id", "")),
        version=str(data.get("version", "1")),
        purpose="Incident response policy",
        responsible_role="",
        approval_required=False,
        approval_role=None,
        required_verification=True,
        required_threat_hunt=False,
    )


def _resolve_playbook(incident_type: str) -> tuple[PlaybookRef, Path]:
    manifest = _load_yaml(_MANIFEST_PATH)

    procedures = manifest.get("procedures") or []

    matched = next(
        (
            procedure
            for procedure in procedures
            if str(procedure.get("code", "")).upper() == incident_type
        ),
        None,
    )

    if matched is None:
        raise ValueError(
            f"No procedure is registered for incident type: {incident_type}"
        )

    status = str(matched.get("status", "")).upper()

    if status != "ACTIVE":
        raise ValueError(
            f"Procedure for incident type {incident_type} is not ACTIVE "
            f"(status={status or 'UNKNOWN'})"
        )

    procedure_path = matched.get("path")

    if not procedure_path:
        raise ValueError(
            f"Procedure path is missing for incident type: {incident_type}"
        )

    procedure_dir = _PLAYBOOK_ROOT / procedure_path

    if not procedure_dir.exists():
        raise FileNotFoundError(
            f"Procedure directory not found for {incident_type}: "
            f"{procedure_dir}"
        )

    phases = [
        str(phase.get("id"))
        for phase in manifest.get("phases", [])
        if phase.get("id")
    ]

    supported_incident_types = [
        str(procedure.get("code"))
        for procedure in procedures
        if str(procedure.get("status", "")).upper() == "ACTIVE"
        and procedure.get("code")
    ]

    playbook = PlaybookRef(
        id=str(manifest.get("id", "")),
        name=str(manifest.get("name", "")),
        version=str(manifest.get("version", "1")),
        phases=phases,
        supported_incident_types=supported_incident_types,
    )

    return playbook, procedure_dir


def _resolve_procedure(
    incident_type: str,
    procedure_dir: Path,
) -> ProcedureRef:
    procedure = _load_yaml(procedure_dir / "procedure.yaml")

    procedure_code = str(procedure.get("code", "")).upper()

    if procedure_code != incident_type:
        raise ValueError(
            f"Procedure code mismatch: expected {incident_type}, "
            f"got {procedure_code or 'UNKNOWN'}"
        )

    containment = _load_yaml(procedure_dir / "containment.yaml")

    candidate_actions = containment.get("candidateActions") or []

    allowed_actions = [
        str(action.get("actionCode"))
        for action in candidate_actions
        if action.get("actionCode")
    ]

    return ProcedureRef(
        id=str(procedure.get("id", "")),
        name=str(procedure.get("name", "")),
        version=str(procedure.get("version", "1")),
        objective=str(procedure.get("objective", "")).strip(),
        allowed_actions=allowed_actions,
    )


def resolve_runbook(
    incident_type: str,
    severity: str,
) -> RunbookSnapshot:
    incident_type = incident_type.strip().upper()
    severity = severity.strip().upper()

    if not incident_type:
        raise ValueError("incident_type is required")

    if not severity:
        raise ValueError("severity is required")

    policy = _resolve_policy()
    playbook, procedure_dir = _resolve_playbook(incident_type)
    procedure = _resolve_procedure(incident_type, procedure_dir)

    return RunbookSnapshot(
        incident_type=incident_type,
        severity=severity,
        policy=policy,
        playbook=playbook,
        procedure=procedure,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
