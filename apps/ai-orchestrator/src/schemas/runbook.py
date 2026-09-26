"""Runbook snapshot: the policy / playbook / procedure versions a plan was built from."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PolicyRef:
    id: str
    name: str
    version: str
    purpose: str = ""
    responsible_role: str = ""
    approval_required: bool = False
    approval_role: Optional[str] = None
    required_verification: bool = False
    required_threat_hunt: bool = False


@dataclass
class PlaybookRef:
    id: str
    name: str
    version: str
    phases: list[str] = field(default_factory=list)
    supported_incident_types: list[str] = field(default_factory=list)


@dataclass
class ProcedureRef:
    id: str
    name: str
    version: str
    objective: str = ""
    allowed_actions: list[str] = field(default_factory=list)  # the only actions the AI may recommend


@dataclass
class RunbookSnapshot:
    incident_type: str
    severity: str
    policy: PolicyRef
    playbook: PlaybookRef
    procedure: ProcedureRef
    created_at: str = ""
