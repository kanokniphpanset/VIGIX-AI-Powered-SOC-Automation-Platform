"""Response plan. Mirrors what the Response Plan page shows.

The AI fills the *recommendation* fields only. `status`, `actual_result`, who executed it and
which decision-point branch was chosen are recorded by people and live outside this schema.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DecisionPoint:
    question: str
    options: list[dict[str, str]] = field(default_factory=list)  # [{"value": "YES", "next": "..."}]


@dataclass
class ApprovalRequirement:
    required: bool
    role: Optional[str] = None
    level: Optional[str] = None
    reason: str = ""                 # taken from the policy


@dataclass
class ResponsePlanStep:
    key: str
    title: str
    objective: str
    recommended_actions: list[str] = field(default_factory=list)   # must be in procedure.allowed_actions
    reason: str = ""
    basis: str = ""                  # which policy / playbook / procedure part this comes from
    evidence_required: list[str] = field(default_factory=list)
    expected_result: str = ""
    decision_point: Optional[DecisionPoint] = None
    responsible_duty: str = ""
    approval: ApprovalRequirement = field(default_factory=lambda: ApprovalRequirement(required=False))
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class ResponsePlan:
    plan_id: str
    incident_id: str
    cycle: int = 1
    parent_plan_id: Optional[str] = None
    trigger: str = "NEW_INCIDENT"    # NEW_INCIDENT | THREAT_SPREAD | ...
    steps: list[ResponsePlanStep] = field(default_factory=list)
    runbook_policy_version: str = ""
    runbook_playbook_version: str = ""
    runbook_procedure_version: str = ""
    model: str = ""
    prompt_version: str = ""
    created_at: str = ""
