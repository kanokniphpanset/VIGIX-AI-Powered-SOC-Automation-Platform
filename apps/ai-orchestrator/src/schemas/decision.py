"""Decision output. Approval and responsible roles come from the policy, not from an LLM."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DecisionResult:
    escalate: bool
    responsible_role: str                 # e.g. "SOC"
    approval_required: bool
    approval_role: Optional[str] = None   # e.g. "IR_TEAM"
    severity: str = ""
    policy_id: str = ""
    policy_version: str = ""
    evidence_ids: list[str] = field(default_factory=list)
