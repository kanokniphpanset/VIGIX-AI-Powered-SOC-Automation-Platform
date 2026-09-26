"""Verification (re-hunt) output."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

RESOLVED = "RESOLVED"
NOT_RESOLVED = "NOT_RESOLVED"


@dataclass
class VerificationResult:
    plan_id: str
    result: str                                   # RESOLVED | NOT_RESOLVED
    before_count: int
    after_count: int
    spread_detected: bool
    query: str = ""
    before_range: dict[str, Any] = field(default_factory=dict)
    after_range: dict[str, Any] = field(default_factory=dict)
    new_hosts: list[str] = field(default_factory=list)
    new_evidence_ids: list[str] = field(default_factory=list)
    next_action: Optional[str] = None             # e.g. "GENERATE_NEXT_PLAN"
