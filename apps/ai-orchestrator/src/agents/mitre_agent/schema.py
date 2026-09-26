"""Output schema of the mitre agent."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MitreMapping:
    technique_id: str            # e.g. "T1110"
    technique: str
    tactics: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)   # required and non-empty
    confidence: float = 0.0
