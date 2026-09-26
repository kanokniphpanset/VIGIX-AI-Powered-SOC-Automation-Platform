"""Output schema of the llm analyst agent."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AnalystReport:
    classification: str                                     # e.g. "BRUTE_FORCE"
    hypotheses: list[str] = field(default_factory=list)
    analysis: str = ""
    unknowns: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)   # must all exist
