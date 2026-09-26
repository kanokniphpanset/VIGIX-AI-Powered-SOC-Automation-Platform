"""Risk score output. Produced by a model / formula, never by an LLM."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskResult:
    score: int                                   # 0-100
    level: str                                   # LOW | MEDIUM | HIGH | CRITICAL
    features: dict[str, float] = field(default_factory=dict)  # contribution per feature
    model_version: str = ""
