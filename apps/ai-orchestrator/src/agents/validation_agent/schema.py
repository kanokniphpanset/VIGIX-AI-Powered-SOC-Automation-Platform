"""Output schema of the validation agent."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ValidationIssue:
    field: str
    problem: str          # e.g. "Expected 184 but received 284"


@dataclass
class ValidationResult:
    passed: bool
    issues: list[ValidationIssue] = field(default_factory=list)
