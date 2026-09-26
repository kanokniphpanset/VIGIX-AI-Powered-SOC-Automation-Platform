"""
ValidationAgent's deterministic rule engine.

`validate()` is UNCHANGED in behavior from before the Validation Stage task
— its exact (bool, list[str]) signature and every message string it can
produce are preserved verbatim, because decision_agent/decision_engine.py's
_resolve_validation() imports and calls it directly by name as a fallback
for the Universal Analysis Graph (build_analysis_graph()), which has no
ValidationAgent node of its own. Changing this function's behavior would
silently change DecisionAgent's policy evaluation for that graph — out of
this task's scope (section 14: do not touch DecisionAgent unless required).

`validate_full()` is new (Validation Stage task): it reuses the exact same
four numeric sub-checks below (zero duplicated logic) and adds the new
LLM-vs-evidence consistency checks (llm_consistency.py) to produce a richer,
structured VALID/WARNING/INVALID report. Only validation_agent/agent.py
calls it — decision_engine.py's fallback path is untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from . import llm_consistency
from .llm_consistency import CheckResult

ValidationStatus = Literal["VALID", "WARNING", "INVALID"]


@dataclass(frozen=True)
class ValidationReport:
    status: ValidationStatus
    is_valid: bool  # True for VALID and WARNING — matches this task's own semantics (WARNING is still usable)
    checks: list[CheckResult] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)  # every non-PASS check's details, in check order


def _check_mitre_confidence(state: dict) -> CheckResult:
    weak_techniques = [t for t in state.get("mitre_techniques", []) if t.get("confidence", 0) < 0.4]
    if weak_techniques:
        return CheckResult("mitre_confidence", "WARNING", f"{len(weak_techniques)} MITRE technique match(es) below confidence threshold")
    return CheckResult("mitre_confidence", "PASS", "MITRE technique matches meet the confidence threshold")


def _check_ioc_enrichment(state: dict) -> CheckResult:
    iocs = state.get("iocs", [])
    unverified_iocs = [i for i in iocs if i.get("reputation_score") is None]
    if unverified_iocs and len(unverified_iocs) == len(iocs) and iocs:
        return CheckResult(
            "ioc_enrichment",
            "WARNING",
            "No IOC could be enriched with reputation data (threat intel sources unreachable or unconfigured)",
        )
    return CheckResult("ioc_enrichment", "PASS", "IOC reputation data available where applicable")


def validate(state: dict) -> tuple[bool, list[str]]:
    """
    Cross-checks upstream agent outputs for internal consistency.
    Returns (passed, notes). This is intentionally rule-based and transparent —
    an analyst can read validation_notes and understand exactly why a run was
    flagged, rather than trusting an opaque second LLM call to judge the first.
    """
    results = [
        _check_mitre_confidence(state),
        _check_ioc_enrichment(state),
    ]
    passed = not any(r.status == "FAIL" for r in results)
    notes = [r.details for r in results if r.status != "PASS"]
    if not notes:
        notes = ["All checks passed"]
    return passed, notes


def validate_full(state: dict) -> ValidationReport:
    """
    Validation Stage task: the richer VALID/WARNING/INVALID gate, additive
    to validate() above. Combines the same three checks with the new
    LLM-vs-evidence consistency checks (llm_consistency.py) — evidence
    support, risk-text consistency, MITRE consistency, IOC consistency,
    knowledge grounding, recommendation safety.

    INVALID: at least one check FAILed — a material, unsupported claim or
    contradiction makes downstream recommendation generation unsafe.
    WARNING: no FAIL, but at least one check only WARNed — usable, but
    caveated (partial/optional data, low confidence, ...).
    VALID: every check PASSed.
    """
    checks = [
        _check_mitre_confidence(state),
        _check_ioc_enrichment(state),
        *llm_consistency.run_llm_consistency_checks(state),
    ]

    if any(c.status == "FAIL" for c in checks):
        status: ValidationStatus = "INVALID"
    elif any(c.status == "WARNING" for c in checks):
        status = "WARNING"
    else:
        status = "VALID"

    issues = [c.details for c in checks if c.status != "PASS"]
    return ValidationReport(status=status, is_valid=status != "INVALID", checks=checks, issues=issues)
