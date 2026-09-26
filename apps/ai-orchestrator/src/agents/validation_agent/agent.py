"""Validation agent.

Validates the analyst output and upstream evidence using the deterministic
validation rule engine. This module also exposes the LangGraph-compatible
`run(state)` entrypoint expected by build_graph.py.
"""

from __future__ import annotations

from src.contracts.error_builder import build_error
from src.graph.state import AgentState

from .rules import validate_full
from .schema import ValidationIssue, ValidationResult
from src.agents.llm_analyst_agent.schema import AnalystReport


def run_validation(
    report: AnalystReport,
    tool_results: dict,
) -> ValidationResult:
    """Compatibility wrapper for callers that still use the old API."""

    state = dict(tool_results)

    state["analyst_report"] = {
        "classification": report.classification,
        "hypotheses": report.hypotheses,
        "analysis": report.analysis,
        "unknowns": report.unknowns,
        "evidence_ids": report.evidence_ids,
    }

    validation_report = validate_full(state)

    return ValidationResult(
        passed=validation_report.is_valid,
        issues=[
            ValidationIssue(
                field="validation",
                problem=issue,
            )
            for issue in validation_report.issues
        ],
    )


async def run(state: AgentState) -> AgentState:
    """LangGraph validation node.

    Writes the FLAT state keys the rest of the pipeline reads (validation_passed / _status / _notes / _checks —
    router.after_validation, recommendation_agent, output_contract, database). A key named "validation" would
    collide with this node's own name and be dropped by LangGraph (see graph/state.py). `retry_count` is
    incremented on every failed validation so the retry loop in router.after_validation always terminates.
    """

    retry_count = int(state.get("retry_count") or 0)

    try:
        validation_report = validate_full(dict(state))

        checks = [
            {
                # CheckResult's field is `check` (llm_consistency.CheckResult); exposed as "name" in the contract.
                "name": check.check,
                "status": check.status,
                "details": check.details,
            }
            for check in validation_report.checks
        ]

        passed = validation_report.is_valid

        return {
            "validation_passed": passed,
            "validation_status": validation_report.status,
            "validation_notes": list(validation_report.issues),
            "validation_checks": checks,
            "retry_count": retry_count if passed else retry_count + 1,
            "trace": [
                (
                    f"ValidationAgent: status={validation_report.status}, "
                    f"passed={passed}, "
                    f"issues={len(validation_report.issues)}"
                )
            ],
        }

    except Exception as exc:  # noqa: BLE001 - recorded as a structured error; validation fails closed
        error = build_error(
            agent="validation",
            code="AGENT_EXECUTION_FAILED",
            message=f"Validation agent failed: {exc}",
            retryable=True,
            severity="ERROR",
        )

        return {
            # Fail closed: an analysis that could not be validated is never treated as validated.
            "validation_passed": False,
            "validation_status": "ERROR",
            "validation_notes": [f"Validation execution failed: {exc}"],
            "validation_checks": [],
            "retry_count": retry_count + 1,
            "structured_errors": [
                error.model_dump(by_alias=True, mode="json")
            ],
            "trace": [
                f"ValidationAgent: execution failed ({type(exc).__name__})"
            ],
        }
