"""Step execution record: what actually happened when a human/IR executed a ResponsePlanStep.

Deliberately separate from ResponsePlanStep (src/schemas/response_plan.py), which is AI output
only. `completed_at` must be set by the backend when the "Complete Step" action is called - never
accepted from the request body - because verification uses it as the start of the after-window
and a client-supplied timestamp would make that window unverifiable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
COMPLETED = "COMPLETED"
SKIPPED = "SKIPPED"

TERMINAL_STATUSES = frozenset({COMPLETED, SKIPPED})


@dataclass
class StepExecution:
    plan_id: str
    step_key: str                       # matches ResponsePlanStep.key
    status: str = PENDING               # PENDING | IN_PROGRESS | COMPLETED | SKIPPED
    executed_by: str = ""
    started_at: Optional[str] = None
    completed_at: Optional[str] = None  # backend-set; None until COMPLETED or SKIPPED
    actual_result: str = ""
    decision_taken: Optional[str] = None  # which DecisionPoint.options[].value was chosen, if any
