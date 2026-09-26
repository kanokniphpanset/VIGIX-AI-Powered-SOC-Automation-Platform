"""Response plan service.

Creates and validates response plans and creates the next investigation
cycle when verification shows that the incident is not resolved.

Validation must reject any recommended action that is not present in
procedure.allowed_actions.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any


class ResponsePlanService:
    """Service for response-plan lifecycle and validation."""

    def create_plan(self, incident_id: str, plan: Any) -> dict:
        """Create a normalized response-plan dictionary."""

        if not incident_id:
            raise ValueError("incident_id is required")

        if plan is None:
            raise ValueError("plan is required")

        if is_dataclass(plan):
            data = asdict(plan)
        elif isinstance(plan, dict):
            data = dict(plan)
        else:
            raise TypeError(
                "plan must be a dataclass instance or dict"
            )

        data["incident_id"] = str(incident_id)

        if not data.get("plan_id"):
            data["plan_id"] = (
                f"RP-{incident_id}-{data.get('cycle', 1)}"
            )

        data.setdefault("cycle", 1)
        data.setdefault("parent_plan_id", None)
        data.setdefault("trigger", "NEW_INCIDENT")
        data.setdefault("steps", [])
        data.setdefault("runbook_policy_version", "")
        data.setdefault("runbook_playbook_version", "")
        data.setdefault("runbook_procedure_version", "")
        data.setdefault("model", "")
        data.setdefault("prompt_version", "")

        if not data.get("created_at"):
            data["created_at"] = (
                datetime.now(timezone.utc).isoformat()
            )

        return data

    def validate_plan(
        self,
        plan: Any,
        snapshot: Any,
    ) -> list[str]:
        """Validate that every recommended action is allowed."""

        errors: list[str] = []

        if plan is None:
            return ["plan is required"]

        if snapshot is None:
            return ["runbook snapshot is required"]

        procedure = self._get_value(snapshot, "procedure")

        if procedure is None:
            return ["runbook snapshot procedure is required"]

        allowed_actions = {
            str(action).strip().upper()
            for action in self._get_value(
                procedure,
                "allowed_actions",
                [],
            )
            if str(action).strip()
        }

        steps = self._get_value(plan, "steps", [])

        for index, step in enumerate(steps, start=1):
            step_key = self._get_value(
                step,
                "key",
                f"STEP-{index}",
            )

            actions = self._get_value(
                step,
                "recommended_actions",
                [],
            )

            for action in actions:
                normalized = str(action).strip().upper()

                if not normalized:
                    continue

                if normalized not in allowed_actions:
                    errors.append(
                        f"{step_key}: action "
                        f"'{normalized}' is not allowed by "
                        f"procedure.allowed_actions"
                    )

        return errors

    def create_next_plan(
        self,
        parent_plan_id: str,
        verification: dict,
    ) -> dict:
        """Create metadata for the next response-plan cycle."""

        if not parent_plan_id:
            raise ValueError("parent_plan_id is required")

        if verification is None:
            raise ValueError("verification is required")

        current_cycle = self._get_value(
            verification,
            "cycle",
            1,
        )

        try:
            next_cycle = int(current_cycle) + 1
        except (TypeError, ValueError):
            next_cycle = 2

        incident_id = self._get_value(
            verification,
            "incident_id",
            "",
        )

        if not incident_id:
            incident_id = self._get_value(
                verification,
                "parent_incident_id",
                "",
            )

        return {
            "plan_id": f"RP-{incident_id}-{next_cycle}",
            "incident_id": str(incident_id),
            "cycle": next_cycle,
            "parent_plan_id": str(parent_plan_id),
            "trigger": self._build_trigger(verification),
            "steps": [],
            "runbook_policy_version": "",
            "runbook_playbook_version": "",
            "runbook_procedure_version": "",
            "model": "",
            "prompt_version": "",
            "created_at": datetime.now(
                timezone.utc
            ).isoformat(),
        }

    @staticmethod
    def _get_value(
        source: Any,
        key: str,
        default: Any = None,
    ) -> Any:
        """Read a value from either a dict or an object."""

        if isinstance(source, dict):
            return source.get(key, default)

        return getattr(source, key, default)

    @staticmethod
    def _build_trigger(verification: Any) -> str:
        """Map verification outcome to the next-plan trigger."""

        result = str(
            ResponsePlanService._get_value(
                verification,
                "result",
                "",
            )
        ).upper()

        if result == "SPREAD":
            return "THREAT_SPREAD"

        if result == "THREAT_NOT_CONTAINED":
            return "THREAT_NOT_CONTAINED"

        if result == "NOT_RESOLVED":
            return "NOT_RESOLVED"

        return "VERIFICATION_FAILED"