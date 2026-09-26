"""Verification service.

Runs rehunt_tool, compares before / after, sets RESOLVED or NOT_RESOLVED. No LLM.
NOT_RESOLVED (or spread) -> next action is to generate the next plan.

verify(plan_id) takes NO other arguments on purpose: every input it needs (the original hunt
query, the time window, which agents, when remediation finished) is derived from data already
recorded in the system, so the caller never has to know Investigation/Execution internals.

    plan_id
      -> ResponsePlan               (RecommendationRepository)
      -> original HuntQuery         (EvidenceRepository, WAZUH_HUNT evidence for the incident)
      -> remediation completed_at   (StepExecutionRepository, latest terminal step)
      -> rehunt_tool.run_rehunt(original_query, before=hunt window, after=completed_at..now)
      -> RESOLVED / NOT_RESOLVED
      -> VerificationRepository.save(...)

Before/after windows are NEVER derived from ResponsePlan.created_at: that would measure "did the
threat vanish after the AI made a recommendation" instead of "did it vanish after IR acted on it".
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Optional

from src.repositories.evidence_repository import EvidenceRepository
from src.repositories.incident_repository import IncidentRepository
from src.repositories.recommendation_repository import RecommendationRepository
from src.repositories.step_execution_repository import StepExecutionRepository
from src.repositories.verification_repository import VerificationRepository
from src.schemas.evidence import REHUNT_RESULT, WAZUH_HUNT
from src.schemas.hunt_query import HuntQueryData, HuntQueryDataError
from src.schemas.step_execution import TERMINAL_STATUSES
from src.schemas.verification import NOT_RESOLVED, RESOLVED, VerificationResult
from src.tools import rehunt_tool

STATUS_OK = "ok"
STATUS_NOT_READY = "not_ready"   # remediation hasn't finished yet - re-hunting now would be meaningless
STATUS_ERROR = "error"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VerificationError(RuntimeError):
    """Base class for verification failures that are the caller's problem to fix
    (missing evidence, incomplete remediation) rather than a transient tool failure."""


class RemediationNotCompleteError(VerificationError):
    """At least one step of the plan has no terminal (COMPLETED/SKIPPED) execution record yet."""


class MissingHuntQueryError(VerificationError):
    """No WAZUH_HUNT evidence found for the incident; there is no original query to re-run."""


class VerificationService:
    def __init__(
        self,
        recommendation_repo: Optional[RecommendationRepository] = None,
        incident_repo: Optional[IncidentRepository] = None,
        evidence_repo: Optional[EvidenceRepository] = None,
        step_execution_repo: Optional[StepExecutionRepository] = None,
        verification_repo: Optional[VerificationRepository] = None,
    ) -> None:
        self._recommendations = recommendation_repo or RecommendationRepository()
        self._incidents = incident_repo or IncidentRepository()
        self._evidence = evidence_repo or EvidenceRepository()
        self._step_executions = step_execution_repo or StepExecutionRepository()
        self._verifications = verification_repo or VerificationRepository()

    # ------------------------------------------------------------------ derivation helpers
    def _find_hunt_query(self, plan: dict[str, Any], incident_id: str) -> HuntQueryData:
        """The hunt query linked from the plan's steps wins; otherwise fall back to the
        earliest WAZUH_HUNT evidence recorded for the incident (the original investigation)."""
        evidence_list = self._evidence.list_for_incident(incident_id)
        hunts = [e for e in evidence_list if e.get("type") == WAZUH_HUNT]
        if not hunts:
            raise MissingHuntQueryError(
                f"no WAZUH_HUNT evidence found for incident {incident_id!r}; "
                "cannot re-hunt without the original investigation query"
            )

        linked_ids = {
            eid
            for step in plan.get("steps", [])
            for eid in step.get("evidence_ids", [])
        }
        linked = [e for e in hunts if e.get("evidence_id") in linked_ids]
        chosen = linked[0] if linked else min(hunts, key=lambda e: e.get("timestamp", ""))

        try:
            return HuntQueryData.from_evidence(chosen)
        except HuntQueryDataError as exc:
            raise MissingHuntQueryError(str(exc)) from exc

    def _remediation_completed_at(self, plan_id: str) -> str:
        """Latest completed_at across every step's execution record. Raises if any step has
        no terminal record yet - verifying mid-remediation would compare against a moving target."""
        executions = self._step_executions.list_for_plan(plan_id)
        if not executions:
            raise RemediationNotCompleteError(f"plan {plan_id!r} has no step executions recorded yet")

        not_terminal = [e for e in executions if e.get("status") not in TERMINAL_STATUSES]
        if not_terminal:
            pending_keys = [e.get("step_key") for e in not_terminal]
            raise RemediationNotCompleteError(
                f"plan {plan_id!r} still has unfinished steps: {pending_keys}"
            )

        completed_ats = [e["completed_at"] for e in executions if e.get("completed_at")]
        if not completed_ats:
            # every step was SKIPPED with no timestamp recorded - nothing to measure "after" from
            raise RemediationNotCompleteError(f"plan {plan_id!r} has no completed_at timestamps")
        return max(completed_ats)

    # ------------------------------------------------------------------ evaluation
    @staticmethod
    def _evaluate(after_count: int, spread_detected: bool) -> str:
        if after_count == 0 and not spread_detected:
            return RESOLVED
        return NOT_RESOLVED

    def _record_new_evidence(self, incident_id: str, rehunt_data: dict[str, Any]) -> list[str]:
        """On NOT_RESOLVED, file the re-hunt result as evidence so Plan #2 has something to cite."""
        evidence_id = self._evidence.add({
            "incident_id": incident_id,
            "type": REHUNT_RESULT,
            "source": "rehunt",
            "timestamp": _utcnow_iso(),
            "data": rehunt_data,
        })
        return [evidence_id]

    # ------------------------------------------------------------------ public API
    def verify(self, plan_id: str) -> dict:
        plan = self._recommendations.get_plan(plan_id)
        incident_id = plan["incident_id"]

        hunt = self._find_hunt_query(plan, incident_id)
        remediation_completed_at = self._remediation_completed_at(plan_id)
        verification_started_at = _utcnow_iso()

        after_range = {"from": remediation_completed_at, "to": verification_started_at}

        rehunt = rehunt_tool.run_rehunt(
            original_query=hunt.query,
            before_range=hunt.time_range,
            after_range=after_range,
            agents=hunt.agents_for_rehunt(),
            ioc=hunt.ioc,
        )
        if not rehunt.ok:
            return {
                "status": STATUS_ERROR,
                "plan_id": plan_id,
                "reason": f"rehunt_tool failed: {rehunt.error}",
            }

        before_count = rehunt.data["before_count"]
        after_count = rehunt.data["after_count"]
        spread_detected = rehunt.data["spread_detected"]
        new_hosts = [h["id"] for h in rehunt.data["new_hosts"]]

        result = self._evaluate(after_count, spread_detected)
        next_action = "GENERATE_NEXT_PLAN" if result == NOT_RESOLVED else None

        new_evidence_ids: list[str] = []
        if result == NOT_RESOLVED:
            new_evidence_ids = self._record_new_evidence(incident_id, {
                "before_count": before_count,
                "after_count": after_count,
                "spread_detected": spread_detected,
                "new_hosts": new_hosts,
                "query": hunt.query,
                "after_range": after_range,
            })

        verification = VerificationResult(
            plan_id=plan_id,
            result=result,
            before_count=before_count,
            after_count=after_count,
            spread_detected=spread_detected,
            query=hunt.query,
            before_range=hunt.time_range,
            after_range=after_range,
            new_hosts=new_hosts,
            new_evidence_ids=new_evidence_ids,
            next_action=next_action,
        )
        self._verifications.save(asdict(verification))

        return {"status": STATUS_OK, **asdict(verification)}
