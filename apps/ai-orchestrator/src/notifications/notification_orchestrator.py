from __future__ import annotations

import logging

from src.agents.decision_agent.models import DecisionResult
from src.notifications.email_notification_service import email_notification_service
from src.notifications.models import (
    IncidentContext,
    NotificationMessage,
    NotificationResult,
)

logger = logging.getLogger("soar.ai-orchestrator")


class NotificationOrchestrator:
    """
    Dispatches incident notifications to configured channels.

    Notification failures must never fail the main AI pipeline.
    """

    def __init__(
        self,
        email_service=email_notification_service,
    ):
        self._email_service = email_service

    async def dispatch(
        self,
        decision: DecisionResult,
        incident: IncidentContext,
    ) -> list[NotificationResult]:

        message = NotificationMessage(
            incident_id=incident.incident_id,
            incident_type=incident.incident_type,
            priority=decision.severity or incident.severity or "MEDIUM",
            confidence=incident.confidence,
            asset_criticality=incident.asset_criticality or "unknown",
            decision=getattr(decision, "escalate", False)
            and "escalate"
            or "human_approval"
            if decision.approval_required
            else "auto_response",
            approval_required=decision.approval_required,
            approval_tier=decision.approval_role,
            recommended_actions=incident.recommended_actions,
            mitre_techniques=incident.mitre_techniques,
            rationale=incident.rationale,
        )

        results: list[NotificationResult] = []

        # Email is currently the first enabled channel.
        # Failures are captured so notification problems cannot
        # break the incident pipeline.
        try:
            result = await self._email_service.send(message)
            results.append(result)

            if not result.success:
                logger.warning(
                    "notification.email.failed",
                    extra={
                        "incidentId": incident.incident_id,
                        "error": result.error,
                    },
                )

        except Exception as exc:
            logger.exception(
                "notification.email.unexpected_failure",
                extra={"incidentId": incident.incident_id},
            )
            results.append(
                NotificationResult(
                    success=False,
                    channel="email",
                    error=str(exc),
                )
            )

        return results


notification_orchestrator = NotificationOrchestrator()
