"""
EmailNotificationService — implements NotificationService for the Email
channel. Pure notification plumbing: never decides anything, catches every
failure and returns a NotificationResult instead of raising (same contract
as jira_notification_service.py), so an SMTP outage can't fail the pipeline
or the other channels NotificationOrchestrator dispatches alongside it.
"""

from __future__ import annotations

import logging

from src.config.settings import settings
from src.notifications import email_formatter
from src.notifications.email_client import EmailClient, EmailError
from src.notifications.models import NotificationMessage, NotificationResult

logger = logging.getLogger("soar.ai-orchestrator")


class EmailNotificationService:
    def __init__(
        self,
        client: EmailClient | None = None,
        enabled: bool = False,
        mock_mode: bool = True,
        recipients: list[str] | None = None,
    ):
        self._client = client
        self._enabled = enabled
        self._mock_mode = mock_mode
        self._recipients = recipients or []

    async def send(self, message: NotificationMessage) -> NotificationResult:
        subject = email_formatter.build_subject(message)
        body = email_formatter.build_body(message)

        if self._mock_mode:
            logger.info(
                "[MOCK EMAIL] To=%s Subject=%s Incident=%s", ", ".join(self._recipients), subject, message.incident_id
            )
            return NotificationResult(success=True, channel="email", detail={"mock": True})

        if not self._enabled:
            return NotificationResult(success=False, channel="email", error="Email notifications are disabled")

        if not self._recipients:
            return NotificationResult(success=False, channel="email", error="No SOC_EMAIL recipient configured")

        if self._client is None or not self._client.is_configured:
            return NotificationResult(success=False, channel="email", error="Email is not configured (missing SMTP settings)")

        try:
            await self._client.send(self._recipients, subject, body)
        except EmailError as exc:
            logger.warning("email.notification.failed", extra={"incidentId": message.incident_id, "reason": exc.__class__.__name__})
            return NotificationResult(success=False, channel="email", error=str(exc))

        logger.info("email.notification.sent", extra={"incidentId": message.incident_id})
        return NotificationResult(success=True, channel="email")


def _build_default_client() -> EmailClient:
    return EmailClient(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username,
        password=settings.smtp_password,
        sender=settings.email_from,
        timeout=settings.email_timeout_s,
    )


def _default_recipients() -> list[str]:
    return [addr.strip() for addr in (settings.soc_email or "").split(",") if addr.strip()]


# Module-level singleton, same pattern as jira_notification_service.jira_notification_service.
email_notification_service = EmailNotificationService(
    client=_build_default_client(),
    enabled=settings.email_enabled,
    mock_mode=settings.email_mock_mode,
    recipients=_default_recipients(),
)
