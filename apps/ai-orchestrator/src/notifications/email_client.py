"""
Thin SMTP client — same shape as jira_client.py (is_configured guard, typed
errors, no retry/backoff of its own). smtplib is blocking, so `send()` runs
it off the event loop via asyncio.to_thread rather than pulling in an async
SMTP dependency (stdlib only, per the "don't introduce unnecessary libraries"
constraint).
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("soar.ai-orchestrator")


class EmailError(Exception):
    """Base for all typed email client failures."""


class EmailAuthenticationError(EmailError):
    """SMTP authentication rejected the configured username/password."""


class EmailTimeoutError(EmailError):
    """Connecting to or talking to the SMTP server timed out."""


class EmailUnavailableError(EmailError):
    """Any other SMTP/network failure."""


class EmailClient:
    def __init__(
        self,
        host: str | None,
        port: int,
        username: str | None,
        password: str | None,
        sender: str | None,
        timeout: float = 10.0,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender = sender
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.sender)

    async def send(self, to: list[str], subject: str, body: str) -> None:
        if not self.is_configured:
            raise EmailError("EmailClient is not configured (missing smtp_host/email_from)")
        if not to:
            raise EmailError("EmailClient has no recipients")
        await asyncio.to_thread(self._send_sync, to, subject, body)

    def _send_sync(self, to: list[str], subject: str, body: str) -> None:
        message = MIMEText(body, "plain", "utf-8")
        message["Subject"] = subject
        message["From"] = self.sender
        message["To"] = ", ".join(to)

        try:
            if self.port == 465:
                server = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            try:
                if self.port == 587:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.sender, to, message.as_string())
            finally:
                server.quit()
        except smtplib.SMTPAuthenticationError as exc:
            logger.warning("email.request.failure", extra={"reason": "authentication"})
            raise EmailAuthenticationError("SMTP authentication failed") from exc
        except TimeoutError as exc:
            logger.warning("email.request.failure", extra={"reason": "timeout"})
            raise EmailTimeoutError("SMTP request timed out") from exc
        except (smtplib.SMTPException, OSError) as exc:
            # Deliberately log only the exception class — never message details,
            # which could echo back SMTP conversation content.
            logger.warning("email.request.failure", extra={"reason": exc.__class__.__name__})
            raise EmailUnavailableError(f"SMTP request failed: {exc.__class__.__name__}") from exc
