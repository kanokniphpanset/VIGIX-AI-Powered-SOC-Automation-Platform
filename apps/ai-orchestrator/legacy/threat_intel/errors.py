"""Structured domain errors for the Threat Intelligence Agent.

Raised only by providers/services that need to signal a specific failure mode
to their caller. The agent's top-level `run()` never lets one of these escape
the pipeline — every provider call is caught and downgraded to a
ThreatIntelProviderResult with the matching ProviderStatus instead. They exist
so that error *classification* (permanent vs transient, config vs runtime)
happens once, near the source, instead of via string-matching exception
messages further up the stack.
"""

from __future__ import annotations


class ThreatIntelError(Exception):
    """Base class for all threat-intel domain errors."""


class ThreatIntelConfigurationError(ThreatIntelError):
    """Provider is missing required configuration (e.g. no API key/URL)."""


class InvalidIOCError(ThreatIntelError):
    """IOC failed format validation before any provider was queried."""

    def __init__(self, indicator: str, reason: str):
        self.indicator = indicator
        self.reason = reason
        super().__init__(f"Invalid IOC '{indicator}': {reason}")


class ThreatIntelProviderError(ThreatIntelError):
    """A provider request failed for a reason other than timeout/rate-limit."""

    def __init__(self, provider: str, message: str, *, status_code: int | None = None):
        self.provider = provider
        self.status_code = status_code
        super().__init__(f"{provider} provider error: {message}")


class ThreatIntelTimeoutError(ThreatIntelProviderError):
    """A provider request exceeded its configured timeout."""


class ThreatIntelRateLimitError(ThreatIntelProviderError):
    """A provider rejected the request due to rate limiting (HTTP 429)."""
