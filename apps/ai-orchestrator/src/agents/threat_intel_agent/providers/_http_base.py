"""
Shared HTTP execution helper for threat-intel providers.

Centralizes: timing, retry/backoff (transient errors only), and mapping raw
httpx outcomes to ProviderStatus. Providers call `execute_request(...)` and
get back either a successful httpx.Response or a ProviderCallFailure they can
turn into a ThreatIntelProviderResult — this keeps retry/backoff/timeout
policy in one place instead of duplicated per-client.

Retry policy (spec section 6):
  RETRY (transient):    408, 429, 500, 502, 503, 504, network timeout,
                         connection failure — via tenacity, exponential
                         backoff, bounded by settings.threat_intel_retry_count.
  NEVER RETRY (permanent): 401, 403, 404, other 4xx, unsupported IOC type
                         (the last is rejected by supports() before any
                         request is even attempted).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from src.config.settings import settings
from ..types import ProviderStatus

logger = logging.getLogger("soar.ai-orchestrator.threat-intel")

# 500 is included alongside the more commonly-cited 502/503/504 — spec
# section 6 explicitly lists it as retryable.
_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class _RetryableHTTPStatusError(Exception):
    """Wraps an httpx.HTTPStatusError whose status code is transient, so
    tenacity's predicate can distinguish it from a permanent 4xx without
    re-inspecting the response on every retry attempt."""

    def __init__(self, response: httpx.Response):
        self.response = response
        super().__init__(f"HTTP {response.status_code}")


@dataclass
class ProviderCallFailure:
    status: ProviderStatus
    message: str
    status_code: int | None = None


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, _RetryableHTTPStatusError):
        return True
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.TransportError):
        return True
    return False


def _retrying():
    return retry(
        reraise=True,
        stop=stop_after_attempt(max(1, settings.threat_intel_retry_count + 1)),
        wait=wait_exponential(multiplier=settings.threat_intel_retry_backoff_seconds, max=10),
        retry=retry_if_exception(_is_retryable),
    )


async def execute_request(
    provider_name: str,
    make_request,
) -> tuple[httpx.Response | None, ProviderCallFailure | None, int, int]:
    """
    Runs `make_request` (a zero-arg async callable performing exactly one
    httpx call) under the shared retry policy. Returns
    (response, failure, duration_ms, retry_count) — exactly one of
    response/failure is set. Never raises: every httpx/network exception is
    caught and classified. Never logs the request/response body or headers
    — API keys can appear in either — only status codes and exception class
    names.
    """
    start = time.monotonic()
    attempts = 0

    @_retrying()
    async def _attempt() -> httpx.Response:
        nonlocal attempts
        attempts += 1
        response = await make_request()
        if response.status_code in _RETRYABLE_STATUS_CODES:
            raise _RetryableHTTPStatusError(response)
        return response

    try:
        response = await _attempt()
        duration_ms = int((time.monotonic() - start) * 1000)
        return response, None, duration_ms, attempts - 1
    except _RetryableHTTPStatusError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        status_code = exc.response.status_code
        provider_status = ProviderStatus.RATE_LIMITED if status_code == 429 else ProviderStatus.FAILED
        logger.warning(
            "threat_intel.provider.failure",
            extra={"provider": provider_name, "status_code": status_code, "durationMs": duration_ms, "retryCount": attempts - 1},
        )
        return None, ProviderCallFailure(provider_status, f"HTTP {status_code}", status_code), duration_ms, attempts - 1
    except httpx.TimeoutException:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.warning(
            "threat_intel.provider.failure",
            extra={"provider": provider_name, "reason": "timeout", "durationMs": duration_ms, "retryCount": attempts - 1},
        )
        return None, ProviderCallFailure(ProviderStatus.TIMEOUT, "Request timed out"), duration_ms, attempts - 1
    except httpx.HTTPError as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.warning(
            "threat_intel.provider.failure",
            extra={"provider": provider_name, "reason": exc.__class__.__name__, "durationMs": duration_ms, "retryCount": attempts - 1},
        )
        return None, ProviderCallFailure(ProviderStatus.FAILED, exc.__class__.__name__), duration_ms, attempts - 1
