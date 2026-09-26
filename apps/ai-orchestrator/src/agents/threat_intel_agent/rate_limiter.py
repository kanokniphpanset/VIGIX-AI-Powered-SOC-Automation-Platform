"""
Per-provider rate limiting (spec section 7) — a sliding-window limiter
shared across every concurrent IOC analysis in this process, so a burst of
IOCs from one alert (or several alerts in flight at once) can never exceed
a provider's configured requests-per-minute, no matter how much
`threat_intel_max_concurrency` allows in parallel.

Limits are entirely config-driven (Settings.*_rate_limit_per_minute) — no
"if free tier" branching in code. A limit of 0 means unlimited.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    def __init__(self, max_requests_per_minute: int):
        self.max_requests = max_requests_per_minute
        self.period_seconds = 60.0
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.max_requests <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self.period_seconds]
                if len(self._timestamps) < self.max_requests:
                    self._timestamps.append(now)
                    return
                wait_time = self.period_seconds - (now - self._timestamps[0])
                if wait_time > 0:
                    await asyncio.sleep(wait_time)


class RateLimiterRegistry:
    """One RateLimiter instance per provider name, created lazily and reused
    for the lifetime of the process — see service.py."""

    def __init__(self, limits_by_provider: dict[str, int]):
        self._limits = limits_by_provider
        self._limiters: dict[str, RateLimiter] = {}

    def for_provider(self, provider_name: str) -> RateLimiter:
        if provider_name not in self._limiters:
            self._limiters[provider_name] = RateLimiter(self._limits.get(provider_name, 0))
        return self._limiters[provider_name]
