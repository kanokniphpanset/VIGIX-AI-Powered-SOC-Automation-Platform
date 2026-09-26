"""
Short-term TTL cache for per-provider IOC lookups.

Keyed on (provider name, IOC type, normalized value) — the exact tuple the
spec calls for. In-process (dict-based) by design: Redis is provisioned in
infra/docker/docker-compose.yml but nothing in this service connects to it
today (see docs/architecture note in threat-intelligence-agent.md), and a
single-process FastAPI deployment doesn't need a distributed cache to get
real benefit — cache hits still save an external HTTP round-trip and count
against the same free-tier rate limit either way. Swapping the backing store
for Redis later only requires reimplementing this class's two methods.

Failures are never cached (a transient timeout must not be remembered as "no
data" for the next hour) — only ProviderStatus.SUCCESS results are stored.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock

from .types import IocType, ThreatIntelProviderResult


@dataclass
class _CacheEntry:
    result: ThreatIntelProviderResult
    expires_at: float


class ThreatIntelCache:
    def __init__(self, ttl_seconds: int, enabled: bool = True):
        self.ttl_seconds = ttl_seconds
        self.enabled = enabled
        self._store: dict[str, _CacheEntry] = {}
        self._lock = Lock()

    @staticmethod
    def _key(provider: str, ioc_type: IocType, value: str) -> str:
        return f"{provider}:{ioc_type.value}:{value}"

    def get(self, provider: str, ioc_type: IocType, value: str) -> ThreatIntelProviderResult | None:
        if not self.enabled:
            return None
        key = self._key(provider, ioc_type, value)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.expires_at < time.monotonic():
                del self._store[key]
                return None
            cached = entry.result
            cached.from_cache = True
            return cached

    def set(self, provider: str, ioc_type: IocType, value: str, result: ThreatIntelProviderResult) -> None:
        if not self.enabled:
            return
        # Never let a failed/degraded lookup masquerade as fresh intel later.
        from .types import ProviderStatus

        if result.status != ProviderStatus.SUCCESS:
            return
        key = self._key(provider, ioc_type, value)
        with self._lock:
            self._store[key] = _CacheEntry(result=result, expires_at=time.monotonic() + self.ttl_seconds)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
