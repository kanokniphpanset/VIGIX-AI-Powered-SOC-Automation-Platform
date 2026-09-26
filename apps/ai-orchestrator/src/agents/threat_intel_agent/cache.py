"""
Redis-backed TTL cache for per-provider IOC lookups (spec section 8).

Key format: threatintel:{provider}:{ioc_type}:{normalized_ioc} — exactly as
specified. Each record stores provider, ioc, result, fetchedAt, expiresAt;
Redis's own key TTL (`ex=`) handles expiry, so a lookup past expiry is
simply a cache miss — "expired data must be refreshed" falls out of that for
free rather than needing separate expiry bookkeeping.

Failures are never cached (a transient timeout/rate-limit must not be
remembered as "no data" for the next 24h) — only SUCCESS and NO_MATCH
results are stored, since both represent a provider that was actually,
successfully queried.

Redis being unreachable degrades to "no cache" (every lookup becomes a live
call) rather than failing the analysis — a cache is an optimization, not a
dependency the agent should be unable to run without.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import redis.asyncio as redis_asyncio

from src.config.settings import settings
from .types import Evidence, EvidenceType, IocType, ProviderStatus, ThreatIntelProviderResult

logger = logging.getLogger("soar.ai-orchestrator.threat-intel")

_CACHEABLE_STATUSES = {ProviderStatus.SUCCESS, ProviderStatus.NO_MATCH}


def _serialize_evidence(e: Evidence) -> dict:
    return {
        "provider": e.provider,
        "ioc": e.ioc,
        "evidenceType": e.evidence_type.value,
        "providerObjectId": e.provider_object_id,
        "reference": e.reference,
        "observedAt": e.observed_at,
        "fetchedAt": e.fetched_at,
        "summary": e.summary,
    }


def _deserialize_evidence(d: dict) -> Evidence:
    return Evidence(
        provider=d["provider"],
        ioc=d["ioc"],
        evidence_type=EvidenceType(d["evidenceType"]),
        provider_object_id=d.get("providerObjectId"),
        reference=d.get("reference"),
        observed_at=d.get("observedAt"),
        fetched_at=d.get("fetchedAt", ""),
        summary=d.get("summary", ""),
    )


def _serialize_result(result: ThreatIntelProviderResult) -> dict:
    return {
        "name": result.name,
        "status": result.status.value,
        "malicious": result.malicious,
        "suspicious": result.suspicious,
        "confidence": result.confidence,
        "reputation": result.reputation,
        "categories": result.categories,
        "malwareFamily": result.malware_family,
        "threatActors": result.threat_actors,
        "campaigns": result.campaigns,
        "detections": result.detections,
        "totalChecks": result.total_checks,
        "rawSummary": result.raw_summary,
        "evidence": [_serialize_evidence(e) for e in result.evidence],
        "error": result.error,
    }


def _deserialize_result(d: dict) -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name=d["name"],
        status=ProviderStatus(d["status"]),
        source="CACHE",
        malicious=d.get("malicious", False),
        suspicious=d.get("suspicious", False),
        confidence=d.get("confidence", 0.0),
        reputation=d.get("reputation"),
        categories=d.get("categories", []),
        malware_family=d.get("malwareFamily"),
        threat_actors=d.get("threatActors", []),
        campaigns=d.get("campaigns", []),
        detections=d.get("detections", 0),
        total_checks=d.get("totalChecks", 0),
        raw_summary=d.get("rawSummary", {}),
        evidence=[_deserialize_evidence(e) for e in d.get("evidence", [])],
        error=d.get("error"),
        duration_ms=0,
        retry_count=0,
    )


class ThreatIntelCache:
    def __init__(
        self,
        redis_client: "redis_asyncio.Redis | None" = None,
        ttl_seconds: int | None = None,
        enabled: bool | None = None,
    ):
        self.ttl_seconds = ttl_seconds if ttl_seconds is not None else settings.threat_intel_cache_ttl
        self.enabled = enabled if enabled is not None else settings.threat_intel_cache_enabled
        self._client = redis_client
        self._owns_client = redis_client is None

    def _get_client(self) -> "redis_asyncio.Redis":
        if self._client is None:
            self._client = redis_asyncio.from_url(settings.redis_url, decode_responses=True)
        return self._client

    @staticmethod
    def key(provider: str, ioc_type: IocType, value: str) -> str:
        return f"threatintel:{provider}:{ioc_type.value}:{value}"

    async def get(self, provider: str, ioc_type: IocType, value: str) -> ThreatIntelProviderResult | None:
        if not self.enabled:
            return None
        client = self._get_client()
        key = self.key(provider, ioc_type, value)
        try:
            raw = await client.get(key)
        except Exception as exc:
            logger.warning("threat_intel.cache.unavailable", extra={"reason": exc.__class__.__name__})
            return None
        if raw is None:
            return None
        try:
            record = json.loads(raw)
            return _deserialize_result(record["result"])
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    async def set(self, provider: str, ioc_type: IocType, value: str, result: ThreatIntelProviderResult) -> None:
        if not self.enabled or result.status not in _CACHEABLE_STATUSES:
            return
        client = self._get_client()
        key = self.key(provider, ioc_type, value)
        now = datetime.now(timezone.utc)
        record = {
            "provider": provider,
            "ioc": value,
            "result": _serialize_result(result),
            "fetchedAt": now.isoformat(),
            "expiresAt": (now + timedelta(seconds=self.ttl_seconds)).isoformat(),
        }
        try:
            await client.set(key, json.dumps(record), ex=self.ttl_seconds)
        except Exception as exc:
            logger.warning("threat_intel.cache.write_failed", extra={"reason": exc.__class__.__name__})

    async def close(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.close()
