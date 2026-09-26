"""
ThreatIntelligenceService — orchestrates provider queries for a single IOC,
and controlled-concurrency analysis across every IOC in an alert.

This is the composition point: it owns the provider list, the Redis cache,
the rate limiters, and the concurrency limiter, and is what agent.py (the
LangGraph node) calls into. Kept separate from agent.py so it can be
unit/integration-tested without any LangGraph/AgentState machinery.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from src.config.settings import settings
from .aggregator import build_report, build_threat_intel_data
from .cache import ThreatIntelCache
from .ioc_extractor import extract_from_alert
from .ioc_normalizer import normalize_and_deduplicate
from .ioc_validator import validate_ioc
from .providers.abuseipdb_provider import AbuseIPDBProvider
from .providers.misp_provider import MispProvider
from .providers.otx_provider import OtxProvider
from .providers.provider_interface import ThreatIntelProvider
from .providers.virustotal_provider import VirusTotalProvider
from .rate_limiter import RateLimiterRegistry
from .types import (
    ExtractedIoc,
    PipelineStatus,
    ProviderStatus,
    RiskLevel,
    ThreatIntelData,
    ThreatIntelProviderResult,
    ThreatIntelReport,
    Verdict,
)

logger = logging.getLogger("soar.ai-orchestrator.threat-intel")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_PROVIDER_FACTORIES = {"virustotal": VirusTotalProvider, "otx": OtxProvider, "misp": MispProvider, "abuseipdb": AbuseIPDBProvider}


def enabled_provider_names(setting: str | None = None) -> list[str]:
    """THREAT_INTEL_PROVIDERS in its declared order; unknown names are ignored (logged), duplicates dropped."""
    raw = settings.threat_intel_providers if setting is None else setting
    names: list[str] = []
    for name in (part.strip().lower() for part in raw.split(",")):
        if not name or name in names:
            continue
        if name not in _PROVIDER_FACTORIES:
            logger.warning("threat_intel.provider.unknown", extra={"provider": name})
            continue
        names.append(name)
    return names


def _default_providers() -> list[ThreatIntelProvider]:
    return [_PROVIDER_FACTORIES[name]() for name in enabled_provider_names()]


def _default_rate_limiters() -> RateLimiterRegistry:
    return RateLimiterRegistry(
        {
            "virustotal": settings.virustotal_rate_limit_per_minute,
            "otx": settings.otx_rate_limit_per_minute,
            "misp": settings.misp_rate_limit_per_minute,
            "abuseipdb": settings.abuseipdb_rate_limit_per_minute,
        }
    )


class ThreatIntelligenceService:
    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache: ThreatIntelCache | None = None,
        rate_limiters: RateLimiterRegistry | None = None,
        max_concurrency: int | None = None,
    ):
        self.providers = providers if providers is not None else _default_providers()
        self.cache = cache if cache is not None else ThreatIntelCache()
        self.rate_limiters = rate_limiters if rate_limiters is not None else _default_rate_limiters()
        self.max_concurrency = max_concurrency or settings.threat_intel_max_concurrency

    async def _query_provider(
        self, provider: ThreatIntelProvider, indicator: str, ioc_type, execution_id: str | None = None
    ) -> ThreatIntelProviderResult:
        # Observability (spec section 14) — every log line below carries
        # executionId/provider/iocType/status/durationMs/retryCount so a
        # single run's timeline is reconstructable; never the indicator
        # value itself in the cache/request lines (avoids logging what
        # could be sensitive lookup targets), and never any API
        # key/Authorization header (those never reach this layer at all —
        # see providers/_http_base.py's own logging).
        if not provider.is_configured:
            return ThreatIntelProviderResult(name=provider.name, status=ProviderStatus.NOT_CONFIGURED)
        if not provider.supports(ioc_type):
            return ThreatIntelProviderResult(name=provider.name, status=ProviderStatus.NOT_SUPPORTED)

        started_at = _now_iso()
        cached = await self.cache.get(provider.name, ioc_type, indicator)
        if cached is not None:
            logger.info(
                "threat_intel.provider.cache_hit",
                extra={"executionId": execution_id, "provider": provider.name, "iocType": ioc_type.value, "startedAt": started_at},
            )
            return cached

        await self.rate_limiters.for_provider(provider.name).acquire()

        logger.info(
            "threat_intel.provider.request",
            extra={"executionId": execution_id, "provider": provider.name, "iocType": ioc_type.value, "startedAt": started_at},
        )
        try:
            result = await provider.analyze(indicator, ioc_type)
        except Exception as exc:  # provider.analyze() is documented to not raise for expected
            # failures — this catches genuinely unexpected bugs so one broken
            # provider can never take down the whole agent.
            completed_at = _now_iso()
            logger.error(
                "threat_intel.provider.failure",
                extra={
                    "executionId": execution_id,
                    "provider": provider.name,
                    "startedAt": started_at,
                    "completedAt": completed_at,
                    "errorCode": f"unexpected:{exc.__class__.__name__}",
                },
            )
            return ThreatIntelProviderResult(name=provider.name, status=ProviderStatus.FAILED, error="Unexpected provider error")

        completed_at = _now_iso()
        result.source = "LIVE"
        if result.status in (ProviderStatus.SUCCESS, ProviderStatus.NO_MATCH):
            logger.info(
                "threat_intel.provider.success",
                extra={
                    "executionId": execution_id,
                    "provider": provider.name,
                    "iocType": ioc_type.value,
                    "status": result.status.value,
                    "malicious": result.malicious,
                    "startedAt": started_at,
                    "completedAt": completed_at,
                    "durationMs": result.duration_ms,
                    "retryCount": result.retry_count,
                },
            )
            await self.cache.set(provider.name, ioc_type, indicator, result)
        else:
            logger.info(
                "threat_intel.provider.failure",
                extra={
                    "executionId": execution_id,
                    "provider": provider.name,
                    "iocType": ioc_type.value,
                    "status": result.status.value,
                    "startedAt": started_at,
                    "completedAt": completed_at,
                    "durationMs": result.duration_ms,
                    "retryCount": result.retry_count,
                    "errorCode": result.error,
                },
            )

        return result

    async def analyze_ioc(self, indicator: str, ioc_type, execution_id: str | None = None) -> ThreatIntelData:
        """Validates then queries every configured provider for a single IOC."""
        start = time.monotonic()
        is_valid, reason = validate_ioc(indicator, ioc_type)
        if not is_valid:
            return ThreatIntelData(
                indicator=indicator,
                type=ioc_type,
                status=PipelineStatus.FAILED,
                verdict=Verdict.UNKNOWN,
                risk_level=RiskLevel.UNKNOWN,
                confidence=0.0,
                threat_score=0.0,
                malicious=False,
                suspicious=False,
                providers=[],
                explanation=[f"Indicator not queried: {reason}"],
                analyzed_at=_now_iso(),
                duration_ms=int((time.monotonic() - start) * 1000),
                execution_id=execution_id,
                valid=False,
                invalid_reason=reason,
            )

        results = await asyncio.gather(
            *(self._query_provider(provider, indicator, ioc_type, execution_id) for provider in self.providers)
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return build_threat_intel_data(indicator, ioc_type, list(results), _now_iso(), duration_ms, execution_id)

    async def analyze_iocs(self, iocs: list[ExtractedIoc], execution_id: str | None = None) -> list[ThreatIntelData]:
        """Analyzes multiple IOCs under a bounded concurrency limit — enough
        parallelism to avoid sequential-wait latency, but bounded so
        aggregate provider rate limits aren't hammered by an alert
        containing dozens of indicators (on top of the per-provider
        RateLimiter, which caps outbound request rate regardless)."""
        semaphore = asyncio.Semaphore(max(1, self.max_concurrency))

        async def _bounded(ioc: ExtractedIoc) -> ThreatIntelData:
            async with semaphore:
                return await self.analyze_ioc(ioc.value, ioc.type, execution_id)

        return list(await asyncio.gather(*(_bounded(ioc) for ioc in iocs)))

    async def analyze_alert(
        self, raw_alert: dict | None, alert_text: str = "", execution_id: str | None = None
    ) -> ThreatIntelReport:
        start = time.monotonic()
        extracted = extract_from_alert(raw_alert, alert_text)
        deduped = normalize_and_deduplicate(extracted)

        if len(deduped) > settings.threat_intel_max_iocs_per_alert:
            logger.info(
                "threat_intel.analysis.ioc_cap_applied",
                extra={"extracted": len(deduped), "cap": settings.threat_intel_max_iocs_per_alert},
            )
            deduped = deduped[: settings.threat_intel_max_iocs_per_alert]

        logger.info("threat_intel.ioc.extracted", extra={"count": len(deduped)})

        indicators = await self.analyze_iocs(deduped, execution_id)
        duration_ms = int((time.monotonic() - start) * 1000)
        return build_report(indicators, _now_iso(), duration_ms, execution_id)
