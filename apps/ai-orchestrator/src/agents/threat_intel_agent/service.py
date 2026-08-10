"""
ThreatIntelligenceService — orchestrates provider queries for a single IOC,
and controlled-concurrency analysis across every IOC in an alert.

This is the composition point: it owns the provider list, the cache, and the
concurrency limiter, and is what agent.py (the LangGraph node) calls into.
Kept separate from agent.py so it can be unit/integration-tested without any
LangGraph/AgentState machinery.
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
from .types import (
    ExtractedIoc,
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


class ThreatIntelligenceService:
    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache: ThreatIntelCache | None = None,
        max_concurrency: int | None = None,
    ):
        self.providers = providers if providers is not None else _default_providers()
        self.cache = cache if cache is not None else ThreatIntelCache(
            ttl_seconds=settings.threat_intel_cache_ttl, enabled=settings.threat_intel_cache_enabled
        )
        self.max_concurrency = max_concurrency or settings.threat_intel_max_concurrency

    async def _query_provider(
        self, provider: ThreatIntelProvider, indicator: str, ioc_type
    ) -> ThreatIntelProviderResult:
        if not provider.is_configured:
            return ThreatIntelProviderResult(name=provider.name, status=ProviderStatus.DISABLED)
        if not provider.supports(ioc_type):
            return ThreatIntelProviderResult(name=provider.name, status=ProviderStatus.NOT_SUPPORTED)

        cached = self.cache.get(provider.name, ioc_type, indicator)
        if cached is not None:
            logger.info(
                "threat_intel.provider.cache_hit",
                extra={"provider": provider.name, "iocType": ioc_type.value},
            )
            return cached

        logger.info(
            "threat_intel.provider.request",
            extra={"provider": provider.name, "iocType": ioc_type.value},
        )
        try:
            result = await provider.analyze(indicator, ioc_type)
        except Exception as exc:  # provider.analyze() is documented to not raise for expected
            # failures — this catches genuinely unexpected bugs so one broken
            # provider can never take down the whole agent.
            logger.error(
                "threat_intel.provider.failure",
                extra={"provider": provider.name, "reason": f"unexpected:{exc.__class__.__name__}"},
            )
            return ThreatIntelProviderResult(
                name=provider.name, status=ProviderStatus.FAILED, error="Unexpected provider error"
            )

        if result.status == ProviderStatus.SUCCESS:
            logger.info(
                "threat_intel.provider.success",
                extra={
                    "provider": provider.name,
                    "iocType": ioc_type.value,
                    "malicious": result.malicious,
                    "durationMs": result.duration_ms,
                },
            )
            self.cache.set(provider.name, ioc_type, indicator, result)
        else:
            logger.info(
                "threat_intel.provider.failure",
                extra={
                    "provider": provider.name,
                    "iocType": ioc_type.value,
                    "status": result.status.value,
                    "durationMs": result.duration_ms,
                },
            )

        return result

    async def analyze_ioc(self, indicator: str, ioc_type) -> ThreatIntelData:
        """Validates then queries every configured provider for a single IOC."""
        start = time.monotonic()
        is_valid, reason = validate_ioc(indicator, ioc_type)
        if not is_valid:
            return ThreatIntelData(
                indicator=indicator,
                type=ioc_type,
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
                valid=False,
                invalid_reason=reason,
            )

        results = await asyncio.gather(
            *(self._query_provider(provider, indicator, ioc_type) for provider in self.providers)
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        return build_threat_intel_data(indicator, ioc_type, list(results), _now_iso(), duration_ms)

    async def analyze_iocs(self, iocs: list[ExtractedIoc]) -> list[ThreatIntelData]:
        """Analyzes multiple IOCs under a bounded concurrency limit — enough
        parallelism to avoid sequential-wait latency, but bounded so provider
        rate limits (e.g. VirusTotal's 4 req/min free tier) aren't hammered by
        an alert containing dozens of indicators."""
        semaphore = asyncio.Semaphore(max(1, self.max_concurrency))

        async def _bounded(ioc: ExtractedIoc) -> ThreatIntelData:
            async with semaphore:
                return await self.analyze_ioc(ioc.value, ioc.type)

        return list(await asyncio.gather(*(_bounded(ioc) for ioc in iocs)))

    async def analyze_alert(self, raw_alert: dict | None, alert_text: str = "") -> ThreatIntelReport:
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

        indicators = await self.analyze_iocs(deduped)
        duration_ms = int((time.monotonic() - start) * 1000)
        return build_report(indicators, _now_iso(), duration_ms)


def _default_providers() -> list[ThreatIntelProvider]:
    return [VirusTotalProvider(), AbuseIPDBProvider(), MispProvider(), OtxProvider()]
