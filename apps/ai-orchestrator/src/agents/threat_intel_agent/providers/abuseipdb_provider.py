"""
AbuseIPDB provider — IPv4/IPv6 abuse-confidence lookups only.

Not one of the three providers named in the Phase 2 spec (VirusTotal/OTX/
MISP), but real, working, and already wired to real settings — kept as a
bonus fourth provider rather than deleted. Everything downstream (scoring,
the result contract) treats it exactly like any other provider.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from src.config.settings import settings
from ..types import Evidence, EvidenceType, IocType, ProviderStatus, ThreatIntelProviderResult
from ._http_base import execute_request
from .provider_interface import ThreatIntelProvider

_SUPPORTED = {IocType.IPV4, IocType.IPV6}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, timeout: float | None = None):
        self.api_key = api_key if api_key is not None else settings.abuseipdb_api_key
        self.base_url = (base_url or settings.abuseipdb_base_url).rstrip("/")
        self.timeout = timeout if timeout is not None else settings.abuseipdb_timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in _SUPPORTED

    async def analyze(self, indicator: str, ioc_type: IocType) -> ThreatIntelProviderResult:
        if not self.is_configured:
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_CONFIGURED)
        if not self.supports(ioc_type):
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_SUPPORTED)

        async def make_request() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.get(
                    f"{self.base_url}/check",
                    headers={"Key": self.api_key, "Accept": "application/json"},
                    params={"ipAddress": indicator, "maxAgeInDays": 90},
                )

        response, failure, duration_ms, retry_count = await execute_request(self.name, make_request)

        if failure is not None:
            return ThreatIntelProviderResult(
                name=self.name, status=failure.status, error=failure.message, duration_ms=duration_ms, retry_count=retry_count
            )

        if response.status_code in (401, 403):
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                error=f"Authentication failed (HTTP {response.status_code})",
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        if response.status_code >= 400:
            return ThreatIntelProviderResult(
                name=self.name, status=ProviderStatus.FAILED, error=f"HTTP {response.status_code}", duration_ms=duration_ms, retry_count=retry_count
            )

        try:
            data = response.json()["data"]
            abuse_confidence = int(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            is_whitelisted = bool(data.get("isWhitelisted") or False)
        except (KeyError, TypeError, ValueError):
            return ThreatIntelProviderResult(
                name=self.name, status=ProviderStatus.FAILED, error="Malformed response", duration_ms=duration_ms, retry_count=retry_count
            )

        fetched_at = _now_iso()

        if total_reports == 0:
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.NO_MATCH,
                raw_summary={"abuseConfidenceScore": abuse_confidence, "totalReports": 0},
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        malicious = abuse_confidence >= 75 and not is_whitelisted
        suspicious = 25 <= abuse_confidence < 75 and not is_whitelisted

        return ThreatIntelProviderResult(
            name=self.name,
            status=ProviderStatus.SUCCESS,
            malicious=malicious,
            suspicious=suspicious,
            confidence=round(abuse_confidence / 100, 2),
            reputation=float(abuse_confidence),
            categories=["abuse"],
            detections=total_reports,
            total_checks=total_reports,
            raw_summary={
                "abuseConfidenceScore": abuse_confidence,
                "totalReports": total_reports,
                "isWhitelisted": is_whitelisted,
            },
            duration_ms=duration_ms,
            retry_count=retry_count,
            evidence=[
                Evidence(
                    provider=self.name,
                    ioc=indicator,
                    evidence_type=EvidenceType.REPUTATION_SCORE,
                    fetched_at=fetched_at,
                    summary=f"Abuse confidence score {abuse_confidence}/100 from {total_reports} report(s).",
                )
            ],
        )
