"""
AlienVault OTX provider — pulse-count reputation lookups for IPs and domains.
OTX has no hash-lookup endpoint used here.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from src.config.settings import settings
from ..types import Evidence, EvidenceType, IocType, ProviderStatus, ThreatIntelProviderResult
from ._http_base import execute_request
from .provider_interface import ThreatIntelProvider

_SUPPORTED = {IocType.IPV4, IocType.IPV6, IocType.DOMAIN}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class OtxProvider(ThreatIntelProvider):
    name = "otx"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, timeout: float | None = None):
        self.api_key = api_key if api_key is not None else settings.otx_api_key
        self.base_url = (base_url or settings.otx_base_url).rstrip("/")
        self.timeout = timeout if timeout is not None else settings.otx_timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in _SUPPORTED

    def _path_for(self, indicator: str, ioc_type: IocType) -> str:
        if ioc_type in (IocType.IPV4, IocType.IPV6):
            return f"IPv4/{indicator}/general"
        return f"domain/{indicator}/general"

    async def analyze(self, indicator: str, ioc_type: IocType) -> ThreatIntelProviderResult:
        if not self.is_configured:
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_CONFIGURED)
        if not self.supports(ioc_type):
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_SUPPORTED)

        path = self._path_for(indicator, ioc_type)

        async def make_request() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.get(f"{self.base_url}/{path}", headers={"X-OTX-API-KEY": self.api_key})

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
            data = response.json()
            pulse_count = int(data.get("pulse_info", {}).get("count", 0))
            pulses = data.get("pulse_info", {}).get("pulses", []) or []
        except (KeyError, TypeError, ValueError):
            return ThreatIntelProviderResult(
                name=self.name, status=ProviderStatus.FAILED, error="Malformed response", duration_ms=duration_ms, retry_count=retry_count
            )

        fetched_at = _now_iso()

        if pulse_count == 0:
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.NO_MATCH,
                raw_summary={"pulseCount": 0},
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        malicious = pulse_count >= 3
        suspicious = not malicious

        evidence = [
            Evidence(
                provider=self.name,
                ioc=indicator,
                evidence_type=EvidenceType.OTX_PULSE,
                provider_object_id=pulse.get("id"),
                reference=f"https://otx.alienvault.com/pulse/{pulse['id']}" if pulse.get("id") else None,
                fetched_at=fetched_at,
                summary=f"Referenced in OTX pulse '{pulse.get('name', 'unknown')}'.",
            )
            for pulse in pulses[:5]
        ]

        return ThreatIntelProviderResult(
            name=self.name,
            status=ProviderStatus.SUCCESS,
            malicious=malicious,
            suspicious=suspicious,
            confidence=min(1.0, 0.3 + 0.1 * pulse_count),
            categories=["threat-pulse"],
            detections=pulse_count,
            total_checks=pulse_count,
            raw_summary={"pulseCount": pulse_count},
            duration_ms=duration_ms,
            retry_count=retry_count,
            evidence=evidence,
        )
