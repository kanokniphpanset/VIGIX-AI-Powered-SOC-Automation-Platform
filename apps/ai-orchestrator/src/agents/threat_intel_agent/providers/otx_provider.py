"""
AlienVault OTX provider — pulse-count reputation lookups for IPs and domains.
OTX has no hash-lookup endpoint in the original client, preserved here.
"""

from __future__ import annotations

import httpx

from src.config.settings import settings
from ..types import IocType, ProviderStatus, ThreatIntelProviderResult
from ._http_base import execute_request
from .provider_interface import ThreatIntelProvider

_SUPPORTED = {IocType.IPV4, IocType.IPV6, IocType.DOMAIN}


class OtxProvider(ThreatIntelProvider):
    name = "OTX"

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
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.DISABLED)
        if not self.supports(ioc_type):
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_SUPPORTED)

        path = self._path_for(indicator, ioc_type)

        async def make_request() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.get(f"{self.base_url}/{path}", headers={"X-OTX-API-KEY": self.api_key})

        response, failure, duration_ms = await execute_request(self.name, make_request)

        if failure is not None:
            return ThreatIntelProviderResult(
                name=self.name, status=failure.status, error=failure.message, duration_ms=duration_ms
            )

        if response.status_code in (401, 403):
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                error=f"Authentication failed (HTTP {response.status_code})",
                duration_ms=duration_ms,
            )

        if response.status_code >= 400:
            return ThreatIntelProviderResult(
                name=self.name, status=ProviderStatus.FAILED, error=f"HTTP {response.status_code}", duration_ms=duration_ms
            )

        try:
            data = response.json()
            pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        except (KeyError, TypeError, ValueError):
            return ThreatIntelProviderResult(
                name=self.name, status=ProviderStatus.FAILED, error="Malformed response", duration_ms=duration_ms
            )

        malicious = pulse_count >= 3
        suspicious = 0 < pulse_count < 3

        return ThreatIntelProviderResult(
            name=self.name,
            status=ProviderStatus.SUCCESS,
            malicious=malicious,
            suspicious=suspicious,
            confidence=min(1.0, 0.3 + 0.1 * pulse_count) if pulse_count else 0.3,
            categories=["threat-pulse"] if pulse_count else [],
            detections=pulse_count,
            total_checks=pulse_count,
            raw_summary={"pulseCount": pulse_count},
            duration_ms=duration_ms,
        )
