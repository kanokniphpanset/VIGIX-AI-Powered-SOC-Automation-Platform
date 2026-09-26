"""
VirusTotal v3 provider.

Supports IP/domain/URL/hash lookups. Normalizes VirusTotal's
`last_analysis_stats` block into the common ThreatIntelProviderResult shape —
nothing downstream (scoring, aggregation) depends on VirusTotal's exact
response structure, only on this normalized result.

Never logs the API key or full raw response bodies; only status codes and
derived counts.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone

import httpx

from src.config.settings import settings
from ..types import Evidence, EvidenceType, IocType, ProviderStatus, ThreatIntelProviderResult
from ._http_base import execute_request
from .provider_interface import ThreatIntelProvider

logger = logging.getLogger("soar.ai-orchestrator.threat-intel")

_SUPPORTED = {IocType.IPV4, IocType.IPV6, IocType.DOMAIN, IocType.URL, IocType.MD5, IocType.SHA1, IocType.SHA256}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, timeout: float | None = None):
        self.api_key = api_key if api_key is not None else settings.virustotal_api_key
        self.base_url = (base_url or settings.virustotal_base_url).rstrip("/")
        self.timeout = timeout if timeout is not None else settings.virustotal_timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def supports(self, ioc_type: IocType) -> bool:
        return ioc_type in _SUPPORTED

    def _path_for(self, indicator: str, ioc_type: IocType) -> str:
        if ioc_type in (IocType.IPV4, IocType.IPV6):
            return f"ip_addresses/{indicator}"
        if ioc_type == IocType.DOMAIN:
            return f"domains/{indicator}"
        if ioc_type == IocType.URL:
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            return f"urls/{url_id}"
        # MD5 / SHA1 / SHA256 all use the same /files/{hash} endpoint.
        return f"files/{indicator}"

    async def analyze(self, indicator: str, ioc_type: IocType) -> ThreatIntelProviderResult:
        if not self.is_configured:
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_CONFIGURED)
        if not self.supports(ioc_type):
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_SUPPORTED)

        path = self._path_for(indicator, ioc_type)

        async def make_request() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.get(
                    f"{self.base_url}/{path}",
                    headers={"x-apikey": self.api_key, "Accept": "application/json"},
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

        if response.status_code == 404:
            # VirusTotal has no record of this indicator at all — a genuine
            # NO_MATCH, never coerced into SUCCESS+malicious=False (spec
            # section 5: "no match" is its own status, not BENIGN).
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.NO_MATCH,
                raw_summary={"found": False},
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        if response.status_code >= 400:
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                error=f"HTTP {response.status_code}",
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        try:
            body = response.json()
            data_id = body["data"].get("id")
            stats = body["data"]["attributes"]["last_analysis_stats"]
            categories = body["data"]["attributes"].get("categories", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected"))
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning(
                "threat_intel.provider.failure",
                extra={"provider": self.name, "reason": f"malformed_response:{exc.__class__.__name__}"},
            )
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.FAILED,
                error="Malformed response",
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        if total == 0:
            # A record exists but no engine has an opinion — treat as
            # NO_MATCH (nothing to report), not a malicious/clean verdict.
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.NO_MATCH,
                raw_summary={"found": True, "malicious": 0, "suspicious": 0, "total": 0},
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        confidence = min(1.0, total / 70)  # VT typically runs ~70 engines
        fetched_at = _now_iso()
        return ThreatIntelProviderResult(
            name=self.name,
            status=ProviderStatus.SUCCESS,
            malicious=malicious > 0,
            suspicious=suspicious > 0 and malicious == 0,
            confidence=round(confidence, 2),
            reputation=round((malicious / total) * 100, 1) if total else None,
            categories=sorted(set(categories.values())) if isinstance(categories, dict) else [],
            detections=malicious,
            total_checks=total,
            raw_summary={"malicious": malicious, "suspicious": suspicious, "total": total, "found": True},
            duration_ms=duration_ms,
            retry_count=retry_count,
            evidence=[
                Evidence(
                    provider=self.name,
                    ioc=indicator,
                    evidence_type=EvidenceType.DETECTION_STATS,
                    provider_object_id=data_id,
                    reference=f"https://www.virustotal.com/gui/{'file' if ioc_type.value in ('MD5', 'SHA1', 'SHA256') else ('url' if ioc_type == IocType.URL else ('domain' if ioc_type == IocType.DOMAIN else 'ip-address'))}/{data_id or indicator}",
                    fetched_at=fetched_at,
                    summary=f"{malicious}/{total} engines flagged this indicator as malicious.",
                )
            ],
        )
