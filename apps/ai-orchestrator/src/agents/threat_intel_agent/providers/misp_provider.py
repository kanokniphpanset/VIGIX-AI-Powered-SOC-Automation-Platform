"""
MISP provider — queries a MISP instance's REST search for matching attributes.

Supports any IOC type (MISP attributes are typed by the community, not by a
fixed enum) — `supports()` always returns True when configured.

Defaults to `misp_verify_tls=True` and only skips TLS verification when an
operator explicitly sets MISP_VERIFY_TLS=false for a lab/self-signed instance.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx

from src.config.settings import settings
from ..types import Evidence, EvidenceType, IocType, ProviderStatus, ThreatIntelProviderResult
from ._http_base import execute_request
from .provider_interface import ThreatIntelProvider


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MispProvider(ThreatIntelProvider):
    name = "misp"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        verify_tls: bool | None = None,
    ):
        raw_base_url = base_url if base_url is not None else settings.misp_url
        self.base_url = raw_base_url.rstrip("/") if raw_base_url else None
        self.api_key = api_key if api_key is not None else settings.misp_api_key
        self.timeout = timeout if timeout is not None else settings.misp_timeout
        self.verify_tls = verify_tls if verify_tls is not None else settings.misp_verify_tls

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def supports(self, ioc_type: IocType) -> bool:
        return True

    async def analyze(self, indicator: str, ioc_type: IocType) -> ThreatIntelProviderResult:
        if not self.is_configured:
            return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.NOT_CONFIGURED)

        async def make_request() -> httpx.Response:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                return await client.post(
                    f"{self.base_url}/attributes/restSearch",
                    headers={"Authorization": self.api_key, "Accept": "application/json"},
                    json={"value": indicator},
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
            data = response.json()
            attributes = data.get("response", {}).get("Attribute", [])
        except (KeyError, TypeError, ValueError):
            return ThreatIntelProviderResult(
                name=self.name, status=ProviderStatus.FAILED, error="Malformed response", duration_ms=duration_ms, retry_count=retry_count
            )

        match_count = len(attributes)
        fetched_at = _now_iso()

        if match_count == 0:
            return ThreatIntelProviderResult(
                name=self.name,
                status=ProviderStatus.NO_MATCH,
                raw_summary={"matches": 0},
                duration_ms=duration_ms,
                retry_count=retry_count,
            )

        threat_levels = [
            int(attr["Event"]["threat_level_id"])
            for attr in attributes
            if isinstance(attr.get("Event"), dict) and attr["Event"].get("threat_level_id") is not None
        ]
        # MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined — lower is worse.
        highest_severity = min(threat_levels) if threat_levels else None
        categories = sorted({attr["category"] for attr in attributes if attr.get("category")})

        malicious = highest_severity is not None and highest_severity <= 2
        suspicious = not malicious

        evidence = [
            Evidence(
                provider=self.name,
                ioc=indicator,
                evidence_type=EvidenceType.MISP_ATTRIBUTE,
                provider_object_id=str(attr.get("id")) if attr.get("id") else None,
                reference=f"{self.base_url}/events/view/{attr['event_id']}" if attr.get("event_id") else None,
                observed_at=attr.get("timestamp"),
                fetched_at=fetched_at,
                summary=f"Matched MISP attribute of category '{attr.get('category', 'unknown')}' in event {attr.get('event_id', 'unknown')}.",
            )
            for attr in attributes[:5]  # cap evidence entries; raw_summary keeps the true count
        ]

        return ThreatIntelProviderResult(
            name=self.name,
            status=ProviderStatus.SUCCESS,
            malicious=malicious,
            suspicious=suspicious,
            confidence=min(1.0, 0.5 + 0.1 * match_count),
            categories=categories,
            detections=match_count,
            total_checks=match_count,
            raw_summary={"matches": match_count, "highestSeverity": highest_severity},
            duration_ms=duration_ms,
            retry_count=retry_count,
            evidence=evidence,
        )
