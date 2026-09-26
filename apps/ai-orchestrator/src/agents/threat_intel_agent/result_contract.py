"""
Threat Intelligence Result Contract — spec section 10's exact shape:

{
  "ioc": "1.2.3.4",
  "iocType": "IPV4",
  "status": "PARTIAL_SUCCESS",
  "verdict": "UNKNOWN",
  "confidence": 0,
  "providers": [
    {"provider": "virustotal", "status": "SUCCESS", "source": "LIVE", "evidence": []},
    {"provider": "otx", "status": "NO_MATCH", "source": "LIVE", "evidence": []},
    {"provider": "misp", "status": "NOT_CONFIGURED", "evidence": []}
  ],
  "evidence": [],
  "queriedAt": "...",
  "executionId": "..."
}

`iocType` uses the specific IocType value (IPV4/IPV6/...) rather than a
generic "IP" — section 4 requires distinguishing IPv4 from IPv6, so
collapsing both to "IP" here would silently lose that.

A provider's `source` key (LIVE vs CACHE) is only present when a query
actually happened — NOT_CONFIGURED/NOT_SUPPORTED/INVALID_INDICATOR never
touched the network, so there's no "source" for them, matching the spec's
own example (the misp entry has no `source` key).
"""

from __future__ import annotations

from .types import ProviderStatus, ThreatIntelData, ThreatIntelProviderResult

_QUERIED_STATUSES = {
    ProviderStatus.SUCCESS,
    ProviderStatus.NO_MATCH,
    ProviderStatus.FAILED,
    ProviderStatus.TIMEOUT,
    ProviderStatus.RATE_LIMITED,
}


def _provider_entry(result: ThreatIntelProviderResult) -> dict:
    entry: dict = {
        "provider": result.name,
        "status": result.status.value,
        "evidence": [e.to_dict() for e in result.evidence],
    }
    if result.status in _QUERIED_STATUSES:
        entry["source"] = result.source
    return entry


def build_result_contract(data: ThreatIntelData) -> dict:
    return {
        "ioc": data.indicator,
        "iocType": data.type.value,
        "status": data.status.value,
        "verdict": data.verdict.value,
        "confidence": data.confidence,
        "providers": [_provider_entry(p) for p in data.providers],
        "evidence": [e.to_dict() for e in data.evidence],
        "queriedAt": data.analyzed_at,
        "executionId": data.execution_id,
    }
