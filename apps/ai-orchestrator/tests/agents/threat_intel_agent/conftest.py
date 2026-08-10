"""
Shared fixtures for Threat Intelligence Agent tests.

Uses anyio's built-in pytest plugin for async test support — no
pytest-asyncio needed. Mark async tests with @pytest.mark.anyio.
"""

import pytest

from src.agents.threat_intel_agent.types import (
    IocType,
    ProviderStatus,
    ThreatIntelProviderResult,
)


@pytest.fixture
def vt_malicious() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name="VirusTotal",
        status=ProviderStatus.SUCCESS,
        malicious=True,
        suspicious=False,
        confidence=0.9,
        detections=45,
        total_checks=70,
        categories=["malware", "trojan"],
    )


@pytest.fixture
def vt_clean() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name="VirusTotal",
        status=ProviderStatus.SUCCESS,
        malicious=False,
        suspicious=False,
        confidence=0.85,
        detections=0,
        total_checks=70,
    )


@pytest.fixture
def vt_suspicious() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name="VirusTotal",
        status=ProviderStatus.SUCCESS,
        malicious=False,
        suspicious=True,
        confidence=0.6,
        detections=3,
        total_checks=70,
    )


@pytest.fixture
def abuse_malicious() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name="AbuseIPDB",
        status=ProviderStatus.SUCCESS,
        malicious=True,
        suspicious=False,
        confidence=0.95,
        reputation=95.0,
    )


@pytest.fixture
def abuse_clean() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name="AbuseIPDB",
        status=ProviderStatus.SUCCESS,
        malicious=False,
        suspicious=False,
        confidence=0.9,
        reputation=1.0,
    )


@pytest.fixture
def disabled_provider() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(name="VirusTotal", status=ProviderStatus.DISABLED)


@pytest.fixture
def failed_provider() -> ThreatIntelProviderResult:
    return ThreatIntelProviderResult(
        name="AbuseIPDB", status=ProviderStatus.FAILED, error="connection timeout"
    )
