"""Unit tests for AbuseIPDBProvider. HTTP mocked — no real API calls."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.agents.threat_intel_agent.providers.abuseipdb_provider import AbuseIPDBProvider
from src.agents.threat_intel_agent.types import IocType, ProviderStatus


def _abuse_body(abuse_score=0, total_reports=0, is_whitelisted=False):
    return {
        "data": {
            "abuseConfidenceScore": abuse_score,
            "totalReports": total_reports,
            "isWhitelisted": is_whitelisted,
        }
    }


def _mock_response(status_code: int, body: dict | None = None):
    content = json.dumps(body).encode() if body else b""
    return httpx.Response(status_code, content=content, headers={"content-type": "application/json"})


def _patch_client(response: httpx.Response):
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return patch("httpx.AsyncClient", return_value=mock_client)


# ── DISABLED / NOT_SUPPORTED ──────────────────────────────────────────────────

@pytest.mark.anyio
async def test_disabled_when_no_api_key():
    provider = AbuseIPDBProvider(api_key="")
    result = await provider.analyze("1.2.3.4", IocType.IPV4)
    assert result.status == ProviderStatus.DISABLED


@pytest.mark.anyio
async def test_not_supported_for_domain():
    provider = AbuseIPDBProvider(api_key="test-key")
    result = await provider.analyze("evil.com", IocType.DOMAIN)
    assert result.status == ProviderStatus.NOT_SUPPORTED


@pytest.mark.anyio
async def test_not_supported_for_url():
    provider = AbuseIPDBProvider(api_key="test-key")
    result = await provider.analyze("http://evil.com", IocType.URL)
    assert result.status == ProviderStatus.NOT_SUPPORTED


# ── Clean IP ──────────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_clean_ip_low_score():
    with _patch_client(_mock_response(200, _abuse_body(abuse_score=0, total_reports=0))):
        provider = AbuseIPDBProvider(api_key="fake-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("8.8.8.8", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is False
    assert result.suspicious is False


# ── Suspicious IP ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_suspicious_ip_mid_score():
    with _patch_client(_mock_response(200, _abuse_body(abuse_score=50, total_reports=10))):
        provider = AbuseIPDBProvider(api_key="fake-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.suspicious is True
    assert result.malicious is False
    assert result.confidence == 0.5


# ── Malicious IP ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_malicious_ip_high_score():
    with _patch_client(_mock_response(200, _abuse_body(abuse_score=95, total_reports=200))):
        provider = AbuseIPDBProvider(api_key="fake-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is True
    assert result.suspicious is False
    assert result.confidence == 0.95
    assert "abuse" in result.categories


# ── Whitelisted IP never malicious ───────────────────────────────────────────

@pytest.mark.anyio
async def test_whitelisted_not_malicious():
    with _patch_client(_mock_response(200, _abuse_body(abuse_score=90, total_reports=50, is_whitelisted=True))):
        provider = AbuseIPDBProvider(api_key="fake-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.malicious is False
    assert result.suspicious is False


# ── HTTP error codes ──────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_401_returns_failed():
    with _patch_client(_mock_response(401)):
        provider = AbuseIPDBProvider(api_key="bad-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED


@pytest.mark.anyio
async def test_500_returns_failed():
    with _patch_client(_mock_response(500)):
        provider = AbuseIPDBProvider(api_key="fake-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED


# ── Malformed response ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_malformed_response_returns_failed():
    resp = httpx.Response(200, content=b"{}", headers={"content-type": "application/json"})
    with _patch_client(resp):
        provider = AbuseIPDBProvider(api_key="fake-key", base_url="https://test.abuseipdb.com/api/v2")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    # missing "data" key should be handled gracefully
    assert result.status == ProviderStatus.FAILED
