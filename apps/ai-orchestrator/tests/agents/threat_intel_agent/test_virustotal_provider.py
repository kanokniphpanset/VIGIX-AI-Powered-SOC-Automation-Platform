"""
Unit tests for VirusTotalProvider.

HTTP is mocked via httpx.MockTransport — no real API keys or network calls.
All assertions are on the *normalized* ThreatIntelProviderResult shape, not
on raw VirusTotal response structure.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.agents.threat_intel_agent.providers.virustotal_provider import VirusTotalProvider
from src.agents.threat_intel_agent.types import IocType, ProviderStatus


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vt_body(malicious=0, suspicious=0, harmless=60, undetected=5, categories=None):
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": stats,
                "categories": categories or {},
            }
        }
    }


def _mock_response(status_code: int, body: dict | None = None):
    content = json.dumps(body).encode() if body else b""
    return httpx.Response(status_code, content=content, headers={"content-type": "application/json"})


def _patch_client(response: httpx.Response):
    """Patch httpx.AsyncClient so make_request() returns the given response."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return patch("httpx.AsyncClient", return_value=mock_client)


# ── DISABLED when no key ──────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_disabled_when_no_api_key():
    provider = VirusTotalProvider(api_key="")
    result = await provider.analyze("1.2.3.4", IocType.IPV4)
    assert result.status == ProviderStatus.DISABLED


@pytest.mark.anyio
async def test_not_supported_for_email():
    provider = VirusTotalProvider(api_key="test-key")
    result = await provider.analyze("user@evil.com", IocType.EMAIL)
    assert result.status == ProviderStatus.NOT_SUPPORTED


# ── Successful malicious response ─────────────────────────────────────────────

@pytest.mark.anyio
async def test_malicious_response_parsed():
    body = _vt_body(malicious=45, harmless=20, undetected=5)
    with _patch_client(_mock_response(200, body)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is True
    assert result.suspicious is False
    assert result.detections == 45
    assert result.confidence > 0.0


@pytest.mark.anyio
async def test_categories_extracted():
    body = _vt_body(malicious=5, categories={"engine_a": "malware", "engine_b": "trojan"})
    with _patch_client(_mock_response(200, body)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert "malware" in result.categories or "trojan" in result.categories


@pytest.mark.anyio
async def test_suspicious_only_not_malicious():
    body = _vt_body(malicious=0, suspicious=3, harmless=60)
    with _patch_client(_mock_response(200, body)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is False
    assert result.suspicious is True


@pytest.mark.anyio
async def test_clean_response():
    body = _vt_body(malicious=0, suspicious=0, harmless=70)
    with _patch_client(_mock_response(200, body)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is False
    assert result.suspicious is False


# ── 404 treated as "not found" (SUCCESS, not FAILED) ─────────────────────────

@pytest.mark.anyio
async def test_404_returns_success_not_found():
    with _patch_client(_mock_response(404)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.SUCCESS
    assert result.malicious is False
    assert result.confidence == 0.3


# ── Auth errors ───────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_401_returns_failed():
    with _patch_client(_mock_response(401)):
        provider = VirusTotalProvider(api_key="bad-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED
    assert "401" in (result.error or "")


@pytest.mark.anyio
async def test_403_returns_failed():
    with _patch_client(_mock_response(403)):
        provider = VirusTotalProvider(api_key="bad-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED


# ── Server errors ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_500_returns_failed():
    with _patch_client(_mock_response(500)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED


# ── Malformed response ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_malformed_json_returns_failed():
    resp = httpx.Response(200, content=b"not-json", headers={"content-type": "application/json"})
    with _patch_client(resp):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED


@pytest.mark.anyio
async def test_missing_stats_key_returns_failed():
    body = {"data": {"attributes": {}}}  # no last_analysis_stats
    with _patch_client(_mock_response(200, body)):
        provider = VirusTotalProvider(api_key="fake-key", base_url="https://test.vt.com/api/v3")
        result = await provider.analyze("1.2.3.4", IocType.IPV4)

    assert result.status == ProviderStatus.FAILED


# ── URL path construction ─────────────────────────────────────────────────────

def test_url_path_uses_base64_url_id():
    provider = VirusTotalProvider(api_key="k")
    path = provider._path_for("http://evil.com/path", IocType.URL)
    assert path.startswith("urls/")
    # The base64 id must not contain '=' padding
    assert "=" not in path.split("/", 1)[1]


def test_hash_path_uses_files_endpoint():
    provider = VirusTotalProvider(api_key="k")
    path = provider._path_for("d41d8cd98f00b204e9800998ecf8427e", IocType.MD5)
    assert path.startswith("files/")
