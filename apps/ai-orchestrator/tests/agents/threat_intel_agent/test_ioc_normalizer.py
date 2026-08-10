"""Tests for IOC normalization and deduplication."""

import pytest

from src.agents.threat_intel_agent.ioc_normalizer import normalize_and_deduplicate, normalize_ioc
from src.agents.threat_intel_agent.types import ExtractedIoc, IocType


def _ioc(value, ioc_type):
    return ExtractedIoc(value=value, type=ioc_type)


# ── IP normalization ──────────────────────────────────────────────────────────

def test_ipv4_unchanged():
    ioc = _ioc("192.168.1.1", IocType.IPV4)
    result = normalize_ioc(ioc)
    assert result.value == "192.168.1.1"


def test_ipv6_lowercased():
    ioc = _ioc("2001:DB8::1", IocType.IPV6)
    result = normalize_ioc(ioc)
    assert result.value == "2001:db8::1"


# ── Domain normalization ──────────────────────────────────────────────────────

def test_domain_lowercased():
    ioc = _ioc("EVIL.EXAMPLE.COM", IocType.DOMAIN)
    result = normalize_ioc(ioc)
    assert result.value == "evil.example.com"


def test_domain_trailing_dot_stripped():
    ioc = _ioc("evil.example.com.", IocType.DOMAIN)
    result = normalize_ioc(ioc)
    assert result.value == "evil.example.com"


def test_domain_already_clean_unchanged():
    ioc = _ioc("malware.io", IocType.DOMAIN)
    result = normalize_ioc(ioc)
    assert result.value == "malware.io"


# ── URL normalization ─────────────────────────────────────────────────────────

def test_url_scheme_lowercased():
    ioc = _ioc("HTTP://Example.COM/Path", IocType.URL)
    result = normalize_ioc(ioc)
    assert result.value.startswith("http://")


def test_url_host_lowercased():
    ioc = _ioc("https://EVIL.COM/payload", IocType.URL)
    result = normalize_ioc(ioc)
    assert "evil.com" in result.value


def test_url_default_port_80_removed():
    ioc = _ioc("http://example.com:80/page", IocType.URL)
    result = normalize_ioc(ioc)
    assert ":80" not in result.value


def test_url_default_port_443_removed():
    ioc = _ioc("https://example.com:443/page", IocType.URL)
    result = normalize_ioc(ioc)
    assert ":443" not in result.value


def test_url_non_default_port_preserved():
    ioc = _ioc("http://example.com:8080/api", IocType.URL)
    result = normalize_ioc(ioc)
    assert ":8080" in result.value


def test_url_query_string_preserved():
    ioc = _ioc("https://example.com/search?q=malware", IocType.URL)
    result = normalize_ioc(ioc)
    assert "q=malware" in result.value


# ── Hash normalization ────────────────────────────────────────────────────────

def test_md5_lowercased():
    ioc = _ioc("D41D8CD98F00B204E9800998ECF8427E", IocType.MD5)
    result = normalize_ioc(ioc)
    assert result.value == "d41d8cd98f00b204e9800998ecf8427e"


def test_sha256_lowercased():
    sha = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    ioc = _ioc(sha, IocType.SHA256)
    result = normalize_ioc(ioc)
    assert result.value == sha.lower()


# ── Email normalization ───────────────────────────────────────────────────────

def test_email_lowercased():
    ioc = _ioc("Attacker@EVIL.COM", IocType.EMAIL)
    result = normalize_ioc(ioc)
    assert result.value == "attacker@evil.com"


# ── Deduplication ─────────────────────────────────────────────────────────────

def test_deduplicates_same_value_and_type():
    iocs = [
        _ioc("8.8.8.8", IocType.IPV4),
        _ioc("8.8.8.8", IocType.IPV4),
    ]
    result = normalize_and_deduplicate(iocs)
    assert len(result) == 1
    assert result[0].value == "8.8.8.8"


def test_deduplicates_after_normalization():
    # EVIL.COM. and evil.com normalize to the same value — should dedupe
    iocs = [
        _ioc("EVIL.COM.", IocType.DOMAIN),
        _ioc("evil.com", IocType.DOMAIN),
    ]
    result = normalize_and_deduplicate(iocs)
    assert len(result) == 1
    assert result[0].value == "evil.com"


def test_same_value_different_type_not_deduped():
    # A domain and a URL with the same text are different IOC types
    iocs = [
        _ioc("evil.com", IocType.DOMAIN),
        _ioc("http://evil.com", IocType.URL),
    ]
    result = normalize_and_deduplicate(iocs)
    assert len(result) == 2


def test_empty_list_returns_empty():
    assert normalize_and_deduplicate([]) == []


def test_drops_empty_value():
    iocs = [_ioc("", IocType.IPV4), _ioc("1.2.3.4", IocType.IPV4)]
    result = normalize_and_deduplicate(iocs)
    values = [i.value for i in result]
    assert "" not in values
    assert "1.2.3.4" in values
