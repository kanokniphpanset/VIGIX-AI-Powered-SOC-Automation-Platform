"""Tests for the in-process TTL cache."""

import time

import pytest

from src.agents.threat_intel_agent.cache import ThreatIntelCache
from src.agents.threat_intel_agent.types import IocType, ProviderStatus, ThreatIntelProviderResult


def _success_result(name="VirusTotal"):
    return ThreatIntelProviderResult(
        name=name, status=ProviderStatus.SUCCESS, malicious=True, confidence=0.9
    )


def _failed_result(name="VirusTotal"):
    return ThreatIntelProviderResult(
        name=name, status=ProviderStatus.FAILED, error="timeout"
    )


# ── Basic get/set ─────────────────────────────────────────────────────────────

def test_cache_miss_returns_none():
    cache = ThreatIntelCache(ttl_seconds=60)
    result = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert result is None


def test_cache_hit_returns_stored_result():
    cache = ThreatIntelCache(ttl_seconds=60)
    r = _success_result()
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    retrieved = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert retrieved is not None
    assert retrieved.malicious is True
    assert retrieved.from_cache is True


def test_cache_key_is_provider_plus_type_plus_value():
    cache = ThreatIntelCache(ttl_seconds=60)
    r = _success_result()
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    # Different provider — should miss
    assert cache.get("AbuseIPDB", IocType.IPV4, "1.2.3.4") is None
    # Different type — should miss
    assert cache.get("VirusTotal", IocType.DOMAIN, "1.2.3.4") is None
    # Different value — should miss
    assert cache.get("VirusTotal", IocType.IPV4, "1.2.3.5") is None


def test_cache_hit_marks_from_cache_true():
    cache = ThreatIntelCache(ttl_seconds=60)
    r = _success_result()
    assert r.from_cache is False
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    retrieved = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert retrieved.from_cache is True


# ── Expiry ────────────────────────────────────────────────────────────────────

def test_expired_entry_returns_none():
    cache = ThreatIntelCache(ttl_seconds=0)  # expires immediately
    r = _success_result()
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    # TTL=0 means the entry expires at the set time
    time.sleep(0.01)  # tiny sleep to ensure expiry
    result = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert result is None


# ── Failed results not cached ─────────────────────────────────────────────────

def test_failed_result_not_cached():
    cache = ThreatIntelCache(ttl_seconds=60)
    r = _failed_result()
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    result = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert result is None  # failed results must never be cached


def test_disabled_result_not_cached():
    cache = ThreatIntelCache(ttl_seconds=60)
    r = ThreatIntelProviderResult(name="VirusTotal", status=ProviderStatus.DISABLED)
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    result = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert result is None


# ── Disabled cache ────────────────────────────────────────────────────────────

def test_disabled_cache_always_misses():
    cache = ThreatIntelCache(ttl_seconds=60, enabled=False)
    r = _success_result()
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    result = cache.get("VirusTotal", IocType.IPV4, "1.2.3.4")
    assert result is None


# ── Clear ─────────────────────────────────────────────────────────────────────

def test_clear_removes_all_entries():
    cache = ThreatIntelCache(ttl_seconds=60)
    r = _success_result()
    cache.set("VirusTotal", IocType.IPV4, "1.2.3.4", r)
    cache.set("AbuseIPDB", IocType.IPV4, "5.6.7.8", _success_result("AbuseIPDB"))
    cache.clear()
    assert cache.get("VirusTotal", IocType.IPV4, "1.2.3.4") is None
    assert cache.get("AbuseIPDB", IocType.IPV4, "5.6.7.8") is None
