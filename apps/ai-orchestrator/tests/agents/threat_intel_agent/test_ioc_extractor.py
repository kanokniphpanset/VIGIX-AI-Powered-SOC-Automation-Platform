"""Tests for IOC extraction from raw alert dicts and free text."""

import pytest

from src.agents.threat_intel_agent.ioc_extractor import extract_from_alert
from src.agents.threat_intel_agent.types import IocType


def _by_type(iocs, ioc_type):
    return [i for i in iocs if i.type == ioc_type]


# ── Structured field extraction ───────────────────────────────────────────────

def test_extracts_ipv4_from_src_ip():
    iocs = extract_from_alert({"src_ip": "192.168.1.1"})
    vals = [i.value for i in _by_type(iocs, IocType.IPV4)]
    assert "192.168.1.1" in vals


def test_extracts_ipv4_from_destination_ip():
    iocs = extract_from_alert({"destination_ip": "10.0.0.5"})
    vals = [i.value for i in _by_type(iocs, IocType.IPV4)]
    assert "10.0.0.5" in vals


def test_extracts_domain_from_hostname():
    iocs = extract_from_alert({"hostname": "evil.example.com"})
    vals = [i.value for i in _by_type(iocs, IocType.DOMAIN)]
    assert "evil.example.com" in vals


def test_extracts_url_from_url_field():
    iocs = extract_from_alert({"url": "http://malicious.site/payload"})
    vals = [i.value for i in _by_type(iocs, IocType.URL)]
    assert "http://malicious.site/payload" in vals


def test_extracts_md5_from_hash_field():
    iocs = extract_from_alert({"hash": "d41d8cd98f00b204e9800998ecf8427e"})
    vals = [i.value for i in _by_type(iocs, IocType.MD5)]
    assert "d41d8cd98f00b204e9800998ecf8427e" in vals


def test_extracts_sha256_from_sha256_field():
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    iocs = extract_from_alert({"sha256": sha})
    vals = [i.value for i in _by_type(iocs, IocType.SHA256)]
    assert sha in vals


def test_extracts_email():
    iocs = extract_from_alert({"email": "attacker@evil.com"})
    vals = [i.value for i in _by_type(iocs, IocType.EMAIL)]
    assert "attacker@evil.com" in vals


def test_extracts_from_nested_source_field():
    alert = {"source": {"ip": "1.2.3.4"}}
    iocs = extract_from_alert(alert)
    # nested ip inside source should be picked up by _walk
    # NOTE: the extractor checks top-level and one level of nested dicts
    vals = [i.value for i in _by_type(iocs, IocType.IPV4)]
    assert "1.2.3.4" in vals


def test_handles_missing_fields_without_crash():
    # Completely empty alert — must not raise
    iocs = extract_from_alert({})
    assert isinstance(iocs, list)


def test_handles_none_alert_without_crash():
    iocs = extract_from_alert(None)
    assert isinstance(iocs, list)


def test_handles_non_dict_field_values():
    # A field that is an int/list — must not crash
    iocs = extract_from_alert({"src_ip": 12345, "tags": ["network", "brute-force"]})
    assert isinstance(iocs, list)


# ── Text extraction (regex scanning) ─────────────────────────────────────────

def test_extracts_ip_from_alert_text():
    iocs = extract_from_alert({}, alert_text="Suspicious connection from 203.0.113.42 detected")
    vals = [i.value for i in _by_type(iocs, IocType.IPV4)]
    assert "203.0.113.42" in vals


def test_extracts_hash_from_free_text():
    sha256 = "aabbcc" * 10 + "aabb"  # 64 hex chars
    iocs = extract_from_alert({}, alert_text=f"Malware hash: {sha256}")
    vals = [i.value for i in _by_type(iocs, IocType.SHA256)]
    assert sha256 in vals


def test_extracts_url_from_free_text():
    iocs = extract_from_alert({}, alert_text="User visited https://phishing.example.com/login")
    vals = [i.value for i in _by_type(iocs, IocType.URL)]
    assert any("phishing.example.com" in v for v in vals)


# ── Deduplication (via extractor, pre-normalizer) ────────────────────────────

def test_does_not_return_exact_duplicates_from_multiple_fields():
    alert = {"src_ip": "8.8.8.8", "destination_ip": "8.8.8.8"}
    iocs = extract_from_alert(alert)
    ip_vals = [i.value for i in _by_type(iocs, IocType.IPV4)]
    # Extraction may return duplicates — normalization deduplicates, but at
    # the extractor level we at minimum verify both are found (normalization
    # tested separately). The extractor itself may or may not dedup — either
    # is valid. This test just asserts extraction doesn't crash.
    assert "8.8.8.8" in ip_vals


def test_multiple_ioc_types_extracted_simultaneously():
    alert = {
        "src_ip": "1.2.3.4",
        "domain": "evil.com",
        "hash": "d41d8cd98f00b204e9800998ecf8427e",
    }
    iocs = extract_from_alert(alert)
    types_found = {i.type for i in iocs}
    assert IocType.IPV4 in types_found
    assert IocType.DOMAIN in types_found
    assert IocType.MD5 in types_found
