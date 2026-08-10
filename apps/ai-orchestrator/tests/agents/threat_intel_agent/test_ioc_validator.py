"""Tests for IOC format validation."""

import pytest

from src.agents.threat_intel_agent.ioc_validator import validate_ioc
from src.agents.threat_intel_agent.types import IocType


def valid(value, ioc_type):
    ok, reason = validate_ioc(value, ioc_type)
    assert ok is True, f"Expected valid but got invalid: {reason}"


def invalid(value, ioc_type):
    ok, reason = validate_ioc(value, ioc_type)
    assert ok is False, f"Expected invalid but was accepted"
    assert reason is not None


# ── IPv4 ──────────────────────────────────────────────────────────────────────

def test_valid_ipv4():
    valid("192.168.1.1", IocType.IPV4)
    valid("8.8.8.8", IocType.IPV4)
    valid("0.0.0.0", IocType.IPV4)
    valid("255.255.255.255", IocType.IPV4)


def test_invalid_ipv4_out_of_range():
    invalid("256.0.0.1", IocType.IPV4)


def test_invalid_ipv4_letters():
    invalid("abc.def.ghi.jkl", IocType.IPV4)


def test_invalid_ipv4_too_few_octets():
    invalid("192.168.1", IocType.IPV4)


# ── IPv6 ──────────────────────────────────────────────────────────────────────

def test_valid_ipv6():
    valid("2001:db8::1", IocType.IPV6)
    valid("::1", IocType.IPV6)
    valid("fe80::1%eth0", IocType.IPV6)


def test_invalid_ipv6():
    invalid("not-an-ipv6", IocType.IPV6)
    invalid("gggg::1", IocType.IPV6)


# ── Domain ───────────────────────────────────────────────────────────────────

def test_valid_domain():
    valid("example.com", IocType.DOMAIN)
    valid("sub.evil.co.uk", IocType.DOMAIN)
    valid("xn--nxasmq6b.com", IocType.DOMAIN)  # IDN


def test_invalid_domain_no_tld():
    invalid("localhost", IocType.DOMAIN)


def test_invalid_domain_too_long():
    invalid("a" * 254 + ".com", IocType.DOMAIN)


def test_invalid_domain_starts_with_dot():
    invalid(".example.com", IocType.DOMAIN)


# ── URL ───────────────────────────────────────────────────────────────────────

def test_valid_url_http():
    valid("http://example.com/path", IocType.URL)


def test_valid_url_https():
    valid("https://evil.com/malware.exe", IocType.URL)


def test_invalid_url_no_scheme():
    invalid("evil.com/malware", IocType.URL)


def test_invalid_url_ftp_scheme():
    invalid("ftp://files.evil.com", IocType.URL)


def test_invalid_url_no_host():
    invalid("http:///path", IocType.URL)


# ── Hashes ────────────────────────────────────────────────────────────────────

def test_valid_md5():
    valid("d41d8cd98f00b204e9800998ecf8427e", IocType.MD5)


def test_invalid_md5_wrong_length():
    invalid("d41d8cd98f00b204e9800998ecf8427", IocType.MD5)  # 31 chars


def test_invalid_md5_non_hex():
    invalid("z41d8cd98f00b204e9800998ecf8427e", IocType.MD5)


def test_valid_sha1():
    valid("da39a3ee5e6b4b0d3255bfef95601890afd80709", IocType.SHA1)


def test_invalid_sha1_wrong_length():
    invalid("da39a3ee5e6b4b0d3255bfef95601890afd8070", IocType.SHA1)  # 39 chars


def test_valid_sha256():
    valid("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IocType.SHA256)


def test_invalid_sha256_wrong_length():
    invalid("e3b0c44298fc1c149afbf4c8996fb924", IocType.SHA256)


# ── Email ─────────────────────────────────────────────────────────────────────

def test_valid_email():
    valid("attacker@evil.com", IocType.EMAIL)
    valid("user+tag@subdomain.example.org", IocType.EMAIL)


def test_invalid_email_no_at():
    invalid("notanemail.com", IocType.EMAIL)


def test_invalid_email_no_domain():
    invalid("user@", IocType.EMAIL)
