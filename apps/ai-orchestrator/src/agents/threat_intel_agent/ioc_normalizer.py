"""
IOCNormalizer — puts every IOC into a canonical form before dedup/validation.

Rules (deliberately conservative — normalization must never change what the
indicator actually refers to):
  * IPv4/IPv6: parsed via `ipaddress` and re-serialized (compresses IPv6,
    strips leading zeros).
  * Domain: lowercased, trailing dot stripped (both are DNS-equivalent forms).
  * URL: scheme + host lowercased, default ports (80/443 for http/https)
    dropped, trailing slash on a bare path stripped. Query string, explicit
    non-default ports, and path casing are preserved — those can be
    semantically significant (case-sensitive paths, tracking params) and
    stripping them could hide the real indicator from a provider lookup.
  * Hash: lowercased (hex digests are case-insensitive by definition).
  * Email: lowercased.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from .types import ExtractedIoc, IocType

_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _normalize_ip(value: str, ip_type: IocType) -> str:
    try:
        parsed = ipaddress.ip_address(value.strip())
        return str(parsed)
    except ValueError:
        return value.strip()


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_url(value: str) -> str:
    value = value.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return value

    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").lower()

    netloc = hostname
    if parts.port and str(parts.port) != _DEFAULT_PORTS.get(scheme):
        netloc = f"{hostname}:{parts.port}"
    if parts.username:
        credentials = parts.username
        if parts.password:
            credentials += f":{parts.password}"
        netloc = f"{credentials}@{netloc}"

    path = parts.path
    if path == "/":
        path = ""
    elif path.endswith("/") and len(path) > 1:
        # Only collapse a single trailing slash on an otherwise non-root path —
        # preserves any deeper structure/query, which can matter for lookups.
        path = path[:-1]

    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _normalize_hash(value: str) -> str:
    return value.strip().lower()


def _normalize_email(value: str) -> str:
    return value.strip().lower()


_NORMALIZERS = {
    IocType.IPV4: lambda v: _normalize_ip(v, IocType.IPV4),
    IocType.IPV6: lambda v: _normalize_ip(v, IocType.IPV6),
    IocType.DOMAIN: _normalize_domain,
    IocType.URL: _normalize_url,
    IocType.MD5: _normalize_hash,
    IocType.SHA1: _normalize_hash,
    IocType.SHA256: _normalize_hash,
    IocType.EMAIL: _normalize_email,
}


def normalize_ioc(ioc: ExtractedIoc) -> ExtractedIoc:
    """Returns a new ExtractedIoc with its value normalized; type/field unchanged."""
    normalizer = _NORMALIZERS.get(ioc.type)
    if normalizer is None:
        return ExtractedIoc(value=ioc.value.strip(), type=ioc.type, field=ioc.field)
    return ExtractedIoc(value=normalizer(ioc.value), type=ioc.type, field=ioc.field)


def normalize_and_deduplicate(iocs: list[ExtractedIoc]) -> list[ExtractedIoc]:
    """
    Normalizes every IOC then deduplicates by (type, normalized value),
    keeping the first occurrence's source field for traceability.
    """
    seen: set[tuple[IocType, str]] = set()
    result: list[ExtractedIoc] = []
    for ioc in iocs:
        normalized = normalize_ioc(ioc)
        key = (normalized.type, normalized.value)
        if not normalized.value or key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result
