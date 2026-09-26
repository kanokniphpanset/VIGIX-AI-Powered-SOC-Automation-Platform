"""
IOCValidator — format validation before any provider is queried.

An indicator that fails validation is never sent to a provider (saves quota,
avoids garbage-in/garbage-out results) and is reported back as
`{"valid": False, "reason": "..."}` rather than raising.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .types import IocType

_HASH_LENGTHS = {IocType.MD5: 32, IocType.SHA1: 40, IocType.SHA256: 64}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,63}$")


def validate_ioc(value: str, ioc_type: IocType) -> tuple[bool, str | None]:
    """Returns (valid, reason). reason is None when valid."""
    if not value or not value.strip():
        return False, "Empty indicator"

    if ioc_type == IocType.IPV4:
        try:
            ipaddress.IPv4Address(value)
            return True, None
        except ValueError:
            return False, "Invalid IPv4 format"

    if ioc_type == IocType.IPV6:
        try:
            ipaddress.IPv6Address(value)
            return True, None
        except ValueError:
            return False, "Invalid IPv6 format"

    if ioc_type == IocType.DOMAIN:
        if len(value) > 253 or not _DOMAIN_RE.match(value):
            return False, "Invalid domain format"
        return True, None

    if ioc_type == IocType.URL:
        try:
            parts = urlsplit(value)
        except ValueError:
            return False, "Invalid URL format"
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False, "Invalid URL format: must be http(s) with a host"
        return True, None

    if ioc_type in _HASH_LENGTHS:
        expected_length = _HASH_LENGTHS[ioc_type]
        if len(value) != expected_length or not _HEX_RE.match(value):
            return False, f"Invalid {ioc_type.value} format: expected {expected_length} hexadecimal characters"
        return True, None

    if ioc_type == IocType.EMAIL:
        if not _EMAIL_RE.match(value):
            return False, "Invalid email format"
        return True, None

    return False, f"Unsupported IOC type: {ioc_type.value}"
