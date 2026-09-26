"""
IOCExtractor — pulls candidate indicators out of a raw SIEM alert.

Two sources are combined:
  1. Known structured fields (src_ip, dst_ip, url, domain, hash, md5, sha1,
     sha256, email, ...) — checked defensively since Wazuh/Splunk/Defender/ELK
     all use different schemas and any given field may be absent, nested, or
     the wrong type.
  2. Free text (alert_text, plus description/message/command_line-style
     fields if present) — regex-scanned via tools/ioc_extraction_tool.py,
     which already handles URL/hash/IP/domain; extended here with IPv6, SHA1,
     and email.

Extraction never raises — a malformed or missing field is skipped, not fatal.
"""

from __future__ import annotations

from typing import Any

from src.tools.ioc_extraction_tool import extract_iocs_from_text
from .types import ExtractedIoc, IocType

# Alert fields that commonly hold a single indicator value keyed by expected type.
_IP_FIELDS = ("src_ip", "dst_ip", "source_ip", "destination_ip", "ip", "client_ip", "remote_ip")
_DOMAIN_FIELDS = ("domain", "hostname", "dns_query", "query")
_URL_FIELDS = ("url", "uri", "request_url")
_HASH_FIELDS = ("hash", "md5", "sha1", "sha256", "file_hash")
_EMAIL_FIELDS = ("email", "sender", "recipient", "from", "to")
# Free-text-bearing fields worth regex-scanning in addition to alert_text.
_TEXT_FIELDS = ("message", "description", "command_line", "process", "full_log", "rule")


def _classify_hash(value: str) -> IocType:
    length = len(value)
    if length == 32:
        return IocType.MD5
    if length == 40:
        return IocType.SHA1
    if length == 64:
        return IocType.SHA256
    return IocType.UNKNOWN


def _stringify(value: Any) -> str | None:
    """Best-effort flatten of a field value that may be a str, dict, or list."""
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    if isinstance(value, (dict, list)):
        return str(value)
    return str(value)


def _walk(payload: Any, field_names: tuple[str, ...]) -> list[tuple[str, str]]:
    """
    Defensively search a (possibly nested, possibly non-dict) payload for any
    of `field_names`. SIEM payloads vary wildly in shape — some nest fields
    under `data`/`agent`/`rule`, some don't — so this checks the top level and
    one level of nested dicts rather than assuming a fixed schema.
    """
    found: list[tuple[str, str]] = []
    if not isinstance(payload, dict):
        return found

    for key in field_names:
        raw = payload.get(key)
        text = _stringify(raw)
        if text:
            found.append((key, text))

    for value in payload.values():
        if isinstance(value, dict):
            for key in field_names:
                raw = value.get(key)
                text = _stringify(raw)
                if text:
                    found.append((key, text))

    return found


def extract_from_alert(raw_alert: dict | None, alert_text: str = "") -> list[ExtractedIoc]:
    """
    Extract every candidate IOC from a raw alert payload plus its flattened
    text representation. Returns extraction results (not yet normalized or
    validated) tagged with the alert field they came from, for traceability.
    """
    payload = raw_alert if isinstance(raw_alert, dict) else {}
    extracted: list[ExtractedIoc] = []

    for field_name, value in _walk(payload, _IP_FIELDS):
        ioc_type = IocType.IPV6 if ":" in value else IocType.IPV4
        extracted.append(ExtractedIoc(value=value, type=ioc_type, field=field_name))

    for field_name, value in _walk(payload, _DOMAIN_FIELDS):
        extracted.append(ExtractedIoc(value=value, type=IocType.DOMAIN, field=field_name))

    for field_name, value in _walk(payload, _URL_FIELDS):
        extracted.append(ExtractedIoc(value=value, type=IocType.URL, field=field_name))

    for field_name, value in _walk(payload, _HASH_FIELDS):
        hash_type = IocType.SHA256 if field_name == "sha256" else (
            IocType.SHA1 if field_name == "sha1" else (
                IocType.MD5 if field_name == "md5" else _classify_hash(value)
            )
        )
        extracted.append(ExtractedIoc(value=value, type=hash_type, field=field_name))

    for field_name, value in _walk(payload, _EMAIL_FIELDS):
        extracted.append(ExtractedIoc(value=value, type=IocType.EMAIL, field=field_name))

    text_blobs = [alert_text] if alert_text else []
    for field_name, value in _walk(payload, _TEXT_FIELDS):
        text_blobs.append(value)

    for blob in text_blobs:
        for match in extract_iocs_from_text(blob):
            extracted.append(
                ExtractedIoc(value=match["value"], type=IocType(match["type"]), field="text")
            )

    return extracted
