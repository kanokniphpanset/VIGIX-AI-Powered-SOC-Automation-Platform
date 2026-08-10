import ipaddress
import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 is intentionally permissive (full + compressed forms) since regex alone
# can't validate an address — ipaddress.ip_address() below does the real check.
IPV6_RE = re.compile(r"\b(?:[a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def extract_iocs_from_text(text: str) -> list[dict[str, str]]:
    """
    Pulls candidate IOCs out of free-text alert content (full_log, command
    lines, descriptions). Real SOC alerts often bury the actual indicator in
    a log blob rather than a structured field, so text extraction matters.

    Returns dicts shaped {"type": <IocType value>, "value": str}, matching
    agents/threat_intel_agent/types.py::IocType. Order of extraction matters:
    longer/more-specific patterns (URL, hashes) run before IP/domain so a
    hash embedded in a URL path isn't mistaken for something else, and so
    de-duplication below sees the most specific classification first.
    """
    text = text or ""
    iocs: list[dict[str, str]] = []

    for match in URL_RE.findall(text):
        iocs.append({"type": "URL", "value": match})

    for match in SHA256_RE.findall(text):
        iocs.append({"type": "SHA256", "value": match})

    for match in SHA1_RE.findall(text):
        if not SHA256_RE.fullmatch(match):
            iocs.append({"type": "SHA1", "value": match})

    for match in MD5_RE.findall(text):
        iocs.append({"type": "MD5", "value": match})

    for match in EMAIL_RE.findall(text):
        iocs.append({"type": "EMAIL", "value": match})

    for match in IP_RE.findall(text):
        if _is_valid_ipv4(match):
            iocs.append({"type": "IPV4", "value": match})

    for match in IPV6_RE.findall(text):
        if "::" in match or match.count(":") >= 2:
            if _is_valid_ipv6(match):
                iocs.append({"type": "IPV6", "value": match})

    for match in DOMAIN_RE.findall(text):
        # Avoid re-flagging IPs (which also match a loose domain pattern) or
        # a domain that's actually the hostname portion of an already-found URL.
        if not _is_valid_ipv4(match) and not any(match in u["value"] for u in iocs if u["type"] == "URL"):
            iocs.append({"type": "DOMAIN", "value": match})

    # De-duplicate while preserving order (first classification wins).
    seen = set()
    unique: list[dict[str, str]] = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    return unique


def extract_iocs(text: str) -> list[dict[str, str]]:
    """
    Legacy shape used before the ThreatIntelAgent rewrite:
    [{"ioc_type": "ip", "ioc_value": ...}, ...] with lowercase type names.
    Kept for any external caller still importing this name; new code should
    use extract_iocs_from_text().
    """
    return [
        {"ioc_type": ioc["type"].lower(), "ioc_value": ioc["value"]}
        for ioc in extract_iocs_from_text(text)
    ]
