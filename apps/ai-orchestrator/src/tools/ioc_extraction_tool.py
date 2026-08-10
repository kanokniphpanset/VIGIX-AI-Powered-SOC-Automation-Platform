import re

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")


def extract_iocs(text: str) -> list[dict[str, str]]:
    """
    Pulls candidate IOCs out of free-text alert content (full_log, command lines,
    descriptions). Real SOC alerts often bury the actual indicator in a log
    blob rather than a structured field, so text extraction matters.
    """
    iocs: list[dict[str, str]] = []

    for match in URL_RE.findall(text):
        iocs.append({"ioc_type": "url", "ioc_value": match})

    for match in SHA256_RE.findall(text):
        iocs.append({"ioc_type": "hash", "ioc_value": match})

    for match in MD5_RE.findall(text):
        iocs.append({"ioc_type": "hash", "ioc_value": match})

    for match in IP_RE.findall(text):
        iocs.append({"ioc_type": "ip", "ioc_value": match})

    for match in DOMAIN_RE.findall(text):
        # Avoid re-flagging IPs (which also match a loose domain pattern) or bare TLDs
        if not IP_RE.match(match):
            iocs.append({"ioc_type": "domain", "ioc_value": match})

    # De-duplicate while preserving order
    seen = set()
    unique: list[dict[str, str]] = []
    for ioc in iocs:
        key = (ioc["ioc_type"], ioc["ioc_value"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    return unique
