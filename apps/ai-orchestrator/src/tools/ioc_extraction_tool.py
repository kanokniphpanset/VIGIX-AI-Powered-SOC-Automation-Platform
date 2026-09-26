"""IOC extraction: alert / log text  ->  IPs, domains, URLs, hashes, e-mails.

Deterministic (regex + validation). No LLM, no network.

Public functions
  extract_iocs_from_text(text, ...)   one string
  extract_iocs_from_event(event, ...) one Wazuh-style alert (dict); scans every value
  extract_iocs_from_events(events, .) many alerts, merged and de-duplicated

Every function returns a ToolResult whose `data` has:
  ips / domains / urls / hashes / emails   plain value lists (what the graph state stores)
  iocs                                     one record per IOC with metadata
  skipped                                  values found but rejected, with the reason
  metadata                                 source_event_id(s), first_seen, extraction_method

An IOC record: {type, value, defanged, occurrences, source_event_ids, first_seen,
                field, extraction_method[, hash_type]}
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Mapping, Optional
from urllib.parse import urlsplit

from src.contracts.tool_result import ToolResult

SOURCE = "ioc_extraction"
TYPES = ("ip", "domain", "url", "hash", "email")
_PLURAL = {"ip": "ips", "domain": "domains", "url": "urls", "hash": "hashes", "email": "emails"}

# ------------------------------------------------------------------ refang
_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
]


def refang(text: str) -> str:
    """Undo common defanging (hxxp://evil[.]com  ->  http://evil.com)."""
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, ioc_type: str) -> str:
    """Safe-to-display form. Hashes are already harmless."""
    if ioc_type == "hash":
        return value
    out = value.replace(".", "[.]")
    if ioc_type == "url":
        out = re.sub(r"^http", "hxxp", out, flags=re.I)
    if ioc_type == "email":
        out = out.replace("@", "[@]")
    return out


# ------------------------------------------------------------------ patterns
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.I)
_EMAIL_RE = re.compile(r"(?<![\w.+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}(?![\w\-])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\w)")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])")
_HASH_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,64}(?![0-9A-Fa-f])")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.\-/])((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9\-]{1,23})(?![\w\-])"
)
_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

_NON_ROUTABLE_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
)]

# A dotted word is only a domain when its last label is a real TLD. This keeps file names
# (auth.log, sshd.conf) and host names (server-01.local) out of the results.
_COMMON_TLDS = frozenset(
    "com net org info biz io co dev app xyz top site online shop club cloud tech pro name mobi "
    "edu gov mil int onion "
    "ru cn br in ir kp ua tr vn id th kr jp de fr uk nl pl it es se no fi ch at be cz ro hu "
    "us ca au nz za mx ar cl pe ve eg ng ke ma".split()
)
# Real TLDs that are far more often file extensions in log text.
_FILE_LIKE_TLDS = frozenset("sh py pl js zip mov md so cc rs ps".split())


def _valid_tld(label: str) -> bool:
    label = label.lower()
    if label in _FILE_LIKE_TLDS:
        return False
    return label in _COMMON_TLDS


def _routable_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv4Address):
        return not any(ip in net for net in _NON_ROUTABLE_V4)
    return ip.is_global


def _in_allow_list(value: str, allow_list: frozenset[str]) -> bool:
    v = value.lower()
    return any(v == a or v.endswith("." + a) for a in allow_list)


# ------------------------------------------------------------------ core scan
def _scan(text: str, *, exclude_non_routable: bool, allow_list: frozenset[str]) -> tuple[list[dict], list[dict]]:
    """Return (found, skipped) for one string. `found` items: {type, value, method[, hash_type]}."""
    text = refang(text)
    found: list[dict] = []
    skipped: list[dict] = []

    def add(t: str, v: str, method: str, **extra: Any) -> None:
        checked = v.split("@")[-1] if t == "email" else v
        if allow_list and _in_allow_list(checked, allow_list):
            skipped.append({"type": t, "value": v, "reason": "allow_listed"})
            return
        found.append({"type": t, "value": v, "method": method, **extra})

    for m in _EMAIL_RE.finditer(text):
        email = m.group(0).lower()
        domain = email.split("@", 1)[1]
        if not _valid_tld(domain.rsplit(".", 1)[-1]):
            continue
        add("email", email, "regex")
        add("domain", domain, "derived_from_email")

    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:!?)]}'\"")
        try:
            host = urlsplit(url).hostname
        except ValueError:
            skipped.append({"type": "url", "value": url, "reason": "invalid_url"})
            continue
        if not host:
            continue
        add("url", url, "regex")
        try:
            ipaddress.ip_address(host)  # host is an IP: the IP scan below reports it
        except ValueError:
            if _valid_tld(host.rsplit(".", 1)[-1]):
                add("domain", host.lower(), "derived_from_url")

    for m in _IPV4_RE.finditer(text):
        raw = m.group(0)
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            skipped.append({"type": "ip", "value": raw, "reason": "invalid_ip"})
            continue
        if exclude_non_routable and not _routable_ip(ip):
            skipped.append({"type": "ip", "value": raw, "reason": "non_routable"})
            continue
        add("ip", str(ip), "regex")

    for m in _IPV6_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue  # times (10:32:11) and MAC addresses land here
        if exclude_non_routable and not _routable_ip(ip):
            skipped.append({"type": "ip", "value": str(ip), "reason": "non_routable"})
            continue
        add("ip", str(ip), "regex")

    for m in _HASH_RE.finditer(text):
        raw = m.group(0)
        if len(raw) not in _HASH_TYPES or raw.isdigit():
            continue
        add("hash", raw.lower(), "regex", hash_type=_HASH_TYPES[len(raw)])

    for m in _DOMAIN_RE.finditer(text):
        domain = m.group(1).lower()
        if len(domain) > 253 or not _valid_tld(domain.rsplit(".", 1)[-1]):
            continue
        add("domain", domain, "regex")

    return found, skipped


# ------------------------------------------------------------------ timestamps
def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    s = re.sub(r"([+\-]\d{2})(\d{2})$", r"\1:\2", s)  # +0000 -> +00:00
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _earlier(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None:
        return b
    if b is None:
        return a
    pa, pb = _parse_ts(a), _parse_ts(b)
    if pa and pb:
        return a if pa <= pb else b
    return min(a, b)


# ------------------------------------------------------------------ record store
class _Store:
    """Collects findings, de-duplicates by (type, value) and keeps the metadata."""

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], dict[str, Any]] = {}
        self.skipped: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add(self, found: Iterable[dict], skipped: Iterable[dict], *, event_id: Optional[str],
            first_seen: Optional[str], field_path: Optional[str]) -> None:
        for f in found:
            key = (f["type"], f["value"])
            rec = self.records.get(key)
            if rec is None:
                rec = {
                    "type": f["type"], "value": f["value"], "defanged": defang(f["value"], f["type"]),
                    "occurrences": 0, "source_event_ids": [], "first_seen": None,
                    "field": field_path, "extraction_method": f["method"],
                }
                if "hash_type" in f:
                    rec["hash_type"] = f["hash_type"]
                self.records[key] = rec
            rec["occurrences"] += 1
            if event_id and event_id not in rec["source_event_ids"]:
                rec["source_event_ids"].append(event_id)
            rec["first_seen"] = _earlier(rec["first_seen"], first_seen)
        for s in skipped:
            key = (s["type"], s["value"], s["reason"])
            if key not in self.skipped:
                self.skipped[key] = dict(s)

    def result(self, query: dict[str, Any], metadata: dict[str, Any]) -> ToolResult:
        iocs = list(self.records.values())
        data: dict[str, Any] = {_PLURAL[t]: [r["value"] for r in iocs if r["type"] == t] for t in TYPES}
        data["iocs"] = iocs
        data["skipped"] = list(self.skipped.values())
        data["metadata"] = metadata
        return ToolResult.success(SOURCE, data, query=query)


def _allow(allow_list: Optional[Iterable[str]]) -> frozenset[str]:
    return frozenset(a.lower().lstrip(".") for a in (allow_list or ()))


# ------------------------------------------------------------------ public API
def extract_iocs_from_text(
    text: str,
    *,
    source_event_id: Optional[str] = None,
    first_seen: Optional[str] = None,
    exclude_non_routable: bool = True,
    allow_list: Optional[Iterable[str]] = None,
    field: Optional[str] = None,
) -> ToolResult:
    """Extract IOCs from one piece of text (alert message, raw log line, report...)."""
    query = {"text_length": len(text or ""), "exclude_non_routable": exclude_non_routable}
    if not isinstance(text, str):
        return ToolResult.failure("error", SOURCE, f"text must be str, got {type(text).__name__}", query)
    found, skipped = _scan(text, exclude_non_routable=exclude_non_routable, allow_list=_allow(allow_list))
    store = _Store()
    store.add(found, skipped, event_id=source_event_id, first_seen=first_seen, field_path=field)
    return store.result(query, {
        "source_event_id": source_event_id, "first_seen": first_seen, "extraction_method": "regex",
    })


def _leaves(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(node, Mapping):
        for k, v in node.items():
            yield from _leaves(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            yield from _leaves(v, f"{path}[{i}]")
    elif node is not None:
        yield path, str(node)


def _event_meta(event: Mapping[str, Any]) -> tuple[Optional[str], Optional[str], Mapping[str, Any]]:
    body = event.get("_source", event)
    event_id = event.get("_id") or body.get("id") or event.get("id")
    ts = body.get("timestamp") or body.get("@timestamp")
    return (str(event_id) if event_id else None), (str(ts) if ts else None), body


def _scan_event_into(
    store: _Store, event: Mapping[str, Any], exclude_non_routable: bool, allow: frozenset[str]
) -> None:
    event_id, ts, body = _event_meta(event)
    for path, value in _leaves(body):
        found, skipped = _scan(value, exclude_non_routable=exclude_non_routable, allow_list=allow)
        store.add(found, skipped, event_id=event_id, first_seen=ts, field_path=path)


def extract_iocs_from_event(
    event: Mapping[str, Any],
    *,
    exclude_non_routable: bool = True,
    allow_list: Optional[Iterable[str]] = None,
) -> ToolResult:
    """Extract IOCs from one Wazuh-style alert (dict). Every value in the alert is scanned."""
    return extract_iocs_from_events([event], exclude_non_routable=exclude_non_routable, allow_list=allow_list)


def extract_iocs_from_events(
    events: Iterable[Mapping[str, Any]],
    *,
    exclude_non_routable: bool = True,
    allow_list: Optional[Iterable[str]] = None,
) -> ToolResult:
    """Extract from many alerts; the same IOC is merged (occurrences summed, earliest first_seen)."""
    events = list(events)
    query = {"event_count": len(events), "exclude_non_routable": exclude_non_routable}
    store, allow = _Store(), _allow(allow_list)
    for ev in events:
        if not isinstance(ev, Mapping):
            return ToolResult.failure("error", SOURCE, f"event must be a mapping, got {type(ev).__name__}", query)
        _scan_event_into(store, ev, exclude_non_routable, allow)
    seen = [r["first_seen"] for r in store.records.values() if r["first_seen"]]
    first = None
    for s in seen:
        first = _earlier(first, s)
    ids: list[str] = []
    for r in store.records.values():
        ids.extend(i for i in r["source_event_ids"] if i not in ids)
    return store.result(query, {"source_event_ids": ids, "first_seen": first, "extraction_method": "regex"})
