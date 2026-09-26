"""
Alert source adapters — Universal Alert Ingestion / Normalization Layer.

Each `AlertNormalizer` maps ONE source's raw payload shape onto the
already-existing `NormalizedAlert` contract (contracts/normalized_alert.py
— the Universal Alert Schema, unmodified here). No IOC extraction happens
here (that stays entirely threat_intel_agent/ioc_extractor.py's job — see
`NormalizedAlert`'s own docstring on why it deliberately has no `iocs`
field), and no agent business logic (MITRE/RAG/ML Risk/LLM Analyst/Threat
Intel) is touched or duplicated.

Every normalizer degrades gracefully on missing OPTIONAL fields (never
raises just because a field is absent — section 4's explicit requirement).
The only two failure modes are structural, not content-related, and are
raised as distinct exceptions the API layer maps onto the Universal Error
Contract (contracts/error_builder.py):
  - `UnsupportedAlertSourceError` — a `source` value with no registered
    normalizer.
  - `InvalidAlertPayloadError` — `alert` is not a JSON object at all (the
    one thing no per-field default can paper over).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.contracts.normalized_alert import NormalizedAlert, from_raw_alert

# Mirrors apps/backend/src/infrastructure/external-services/siem/WazuhAdapter.ts
# ::mapSeverity exactly (rule.level 0-15 -> low/medium/high/critical) so a
# directly-ingested Wazuh alert and one that went through the backend's own
# webhook agree on the same severity for the same rule level.
_WAZUH_SEVERITY_THRESHOLDS: tuple[tuple[float, str], ...] = ((14, "critical"), (11, "high"), (7, "medium"))

# Mirrors apps/backend/src/infrastructure/external-services/siem/SplunkAdapter.ts
# ::mapSeverity exactly (urgency string, anything else -> low).
_SPLUNK_SEVERITIES = {"critical", "high", "medium"}


class InvalidAlertPayloadError(ValueError):
    """`alert` is not a JSON object — nothing can be normalized from it. Never raised for a merely sparse/incomplete object (see module docstring)."""


class UnsupportedAlertSourceError(ValueError):
    def __init__(self, source: Any) -> None:
        super().__init__(f"Unsupported alert source: {source!r}")
        self.source = source


def _wazuh_severity(level: Any) -> str:
    try:
        level_num = float(level)
    except (TypeError, ValueError):
        return "low"
    for threshold, label in _WAZUH_SEVERITY_THRESHOLDS:
        if level_num >= threshold:
            return label
    return "low"


def _splunk_severity(urgency: Any) -> str:
    if isinstance(urgency, str) and urgency.strip().lower() in _SPLUNK_SEVERITIES:
        return urgency.strip().lower()
    return "low"


def _parse_iso_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_epoch_timestamp(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _str_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _dig(payload: Any, *keys: str) -> Any:
    """One-level-safe nested dict access — never raises on a non-dict anywhere along the path."""
    node = payload
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


class AlertNormalizer:
    source: str

    def normalize(self, alert: dict, *, alert_id: str, tenant_id: str) -> NormalizedAlert:
        raise NotImplementedError


class WazuhAlertNormalizer(AlertNormalizer):
    """Wazuh's own JSON alert shape — rule.{description,level}, agent.{name,ip,id}, data.{srcip,dstip,srcuser,dstuser,...}, full_log, timestamp."""

    source = "wazuh"

    def normalize(self, alert: dict, *, alert_id: str, tenant_id: str) -> NormalizedAlert:
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        win_eventdata = _dig(data, "win", "eventdata") or {}

        hashes: list[str] = []
        hash_field = win_eventdata.get("hashes") if isinstance(win_eventdata, dict) else None
        if isinstance(hash_field, str) and hash_field.strip():
            hashes.append(hash_field.strip())

        source_ip = _str_or_none(data.get("srcip"))

        return NormalizedAlert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            timestamp=_parse_iso_timestamp(alert.get("timestamp")),
            source="wazuh",
            title=_str_or_none(rule.get("description")),
            description=_str_or_none(alert.get("full_log")),
            severity=_wazuh_severity(rule.get("level")),
            source_ip=source_ip,
            destination_ip=_str_or_none(data.get("dstip")),
            hostname=_str_or_none(agent.get("name")),
            username=_str_or_none(data.get("srcuser")) or _str_or_none(data.get("dstuser")),
            process=_str_or_none(win_eventdata.get("image")) or _str_or_none(data.get("process")),
            command_line=_str_or_none(win_eventdata.get("commandLine")) or _str_or_none(data.get("command")),
            file=_str_or_none(win_eventdata.get("targetFilename")) or _str_or_none(data.get("file")),
            hashes=hashes,
            # Same srcip -> agent.ip precedence as run_pipeline.py's own
            # _resolve_asset_id (spec's real target-asset field) — kept
            # consistent so a directly-ingested alert resolves the same
            # asset a backend-webhook-ingested one would.
            asset_id=source_ip or _str_or_none(agent.get("ip")),
            raw_alert=alert,
            metadata={k: v for k, v in {"ruleId": rule.get("id"), "ruleLevel": rule.get("level"), "agentId": agent.get("id")}.items() if v is not None},
        )


class SplunkAlertNormalizer(AlertNormalizer):
    """
    Splunk Enterprise Security notable-event / webhook-alert-action shape —
    see apps/backend/.../siem/SplunkAdapter.ts's own SplunkAlertPayload
    interface (event_id, _time, urgency, search_name, result). That
    adapter never destructures `result` itself; the CIM (Common
    Information Model) field names used here (src_ip/dest_ip/dest_host/
    user/process/...) are Splunk's own standard convention, not something
    invented for this task.
    """

    source = "splunk"

    def normalize(self, alert: dict, *, alert_id: str, tenant_id: str) -> NormalizedAlert:
        result = alert.get("result") if isinstance(alert.get("result"), dict) else {}

        hashes: list[str] = []
        file_hash = result.get("file_hash")
        if isinstance(file_hash, str) and file_hash.strip():
            hashes.append(file_hash.strip())

        source_ip = _str_or_none(result.get("src_ip")) or _str_or_none(result.get("src"))

        return NormalizedAlert(
            alert_id=alert_id,
            tenant_id=tenant_id,
            timestamp=_parse_epoch_timestamp(alert.get("_time")),
            source="splunk",
            title=_str_or_none(alert.get("search_name")),
            description=_str_or_none(result.get("_raw")),
            severity=_splunk_severity(alert.get("urgency")),
            source_ip=source_ip,
            destination_ip=_str_or_none(result.get("dest_ip")) or _str_or_none(result.get("dest")),
            hostname=_str_or_none(result.get("dest_host")) or _str_or_none(result.get("host")) or _str_or_none(alert.get("host")),
            username=_str_or_none(result.get("user")) or _str_or_none(result.get("src_user")),
            process=_str_or_none(result.get("process")) or _str_or_none(result.get("process_name")),
            command_line=_str_or_none(result.get("process_command_line")) or _str_or_none(result.get("cmdline")),
            file=_str_or_none(result.get("file_name")) or _str_or_none(result.get("file_path")),
            hashes=hashes,
            asset_id=source_ip,
            raw_alert=alert,
            metadata={k: v for k, v in {"eventId": alert.get("event_id"), "searchName": alert.get("search_name")}.items() if v is not None},
        )


class GenericAlertNormalizer(AlertNormalizer):
    """
    Delegates to contracts/normalized_alert.py::from_raw_alert — the
    already-existing, already-tested generic best-effort mapper built in
    the Universal Alert Schema task specifically for "a source with no
    dedicated adapter". That function's own docstring notes it had no live
    caller yet; this is that caller, not a second generic key-guesser.
    """

    source = "generic"

    def normalize(self, alert: dict, *, alert_id: str, tenant_id: str) -> NormalizedAlert:
        return from_raw_alert(alert, alert_id=alert_id, tenant_id=tenant_id, source="generic")


_NORMALIZERS: dict[str, AlertNormalizer] = {cls.source: cls() for cls in (WazuhAlertNormalizer, SplunkAlertNormalizer, GenericAlertNormalizer)}

SUPPORTED_SOURCES: tuple[str, ...] = tuple(_NORMALIZERS)


def normalize_alert(source: str, alert: dict, *, alert_id: str, tenant_id: str) -> NormalizedAlert:
    """The single dispatch point every caller (the new /pipeline/alerts endpoint, agent_state_builder.py, tests) goes through — never call a concrete normalizer directly."""
    if not isinstance(alert, dict):
        raise InvalidAlertPayloadError("alert payload must be a JSON object")

    normalizer = _NORMALIZERS.get(source)
    if normalizer is None:
        raise UnsupportedAlertSourceError(source)

    return normalizer.normalize(alert, alert_id=alert_id, tenant_id=tenant_id)
