"""
NormalizedAlert — the Universal Alert Schema.

Sits between raw SIEM ingestion (Wazuh, Splunk, anything else) and every AI
agent. This is a NEW, additive contract layer — it does not replace
`AgentState`'s existing flat fields (`raw_alert`, `severity`, `alert_text`,
`asset_id`, `asset_criticality`, ...), which every existing agent already
reads and which stay exactly as they are. `from_agent_state()` below is a
pure adapter that assembles a `NormalizedAlert` FROM those existing fields,
for callers that want the formal, validated, SIEM-agnostic shape instead of
reading six separate dict keys by hand.

Design decisions, made by reading the real codebase rather than guessing:

- Only `alert_id` and `tenant_id` are mandatory. Every real call site
  already requires both (see api/schemas.py::RunPipelineRequest — the only
  two non-optional fields on the one HTTP contract that starts a pipeline
  run), so this mirrors an existing, already-enforced requirement rather
  than inventing a new one. Every other field must degrade to None/empty
  so a minimal alert from a thin SIEM integration is still valid.
- Deliberately has NO `iocs` field. IOC extraction is entirely
  ThreatIntelAgent's job (ioc_extractor.py reads straight from
  raw_alert/alert_text) — giving NormalizedAlert its own `iocs` field would
  create a second, competing source of IOC truth, which the task
  explicitly forbids ("do not create a new IOC Agent / do not replace
  existing IOC extraction").
- `rawAlert` is always preserved verbatim, never summarized or dropped —
  every downstream agent that already reads `raw_alert` directly
  (ThreatIntelAgent's IOC extractor, run_pipeline.py's alert-text
  flattening) still has the original payload to work from.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from ._base import CamelModel


class NormalizedAlert(CamelModel):
    """
    A SIEM-agnostic normalized view of one alert. Field list is deliberately
    NOT the task's full illustrative example — every field below is either
    (a) already read by an existing agent under a different name (mapped
    here 1:1), or (b) a generic hint (sourceIp/hostname/process/...) that
    ThreatIntelAgent's existing extractor can already pull out of raw
    payloads for common SIEMs. Nothing was added just because the example
    listed it.
    """

    alert_id: str
    tenant_id: str

    timestamp: datetime | None = None
    # SIEM vendor tag — mirrors AgentState.siem_source exactly (e.g. "wazuh").
    source: str | None = None
    title: str | None = None
    description: str | None = None
    # Mirrors AgentState.severity — the backend's own normalized low/medium/
    # high/critical value (e.g. WazuhAdapter.mapSeverity()), never a raw
    # per-SIEM severity field.
    severity: str | None = None

    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    process: str | None = None
    command_line: str | None = None
    file: str | None = None
    hashes: list[str] = Field(default_factory=list)

    asset_id: str | None = None
    asset_criticality: str | None = None

    raw_alert: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


def from_agent_state(state: dict) -> NormalizedAlert:
    """
    The authoritative constructor: assembles a NormalizedAlert from the
    AgentState fields that already exist and that every agent already
    trusts (severity, siem_source, asset_id, asset_criticality, raw_alert).
    Never raises on a partial/minimal state — every read is `.get()` with a
    safe default, matching every other adapter in this codebase
    (query_builder.extract_query_input, rag_agent.types.extract_investigation_context).
    """
    raw_alert = state.get("raw_alert") or {}
    return NormalizedAlert(
        alert_id=state.get("alert_id", ""),
        tenant_id=state.get("tenant_id", ""),
        source=state.get("siem_source"),
        severity=state.get("severity"),
        description=state.get("alert_text"),
        asset_id=state.get("asset_id"),
        asset_criticality=state.get("asset_criticality"),
        raw_alert=raw_alert,
    )


# Common raw-payload key paths across the SIEM shapes this codebase already
# encounters (Wazuh's data.srcip/data.dstip/agent.*, plus the generic
# rule/full_log/description/title/search_name keys run_pipeline.py's own
# _flatten_alert_text already treats as the "any SIEM" fallback set — see
# api/routes/run_pipeline.py). Best-effort only: a field not found under any
# of these paths simply stays None, never guessed.
_TITLE_KEYS = ("title", "rule", "search_name")
_DESCRIPTION_KEYS = ("description", "full_log")
_SOURCE_IP_KEYS = (("data", "srcip"), ("src_ip",), ("source_ip",))
_DESTINATION_IP_KEYS = (("data", "dstip"), ("dest_ip",), ("destination_ip",))
_HOSTNAME_KEYS = (("agent", "name"), ("host",), ("hostname",))


def _dig(payload: dict, *paths: tuple[str, ...]) -> str | None:
    for path in paths:
        node = payload
        for key in path:
            if not isinstance(node, dict) or key not in node:
                node = None
                break
            node = node[key]
        if isinstance(node, str) and node:
            return node
        if isinstance(node, dict) and "description" in node and isinstance(node["description"], str):
            # Wazuh's `rule` key is itself an object ({"description": ..., "level": ...}) —
            # unwrap it rather than returning the dict.
            return node["description"]
    return None


def from_raw_alert(raw_alert: dict, alert_id: str, tenant_id: str, severity: str | None = None, source: str | None = None) -> NormalizedAlert:
    """
    Lower-fidelity constructor for when only the raw SIEM payload is
    available (no AgentState yet) — a best-effort, generic key-guesser
    across the SIEM shapes already known to this codebase. Not currently
    called from any live code path (this task builds the contract layer,
    not a new ingestion entrypoint) — provided so the "Wazuh / Splunk /
    other -> NormalizedAlert" mapping in the spec has a real, testable
    implementation rather than only existing on paper.
    """
    title = _dig(raw_alert, ("title",), ("search_name",)) or (raw_alert.get("rule", {}).get("description") if isinstance(raw_alert.get("rule"), dict) else None)
    description = raw_alert.get("full_log") if isinstance(raw_alert.get("full_log"), str) else raw_alert.get("description")
    source_ip = _dig(raw_alert, ("data", "srcip"), ("src_ip",), ("source_ip",))
    destination_ip = _dig(raw_alert, ("data", "dstip"), ("dest_ip",), ("destination_ip",))
    hostname = _dig(raw_alert, ("agent", "name"), ("host",), ("hostname",))

    return NormalizedAlert(
        alert_id=alert_id,
        tenant_id=tenant_id,
        source=source,
        severity=severity,
        title=title if isinstance(title, str) else None,
        description=description if isinstance(description, str) else None,
        source_ip=source_ip,
        destination_ip=destination_ip,
        hostname=hostname,
        raw_alert=raw_alert,
    )
