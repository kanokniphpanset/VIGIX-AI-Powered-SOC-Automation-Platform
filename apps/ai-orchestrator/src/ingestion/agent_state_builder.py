"""
build_initial_state() — turns (source, alert_id, tenant_id, raw_alert) into
the exact AgentState-shaped dict the LangGraph pipeline consumes, with
`normalized_alert` populated alongside the legacy flat fields (severity,
alert_text, asset_id, asset_criticality) every existing agent already
reads. Not wired into build_graph.py / graph.ainvoke() by this task — see
api/routes/run_pipeline.py's new /alerts endpoint, which stops right after
this function returns.

`resolve_asset_id`, `resolve_asset_criticality`, and `flatten_alert_text`
below are moved here, verbatim in behavior, from api/routes/run_pipeline.py
— they operated on a raw SIEM payload dict already (`alert["raw_payload"]`
was unwrapped as their very first line), so generalizing their parameter to
take that payload dict directly makes them reusable by both entrypoints
instead of duplicating asset-resolution/text-flattening logic a second
time. run_pipeline.py now imports them from here; its own behavior for
`/pipeline/run` is unchanged (same lookups, same precedence, same catalog).
"""

from __future__ import annotations

from resources.asset_criticality_loader import ResourceAssetCriticalityProvider

from .alert_normalizer import normalize_alert

# Module-level (not per-request) so the YAML catalog is parsed once — same
# lifetime/reasoning as when this lived in run_pipeline.py.
_asset_criticality_provider = ResourceAssetCriticalityProvider()


def resolve_asset_id(raw_payload: dict) -> str | None:
    """
    The real host/IP a recommended action should target — Wazuh's
    data.srcip, falling back to agent.ip. See the original docstring in
    run_pipeline.py's git history for the full root-cause context (moved
    here verbatim, not reworded, since the reasoning still applies
    unchanged). Returns None (never a fabricated IP) when no structured
    field holds one.
    """
    if not isinstance(raw_payload, dict):
        return None
    data = raw_payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("srcip"), str) and data["srcip"].strip():
        return data["srcip"].strip()
    agent = raw_payload.get("agent")
    if isinstance(agent, dict) and isinstance(agent.get("ip"), str) and agent["ip"].strip():
        return agent["ip"].strip()
    return None


def resolve_asset_criticality(raw_payload: dict, asset_id: str | None) -> str:
    """Looks the real host up in resources/assets/asset-criticality-catalog.yaml by hostname (Wazuh agent.name) and/or IP (asset_id). Always returns a real catalog tier — never fabricates one."""
    tier, _known = resolve_asset_criticality_with_metadata(raw_payload, asset_id)
    return tier


def resolve_asset_criticality_with_metadata(raw_payload: dict, asset_id: str | None) -> tuple[str, bool]:
    """Same lookup as resolve_asset_criticality(), also returning whether
    this was a real catalog hit — Unknown Asset Safety task: lets callers
    record WHY an asset landed on a tier (genuinely catalogued vs. an
    uncatalogued host that fell back to the catalog's default_tier), not
    just which tier."""
    agent = raw_payload.get("agent") if isinstance(raw_payload, dict) else None
    hostname = agent.get("name") if isinstance(agent, dict) and isinstance(agent.get("name"), str) else None
    return _asset_criticality_provider.resolve_with_metadata(hostname=hostname, ip=asset_id)


def flatten_alert_text(raw_payload: dict) -> str:
    """Turns a raw SIEM payload into a single text blob for MitreAgent's keyword matching and RagAgent/LlmAnalystAgent's context — different SIEMs put the interesting text in different fields, so this pulls from all the common ones."""
    parts = []
    for key in ("rule", "full_log", "description", "title", "search_name"):
        value = raw_payload.get(key) if isinstance(raw_payload, dict) else None
        if isinstance(value, dict):
            parts.append(str(value.get("description", value)))
        elif value:
            parts.append(str(value))
    if not parts:
        parts.append(str(raw_payload))
    return " | ".join(parts)


def build_initial_state(*, source: str, alert_id: str, tenant_id: str, raw_alert: dict, graph_run_id: str | None = None) -> dict:
    """
    Section 5/6: Raw Alert -> Source Adapter -> NormalizedAlert -> AgentState.
    Produces the same shape run_pipeline.py's own `initial_state` dict
    always has (severity/alert_text/asset_id/asset_criticality preserved
    for every existing agent that reads them), plus `normalized_alert`.

    `graph_run_id` is optional (defaults to `alert_id`) — threat_intel_agent
    reads it only for provider-request logging/tracing (`state.get("graph_run_id")`,
    already None-safe), never for correctness, but the LangGraph Integration
    task's caller (ingest_alert.py) always passes its own fresh execution_id
    so a graph run is traceable the same way /pipeline/run's runs are.
    """
    normalized = normalize_alert(source, raw_alert, alert_id=alert_id, tenant_id=tenant_id)

    asset_id = resolve_asset_id(raw_alert) or normalized.asset_id
    asset_criticality, asset_known = resolve_asset_criticality_with_metadata(raw_alert, asset_id)
    # Reconcile back onto NormalizedAlert (frozen, so a copy) so the
    # canonical representation and AgentState's own asset_id/
    # asset_criticality never drift apart — section 3's "at minimum
    # preserve assetId/assetCriticality" means the REAL resolved value,
    # not whatever a per-source normalizer alone could infer.
    normalized = normalized.model_copy(update={"asset_id": asset_id, "asset_criticality": asset_criticality})

    state: dict = {
        "alert_id": alert_id,
        "tenant_id": tenant_id,
        "graph_run_id": graph_run_id or alert_id,
        "raw_alert": raw_alert,
        "siem_source": source,
        "severity": normalized.severity or "low",
        "alert_text": flatten_alert_text(raw_alert),
        "normalized_alert": normalized.model_dump(by_alias=True, mode="json"),
        "retry_count": 0,
        "trace": [],
        "errors": [],
    }
    if asset_id:
        state["asset_id"] = asset_id
    state["asset_criticality"] = asset_criticality
    state["asset_known"] = asset_known
    return state
