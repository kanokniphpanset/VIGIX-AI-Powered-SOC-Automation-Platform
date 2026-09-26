import logging

from src.graph.state import AgentState

logger = logging.getLogger("soar.ai-orchestrator")

SEVERITY_NUMERIC = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# tier1_critical is deliberately the highest score, tier4_low the lowest —
# same 25/50/75/100 scale as severity, so WeightedRiskModel can treat both
# "tiered" signals identically. Keys match AssetCriticality's real values
# (decision_agent/models.py) as plain strings — this module never imports
# that enum, to keep MlRiskAgent decoupled from DecisionAgent (same
# reasoning as SEVERITY_NUMERIC not importing anything from the backend).
ASSET_CRITICALITY_NUMERIC = {
    "tier4_low": 25.0,
    "tier3_medium": 50.0,
    "tier2_high": 75.0,
    "tier1_critical": 100.0,
}

# Explicit, named fallbacks — never blend these into "just what .get()
# happened to return." Every fallback path below is logged, not silent.
_MISSING_SEVERITY_FALLBACK = "low"
# Matches resources/assets/asset-criticality-catalog.yaml's own
# default_tier reasoning: treat an unresolvable asset cautiously, not at
# either extreme.
_MISSING_ASSET_CRITICALITY_FALLBACK = "tier2_high"
_MISSING_THREAT_INTEL_CONFIDENCE_FALLBACK = 0.5  # neutral, 0-1 scale


def _resolve_siem_severity(state: AgentState) -> str:
    """
    Root-cause fix: this used to read `state["raw_alert"].get("severity")`,
    but the raw SIEM payload never has a top-level "severity" key (Wazuh's
    own severity signal is `rule.level`, already normalized into the
    backend's Alert.severity column and threaded through as its own
    `AgentState.severity` field by run_pipeline.py — see state.py's
    docstring on that field). Reading the real field now; every fallback
    path below is logged, not silent, per the "no silent default-low"
    requirement.
    """
    alert_id = state.get("alert_id", "unknown")
    severity = state.get("severity")

    if not severity:
        logger.warning(
            "MlRiskAgent/feature_engineering: severity missing from pipeline state for alert_id=%s "
            "— falling back to '%s'. siem_severity_numeric will not reflect this alert's real SIEM signal.",
            alert_id,
            _MISSING_SEVERITY_FALLBACK,
        )
        return _MISSING_SEVERITY_FALLBACK

    normalized = str(severity).lower()
    if normalized not in SEVERITY_NUMERIC:
        logger.warning(
            "MlRiskAgent/feature_engineering: unrecognized severity value %r for alert_id=%s "
            "(expected one of %s) — falling back to '%s'.",
            severity,
            alert_id,
            sorted(SEVERITY_NUMERIC),
            _MISSING_SEVERITY_FALLBACK,
        )
        return _MISSING_SEVERITY_FALLBACK

    return normalized


def _resolve_asset_criticality_numeric(state: AgentState) -> float:
    """
    Reads the real tier run_pipeline.py resolved via
    ResourceAssetCriticalityProvider (resources/assets/asset-criticality-catalog.yaml)
    and maps it to ASSET_CRITICALITY_NUMERIC. Only falls back (logged) if
    `asset_criticality` is somehow still absent/unrecognized — run_pipeline.py
    always sets a real value now, so this path should not normally trigger.
    """
    alert_id = state.get("alert_id", "unknown")
    tier = state.get("asset_criticality")

    if not tier or tier not in ASSET_CRITICALITY_NUMERIC:
        logger.warning(
            "MlRiskAgent/feature_engineering: asset_criticality missing/unrecognized (%r) for alert_id=%s "
            "— falling back to '%s'.",
            tier,
            alert_id,
            _MISSING_ASSET_CRITICALITY_FALLBACK,
        )
        tier = _MISSING_ASSET_CRITICALITY_FALLBACK

    return ASSET_CRITICALITY_NUMERIC[tier]


def _resolve_threat_intel_confidence(state: AgentState) -> float:
    """
    ThreatIntelAgent's own aggregated confidence in its verdict (0-1 scale —
    see threat_intel_agent/aggregator.py's overall_confidence, averaged
    across providers and clamped to [0,1] in scoring.py), NOT MlRiskAgent's
    own output confidence_score. Falls back to a neutral 0.5 (logged) when
    no threat-intel report exists yet for this alert (e.g. the alert had no
    extractable IOCs) — deliberately not 0.0, so "nothing to check" doesn't
    get scored identically to "checked and found nothing concerning."
    """
    alert_id = state.get("alert_id", "unknown")
    report = state.get("threat_intel_report")
    confidence = report.get("overallConfidence") if isinstance(report, dict) else None

    if confidence is None:
        logger.warning(
            "MlRiskAgent/feature_engineering: no threat_intel_report.overallConfidence for alert_id=%s "
            "— falling back to neutral %.2f.",
            alert_id,
            _MISSING_THREAT_INTEL_CONFIDENCE_FALLBACK,
        )
        return _MISSING_THREAT_INTEL_CONFIDENCE_FALLBACK

    return float(confidence)


def build_features(state: AgentState) -> dict[str, float]:
    """
    Turns upstream agent outputs (ThreatIntel, Mitre, real SIEM severity,
    real asset-criticality catalog lookup) into the flat numeric feature
    vector WeightedRiskModel expects. Each raw value here is on its own
    natural scale (not pre-normalized to 0-100) — WeightedRiskModel owns
    normalization, so this function stays a pure "read what upstream agents
    actually produced" step.
    """
    iocs = state.get("iocs", [])
    reputations = [i["reputation_score"] for i in iocs if i.get("reputation_score") is not None]

    siem_severity = _resolve_siem_severity(state)

    # XGBoost re-activation task: ioc_count/rag_document_count are
    # XgboostRiskModel's own two features WeightedRiskModel never needed —
    # both were simply never computed while WeightedRiskModel was the only
    # consumer. rag_result is populated by RagAgent, which runs before
    # MlRiskAgent in build_graph.py, so it's already available here exactly
    # like mitre_techniques/threat_intel_report are.
    rag_result = state.get("rag_result") or {}
    rag_document_count = len(rag_result.get("knowledge") or []) + len(rag_result.get("playbooks") or [])

    return {
        "ioc_count": float(len(iocs)),
        "ioc_avg_reputation": float(sum(reputations) / len(reputations)) if reputations else 0.0,
        "mitre_technique_count": float(len(state.get("mitre_techniques", []))),
        "rag_document_count": float(rag_document_count),
        "siem_severity_numeric": float(SEVERITY_NUMERIC[siem_severity]),
        "asset_criticality_numeric": _resolve_asset_criticality_numeric(state),
        "threat_intel_confidence": _resolve_threat_intel_confidence(state),
    }
