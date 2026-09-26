from .provider_interface import IRiskModel, RiskPrediction

# Phase 12: named so database.py (writing risk_scores.model_version) and
# run_pipeline.py (the orchestrator-callback payload, for audit logging)
# both reference the same value instead of duplicating the literal string —
# same convention xgboost_provider.MODEL_VERSION used.
MODEL_VERSION = "weighted-explainable-v1"

# XGBoost re-activation task: this is now the FALLBACK model, used only if
# XgboostRiskModel (xgboost_provider.py, MlRiskAgent's primary model) raises
# during init/predict — see ml_risk_agent/agent.py. Kept as the fallback
# specifically because of what makes it different from a tree ensemble:
# no training step, no synthetic bootstrap data, and each weight below is a
# direct answer to "why is this alert an 87" — risk_score is exactly the
# weighted sum of the five components, nothing hidden.
#
# Must sum to 1.0 — see the assert below.
FEATURE_WEIGHTS: dict[str, float] = {
    "severity": 0.30,
    "threat_intel": 0.25,
    "mitre": 0.20,
    "asset_criticality": 0.15,
    "confidence": 0.10,
}
assert abs(sum(FEATURE_WEIGHTS.values()) - 1.0) < 1e-9, "FEATURE_WEIGHTS must sum to 1.0"

# A alert with 5+ distinct MITRE techniques matched is treated as maximal
# technique-coverage risk (100) — chosen as a simple, auditable cap rather
# than a compound formula, since transparency was the explicit design goal.
_MITRE_TECHNIQUES_FOR_MAX_SCORE = 5.0


def _severity_component(features: dict[str, float]) -> float:
    """siem_severity_numeric is 1-4 (low..critical) -> 25-100."""
    return features.get("siem_severity_numeric", 1.0) * 25.0


def _threat_intel_component(features: dict[str, float]) -> float:
    """ioc_avg_reputation is already 0-100 (ThreatIntelAgent's own threat_score scale)."""
    return max(0.0, min(100.0, features.get("ioc_avg_reputation", 0.0)))


def _mitre_component(features: dict[str, float]) -> float:
    """mitre_technique_count (raw count) -> 0-100, capped at _MITRE_TECHNIQUES_FOR_MAX_SCORE."""
    count = features.get("mitre_technique_count", 0.0)
    return min(100.0, (count / _MITRE_TECHNIQUES_FOR_MAX_SCORE) * 100.0)


def _asset_criticality_component(features: dict[str, float]) -> float:
    """asset_criticality_numeric is already 25-100 (feature_engineering.py's ASSET_CRITICALITY_NUMERIC)."""
    return features.get("asset_criticality_numeric", 75.0)


def _confidence_component(features: dict[str, float]) -> float:
    """threat_intel_confidence is 0-1 (ThreatIntelAgent's own overall_confidence) -> 0-100."""
    return max(0.0, min(1.0, features.get("threat_intel_confidence", 0.5))) * 100.0


_COMPONENT_FNS = {
    "severity": _severity_component,
    "threat_intel": _threat_intel_component,
    "mitre": _mitre_component,
    "asset_criticality": _asset_criticality_component,
    "confidence": _confidence_component,
}


class WeightedRiskModel(IRiskModel):
    """
    Transparent, auditable risk scoring — no training step, no synthetic
    bootstrap data, nothing that can't be recomputed by hand from the
    numbers in `predict()`'s own trace.
    """

    def predict(self, features: dict[str, float]) -> RiskPrediction:
        components = {name: fn(features) for name, fn in _COMPONENT_FNS.items()}
        weighted = {name: components[name] * FEATURE_WEIGHTS[name] for name in FEATURE_WEIGHTS}

        score = max(0.0, min(100.0, sum(weighted.values())))

        if score >= 75:
            severity = "critical"
        elif score >= 50:
            severity = "high"
        elif score >= 25:
            severity = "medium"
        else:
            severity = "low"

        confidence = round(components["confidence"] / 100.0, 2)

        return {"risk_score": round(score, 2), "severity_prediction": severity, "confidence_score": confidence}

    def explain(self, features: dict[str, float]) -> str:
        """
        Human-readable breakdown of the last predict() call's math —
        `ml_risk_agent/agent.py` puts this straight into the pipeline
        trace, so "why is this alert an 87" is answerable by reading a
        single log line / persisted trace entry, not by reverse-engineering
        a model.
        """
        components = {name: fn(features) for name, fn in _COMPONENT_FNS.items()}
        parts = [f"{name}={components[name]:.1f}*{FEATURE_WEIGHTS[name]:.2f}={components[name] * FEATURE_WEIGHTS[name]:.1f}" for name in FEATURE_WEIGHTS]
        return " + ".join(parts)
