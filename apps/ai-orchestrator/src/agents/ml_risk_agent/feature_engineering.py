from src.graph.state import AgentState

SEVERITY_NUMERIC = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def build_features(state: AgentState) -> dict[f"str", float]:
    """
    Turns upstream agent outputs (ThreatIntel, Mitre, Rag, raw SIEM severity)
    into the flat numeric feature vector XgboostRiskModel expects.
    """
    iocs = state.get("iocs", [])
    reputations = [i["reputation_score"] for i in iocs if i.get("reputation_score") is not None]

    raw_alert = state.get("raw_alert", {})
    siem_severity = str(raw_alert.get("severity", "low")).lower()

    return {
        "ioc_count": float(len(iocs)),
        "ioc_avg_reputation": float(sum(reputations) / len(reputations)) if reputations else 0.0,
        "mitre_technique_count": float(len(state.get("mitre_techniques", []))),
        "rag_similar_incident_count": float(
            len([m for m in state.get("rag_matches", []) if m.get("kind") == "similar_incident"])
        ),
        "siem_severity_numeric": float(SEVERITY_NUMERIC.get(siem_severity, 1)),
    }
