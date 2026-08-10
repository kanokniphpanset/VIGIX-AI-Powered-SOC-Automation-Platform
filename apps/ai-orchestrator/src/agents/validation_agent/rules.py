def validate(state: dict) -> tuple[bool, list[str]]:
    """
    Cross-checks upstream agent outputs for internal consistency.
    Returns (passed, notes). This is intentionally rule-based and transparent —
    an analyst can read validation_notes and understand exactly why a run was
    flagged, rather than trusting an opaque second LLM call to judge the first.
    """
    notes: list[str] = []
    passed = True

    risk_score = state.get("risk_score")
    severity_prediction = state.get("severity_prediction")
    confidence_score = state.get("confidence_score", 0)

    # 1. Risk score and severity label must agree
    expected_severity_for_score = (
        "critical" if risk_score >= 75 else "high" if risk_score >= 50 else "medium" if risk_score >= 25 else "low"
    ) if risk_score is not None else None

    if expected_severity_for_score and expected_severity_for_score != severity_prediction:
        passed = False
        notes.append(
            f"Risk score {risk_score} implies '{expected_severity_for_score}' but "
            f"MlRiskAgent labeled it '{severity_prediction}'"
        )

    # 2. Low confidence with high severity is suspicious — flag for human review
    if severity_prediction in ("high", "critical") and confidence_score < 0.5:
        notes.append(
            f"Severity '{severity_prediction}' called with low confidence "
            f"({confidence_score}) — recommend human review"
        )

    # 3. MITRE techniques should have reasonable confidence to be trusted
    weak_techniques = [t for t in state.get("mitre_techniques", []) if t.get("confidence", 0) < 0.4]
    if weak_techniques:
        notes.append(f"{len(weak_techniques)} MITRE technique match(es) below confidence threshold")

    # 4. IOCs with no reputation data can't be cross-checked against threat intel
    unverified_iocs = [i for i in state.get("iocs", []) if i.get("reputation_score") is None]
    if unverified_iocs and len(unverified_iocs) == len(state.get("iocs", [])) and state.get("iocs"):
        notes.append("No IOC could be enriched with reputation data (threat intel sources unreachable or unconfigured)")

    if not notes:
        notes.append("All checks passed")

    return passed, notes
