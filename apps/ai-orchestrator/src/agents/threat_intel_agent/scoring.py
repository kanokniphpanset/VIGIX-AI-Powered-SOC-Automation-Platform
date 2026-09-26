"""
ThreatScoreService — turns a set of per-provider results for a single IOC
into an explainable threat score, verdict, risk level, and overall pipeline
status.

Pipeline: Provider evidence -> weighting -> threat score -> risk level ->
verdict, plus a separate pipeline_status_for() covering spec section 9's
partial-failure rules. Every point added to the score is paired with a
human-readable explanation string, so `ThreatIntelData.explanation` is
always a faithful, literal audit trail of how the score was built — never
an opaque number.

Deterministic verdict rules (spec section 12), enforced here and nowhere
else — an LLM never reasons over this data to produce or override a verdict:
  * NO_MATCH (from every provider that answered) != BENIGN — it means
    "nobody has ever flagged this," not "this was checked and found clean."
    Only a provider that actually returned SUCCESS (a real, data-bearing
    response) can produce a BENIGN verdict.
  * A provider being unavailable (FAILED/TIMEOUT/RATE_LIMITED/
    NOT_CONFIGURED/NOT_SUPPORTED) never contributes to BENIGN either.
  * An API failure never contributes to MALICIOUS — only a provider that
    actually flagged the indicator does.

Kept as pure functions (no I/O) so it's trivially unit-testable.
"""

from __future__ import annotations

from .types import PipelineStatus, ProviderStatus, RiskLevel, ThreatIntelProviderResult, Verdict

# Base weight per provider — reflects how much signal a positive detection
# from that source is worth. Falls back to _DEFAULT_WEIGHT for any provider
# not listed, so scoring never breaks when a new provider is plugged in.
_PROVIDER_WEIGHTS = {
    "virustotal": 40,
    "abuseipdb": 30,
    "misp": 25,
    "otx": 15,
}
_DEFAULT_WEIGHT = 15

_MALWARE_FAMILY_BONUS = 20
_THREAT_ACTOR_BONUS = 15
_CAMPAIGN_BONUS = 10
_CATEGORY_BONUS = 10

_RISK_THRESHOLDS = (
    (80, RiskLevel.CRITICAL),
    (50, RiskLevel.HIGH),
    (20, RiskLevel.MEDIUM),
    (0, RiskLevel.LOW),
)

# A provider actually answered (whether or not it had a hit) — these two
# statuses are what "the provider was successfully queried" means
# throughout this module and result_contract.py.
_ANSWERED_STATUSES = {ProviderStatus.SUCCESS, ProviderStatus.NO_MATCH}


def _risk_level_for_score(score: float) -> RiskLevel:
    for threshold, level in _RISK_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def pipeline_status_for(providers: list[ThreatIntelProviderResult]) -> PipelineStatus:
    """
    Spec section 9. A provider counts as "answered" if it reached SUCCESS or
    NO_MATCH (it was actually queried and gave a real answer); anything else
    (FAILED/TIMEOUT/RATE_LIMITED/NOT_CONFIGURED/NOT_SUPPORTED/
    INVALID_INDICATOR) counts as "did not contribute."
      - every configured/attempted provider answered  -> SUCCESS
      - some answered, some didn't                     -> PARTIAL_SUCCESS
      - none answered at all                            -> FAILED
    """
    if not providers:
        return PipelineStatus.FAILED
    answered = sum(1 for p in providers if p.status in _ANSWERED_STATUSES)
    if answered == 0:
        return PipelineStatus.FAILED
    if answered == len(providers):
        return PipelineStatus.SUCCESS
    return PipelineStatus.PARTIAL_SUCCESS


def score_indicator(
    providers: list[ThreatIntelProviderResult],
) -> tuple[float, Verdict, RiskLevel, float, list[str], list[str], str | None, list[str], list[str]]:
    """
    Returns (threat_score, verdict, risk_level, confidence, explanation,
    categories, malware_family, threat_actors, campaigns).
    """
    # A SUCCESS status alone isn't enough to ground a verdict — it means the
    # provider was reached and answered, but if that answer carried zero
    # evidence there is nothing to base a claim on. This is the top-level
    # "NO EVIDENCE -> NO CLAIM" rule applied at the scoring layer, not just
    # to provider reachability: SUCCESS-with-no-evidence is treated the same
    # as NO_MATCH below, never as a basis for BENIGN. (Every real provider
    # in this codebase always attaches evidence on a genuine SUCCESS — see
    # e.g. virustotal_provider.py's DETECTION_STATS entry — so this only
    # matters for a deliberately evidence-less result.)
    successful = [p for p in providers if p.status == ProviderStatus.SUCCESS and p.evidence]
    no_match = [p for p in providers if p.status == ProviderStatus.NO_MATCH or (p.status == ProviderStatus.SUCCESS and not p.evidence)]
    explanation: list[str] = []

    if not successful:
        # Either nothing answered at all, or everything that did was a
        # NO_MATCH (or an evidence-less SUCCESS) — in both cases there is no
        # positive evidence to reason over, so the verdict is UNKNOWN, never
        # BENIGN.
        if no_match:
            explanation.append(
                f"No provider has any record of this indicator ({', '.join(p.name for p in no_match)}) "
                "— absence of a hit is not evidence of safety."
            )
        else:
            reasons = sorted({p.status.value for p in providers}) or ["NO_PROVIDERS_CONFIGURED"]
            explanation.append(f"No threat intelligence data available (provider status: {', '.join(reasons)}).")
        return 0.0, Verdict.UNKNOWN, RiskLevel.UNKNOWN, 0.0, explanation, [], None, [], []

    score = 0.0
    malicious_providers: list[str] = []
    suspicious_providers: list[str] = []
    clean_providers: list[str] = []

    for result in successful:
        weight = _PROVIDER_WEIGHTS.get(result.name, _DEFAULT_WEIGHT)
        if result.malicious:
            contribution = weight * max(result.confidence, 0.5)
            score += contribution
            malicious_providers.append(result.name)
            explanation.append(
                f"+{contribution:.0f} {result.name} flagged indicator as malicious "
                f"(confidence {result.confidence:.2f}, {result.detections}/{result.total_checks or result.detections or 1} detections)"
            )
        elif result.suspicious:
            contribution = weight * 0.5 * max(result.confidence, 0.3)
            score += contribution
            suspicious_providers.append(result.name)
            explanation.append(
                f"+{contribution:.0f} {result.name} flagged indicator as suspicious "
                f"(confidence {result.confidence:.2f})"
            )
        else:
            clean_providers.append(result.name)

    categories = sorted({c for p in successful for c in p.categories})
    malware_families = sorted({p.malware_family for p in successful if p.malware_family})
    threat_actors = sorted({a for p in successful for a in p.threat_actors})
    campaigns = sorted({c for p in successful for c in p.campaigns})

    if malware_families:
        score += _MALWARE_FAMILY_BONUS
        explanation.append(f"+{_MALWARE_FAMILY_BONUS} known malware family: {', '.join(malware_families)}")
    if threat_actors:
        score += _THREAT_ACTOR_BONUS
        explanation.append(f"+{_THREAT_ACTOR_BONUS} associated threat actor(s): {', '.join(threat_actors)}")
    if campaigns:
        score += _CAMPAIGN_BONUS
        explanation.append(f"+{_CAMPAIGN_BONUS} associated campaign(s): {', '.join(campaigns)}")
    if categories:
        score += _CATEGORY_BONUS
        explanation.append(f"+{_CATEGORY_BONUS} known threat categor{'y' if len(categories) == 1 else 'ies'}: {', '.join(categories)}")

    score = max(0.0, min(100.0, score))

    if malicious_providers and clean_providers:
        explanation.append(
            f"Provider disagreement: {', '.join(malicious_providers)} malicious vs. "
            f"{', '.join(clean_providers)} clean — verdict based on cumulative weighted evidence."
        )

    if malicious_providers or score >= 50:
        verdict = Verdict.MALICIOUS
    elif suspicious_providers or score >= 20:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.BENIGN
        explanation.append(
            f"No malicious evidence found across {len(successful)} provider(s) "
            f"({', '.join(p.name for p in successful)})."
        )

    risk_level = _risk_level_for_score(score)

    avg_confidence = sum(p.confidence for p in successful) / len(successful)
    agreement_adjustment = 0.0
    if malicious_providers and clean_providers:
        agreement_adjustment = -0.15
    elif len(successful) > 1 and not (malicious_providers and clean_providers):
        agreement_adjustment = 0.1
    confidence = max(0.0, min(1.0, avg_confidence + agreement_adjustment))

    explanation.append(f"Final threat score: {score:.0f}/100 ({risk_level.value}).")

    return (
        round(score, 1),
        verdict,
        risk_level,
        round(confidence, 2),
        explanation,
        categories,
        malware_families[0] if malware_families else None,
        threat_actors,
        campaigns,
    )
