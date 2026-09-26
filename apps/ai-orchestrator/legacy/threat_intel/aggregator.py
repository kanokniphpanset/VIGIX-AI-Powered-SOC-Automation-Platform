"""
Aggregation — builds a single IOC's ThreatIntelData from its provider
results, and an overall ThreatIntelReport across every IOC in an alert.
"""

from __future__ import annotations

from .scoring import score_indicator
from .types import (
    IocType,
    RiskLevel,
    ThreatIntelData,
    ThreatIntelProviderResult,
    ThreatIntelReport,
    Verdict,
)


def build_threat_intel_data(
    indicator: str,
    ioc_type: IocType,
    providers: list[ThreatIntelProviderResult],
    analyzed_at: str,
    duration_ms: int,
) -> ThreatIntelData:
    (
        score,
        verdict,
        risk_level,
        confidence,
        explanation,
        categories,
        malware_family,
        threat_actors,
        campaigns,
    ) = score_indicator(providers)

    queried_sources = [p.name for p in providers if p.status.value == "SUCCESS"]

    return ThreatIntelData(
        indicator=indicator,
        type=ioc_type,
        verdict=verdict,
        risk_level=risk_level,
        confidence=confidence,
        threat_score=score,
        malicious=verdict == Verdict.MALICIOUS,
        suspicious=verdict == Verdict.SUSPICIOUS,
        providers=providers,
        categories=categories,
        malware_family=malware_family,
        threat_actors=threat_actors,
        campaigns=campaigns,
        sources=queried_sources,
        explanation=explanation,
        analyzed_at=analyzed_at,
        duration_ms=duration_ms,
    )


_REPORT_RISK_ORDER = [RiskLevel.UNKNOWN, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]


def build_report(
    indicators: list[ThreatIntelData],
    analyzed_at: str,
    duration_ms: int,
) -> ThreatIntelReport:
    total = len(indicators)
    malicious = [i for i in indicators if i.verdict == Verdict.MALICIOUS]
    suspicious = [i for i in indicators if i.verdict == Verdict.SUSPICIOUS]
    clean = [i for i in indicators if i.verdict == Verdict.CLEAN]
    unknown = [i for i in indicators if i.verdict == Verdict.UNKNOWN]

    summary = {
        "total": total,
        "malicious": len(malicious),
        "suspicious": len(suspicious),
        "clean": len(clean),
        "unknown": len(unknown),
    }

    scored = [i for i in indicators if i.verdict != Verdict.UNKNOWN]
    highest_risk = max(scored, key=lambda i: i.threat_score, default=None)

    all_sources = sorted({s for i in indicators for s in i.sources})

    if not indicators:
        overall_risk_level = RiskLevel.UNKNOWN
    elif malicious:
        overall_risk_level = max((i.risk_level for i in malicious), key=_REPORT_RISK_ORDER.index)
    elif suspicious:
        overall_risk_level = max((i.risk_level for i in suspicious), key=_REPORT_RISK_ORDER.index)
    elif clean:
        overall_risk_level = RiskLevel.LOW
    else:
        overall_risk_level = RiskLevel.UNKNOWN

    overall_confidence = round(sum(i.confidence for i in scored) / len(scored), 2) if scored else 0.0

    key_findings: list[str] = []
    if not indicators:
        key_findings.append("No IOCs were extracted from this alert.")
    else:
        key_findings.append(
            f"Analyzed {total} indicator(s): {len(malicious)} malicious, {len(suspicious)} suspicious, "
            f"{len(clean)} clean, {len(unknown)} unknown."
        )
        if highest_risk:
            key_findings.append(
                f"Highest-risk indicator: {highest_risk.indicator} ({highest_risk.type.value}) — "
                f"{highest_risk.verdict.value}, score {highest_risk.threat_score:.0f}/100."
            )
        if unknown and len(unknown) == total:
            key_findings.append(
                "No indicator could be enriched — all configured threat intelligence providers "
                "were unavailable or none are configured. This is not evidence of a clean alert."
            )
        if all_sources:
            key_findings.append(f"Provider coverage: {', '.join(all_sources)}.")

    return ThreatIntelReport(
        indicators=indicators,
        summary=summary,
        overall_risk_level=overall_risk_level,
        overall_confidence=overall_confidence,
        key_findings=key_findings,
        analyzed_at=analyzed_at,
        duration_ms=duration_ms,
        highest_risk_indicator=highest_risk,
    )
