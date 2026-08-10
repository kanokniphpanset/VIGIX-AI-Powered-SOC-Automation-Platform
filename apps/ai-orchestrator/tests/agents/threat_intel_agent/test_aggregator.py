"""Tests for build_threat_intel_data and build_report aggregation."""

import pytest

from src.agents.threat_intel_agent.aggregator import build_report, build_threat_intel_data
from src.agents.threat_intel_agent.types import (
    IocType,
    ProviderStatus,
    RiskLevel,
    ThreatIntelData,
    ThreatIntelProviderResult,
    Verdict,
)


def _provider(name, status=ProviderStatus.SUCCESS, malicious=False, suspicious=False,
              confidence=0.5, categories=None):
    return ThreatIntelProviderResult(
        name=name, status=status, malicious=malicious, suspicious=suspicious,
        confidence=confidence, categories=categories or [],
    )


def _build(indicator="1.2.3.4", ioc_type=IocType.IPV4, providers=None):
    if providers is None:
        providers = []
    return build_threat_intel_data(indicator, ioc_type, providers, "2026-01-01T00:00:00+00:00", 100)


# ── build_threat_intel_data ───────────────────────────────────────────────────

def test_all_disabled_providers_gives_unknown():
    data = _build(providers=[_provider("VirusTotal", status=ProviderStatus.DISABLED)])
    assert data.verdict == Verdict.UNKNOWN
    assert data.risk_level == RiskLevel.UNKNOWN
    assert data.malicious is False
    assert data.suspicious is False


def test_malicious_provider_gives_malicious_verdict():
    data = _build(providers=[_provider("VirusTotal", malicious=True, confidence=0.9)])
    assert data.verdict == Verdict.MALICIOUS
    assert data.malicious is True
    assert data.suspicious is False


def test_suspicious_only_provider_gives_suspicious_verdict():
    data = _build(providers=[_provider("VirusTotal", suspicious=True, confidence=0.6)])
    assert data.verdict == Verdict.SUSPICIOUS
    assert data.suspicious is True
    assert data.malicious is False


def test_clean_provider_gives_clean_verdict():
    data = _build(providers=[_provider("VirusTotal", malicious=False, confidence=0.9)])
    assert data.verdict == Verdict.CLEAN
    assert data.malicious is False


def test_sources_lists_only_successful_providers():
    data = _build(providers=[
        _provider("VirusTotal", malicious=True),
        _provider("AbuseIPDB", status=ProviderStatus.DISABLED),
    ])
    assert "VirusTotal" in data.sources
    assert "AbuseIPDB" not in data.sources


def test_threat_score_positive_for_malicious():
    data = _build(providers=[_provider("VirusTotal", malicious=True, confidence=0.9)])
    assert data.threat_score > 0


def test_explanation_is_non_empty():
    data = _build(providers=[_provider("VirusTotal", malicious=True, confidence=0.9)])
    assert len(data.explanation) >= 1


def test_to_dict_returns_expected_keys():
    data = _build(providers=[_provider("VirusTotal", malicious=True, confidence=0.5)])
    d = data.to_dict()
    for key in ("indicator", "type", "verdict", "riskLevel", "threatScore", "confidence",
                "malicious", "suspicious", "providers", "explanation", "analyzedAt"):
        assert key in d, f"Missing key: {key}"


# ── build_report ──────────────────────────────────────────────────────────────

def _data(indicator, verdict, score=50.0, risk=RiskLevel.HIGH):
    return ThreatIntelData(
        indicator=indicator,
        type=IocType.IPV4,
        verdict=verdict,
        risk_level=risk,
        confidence=0.8,
        threat_score=score,
        malicious=(verdict == Verdict.MALICIOUS),
        suspicious=(verdict == Verdict.SUSPICIOUS),
        providers=[],
        sources=["VirusTotal"] if verdict != Verdict.UNKNOWN else [],
        explanation=["test"],
        analyzed_at="2026-01-01T00:00:00+00:00",
        duration_ms=50,
    )


def test_report_summary_counts_correctly():
    indicators = [
        _data("1.1.1.1", Verdict.MALICIOUS),
        _data("2.2.2.2", Verdict.SUSPICIOUS, score=20.0, risk=RiskLevel.MEDIUM),
        _data("3.3.3.3", Verdict.CLEAN, score=0.0, risk=RiskLevel.LOW),
        _data("4.4.4.4", Verdict.UNKNOWN, score=0.0, risk=RiskLevel.UNKNOWN),
    ]
    report = build_report(indicators, "2026-01-01T00:00:00+00:00", 200)
    assert report.summary["total"] == 4
    assert report.summary["malicious"] == 1
    assert report.summary["suspicious"] == 1
    assert report.summary["clean"] == 1
    assert report.summary["unknown"] == 1


def test_report_overall_risk_from_malicious_indicators():
    indicators = [
        _data("1.1.1.1", Verdict.MALICIOUS, score=85.0, risk=RiskLevel.CRITICAL),
        _data("2.2.2.2", Verdict.CLEAN, score=0.0, risk=RiskLevel.LOW),
    ]
    report = build_report(indicators, "2026-01-01T00:00:00+00:00", 100)
    assert report.overall_risk_level == RiskLevel.CRITICAL


def test_report_overall_risk_unknown_when_all_unknown():
    indicators = [
        _data("1.1.1.1", Verdict.UNKNOWN, score=0.0, risk=RiskLevel.UNKNOWN),
    ]
    report = build_report(indicators, "2026-01-01T00:00:00+00:00", 100)
    assert report.overall_risk_level == RiskLevel.UNKNOWN


def test_report_highest_risk_indicator_selected():
    indicators = [
        _data("1.1.1.1", Verdict.MALICIOUS, score=60.0, risk=RiskLevel.HIGH),
        _data("2.2.2.2", Verdict.MALICIOUS, score=85.0, risk=RiskLevel.CRITICAL),
    ]
    report = build_report(indicators, "2026-01-01T00:00:00+00:00", 100)
    assert report.highest_risk_indicator is not None
    assert report.highest_risk_indicator.indicator == "2.2.2.2"


def test_report_key_findings_include_warning_when_all_unknown():
    indicators = [
        _data("1.1.1.1", Verdict.UNKNOWN, score=0.0, risk=RiskLevel.UNKNOWN),
        _data("2.2.2.2", Verdict.UNKNOWN, score=0.0, risk=RiskLevel.UNKNOWN),
    ]
    report = build_report(indicators, "2026-01-01T00:00:00+00:00", 100)
    warning_present = any("not evidence" in f.lower() for f in report.key_findings)
    assert warning_present, "Must warn that UNKNOWN is not the same as clean"


def test_report_empty_indicators():
    report = build_report([], "2026-01-01T00:00:00+00:00", 10)
    assert report.summary["total"] == 0
    assert report.overall_risk_level == RiskLevel.UNKNOWN
    assert report.highest_risk_indicator is None


def test_report_to_dict_keys():
    indicators = [_data("1.1.1.1", Verdict.MALICIOUS)]
    report = build_report(indicators, "2026-01-01T00:00:00+00:00", 100)
    d = report.to_dict()
    for key in ("indicators", "summary", "overallRiskLevel", "overallConfidence",
                "keyFindings", "analyzedAt", "durationMs"):
        assert key in d, f"Missing key: {key}"
