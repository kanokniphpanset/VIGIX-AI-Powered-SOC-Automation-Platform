"""Tests for the explainable threat-scoring model."""

import pytest

from src.agents.threat_intel_agent.scoring import score_indicator
from src.agents.threat_intel_agent.types import (
    IocType,
    ProviderStatus,
    RiskLevel,
    ThreatIntelProviderResult,
    Verdict,
)


def _make(name, status=ProviderStatus.SUCCESS, malicious=False, suspicious=False,
          confidence=0.5, reputation=None, categories=None, malware_family=None,
          threat_actors=None, campaigns=None, detections=0, total_checks=0):
    return ThreatIntelProviderResult(
        name=name,
        status=status,
        malicious=malicious,
        suspicious=suspicious,
        confidence=confidence,
        reputation=reputation,
        categories=categories or [],
        malware_family=malware_family,
        threat_actors=threat_actors or [],
        campaigns=campaigns or [],
        detections=detections,
        total_checks=total_checks,
    )


# ── UNKNOWN: no successful providers ─────────────────────────────────────────

def test_no_providers_returns_unknown():
    score, verdict, risk, confidence, explanation, *_ = score_indicator([])
    assert verdict == Verdict.UNKNOWN
    assert risk == RiskLevel.UNKNOWN
    assert score == 0.0
    assert confidence == 0.0
    assert len(explanation) >= 1


def test_all_disabled_providers_returns_unknown():
    providers = [
        _make("VirusTotal", status=ProviderStatus.DISABLED),
        _make("AbuseIPDB", status=ProviderStatus.DISABLED),
    ]
    score, verdict, risk, *_ = score_indicator(providers)
    assert verdict == Verdict.UNKNOWN
    assert risk == RiskLevel.UNKNOWN
    assert score == 0.0


def test_all_failed_providers_returns_unknown():
    providers = [
        _make("VirusTotal", status=ProviderStatus.FAILED),
    ]
    score, verdict, *_ = score_indicator(providers)
    assert verdict == Verdict.UNKNOWN


# ── CLEAN verdict ─────────────────────────────────────────────────────────────

def test_single_clean_provider_returns_clean():
    providers = [_make("VirusTotal", malicious=False, suspicious=False, confidence=0.9)]
    score, verdict, risk, confidence, explanation, *_ = score_indicator(providers)
    assert verdict == Verdict.CLEAN
    assert risk == RiskLevel.LOW
    assert score == 0.0
    # Must explicitly state why it's clean
    assert any("No malicious evidence" in e for e in explanation)


def test_two_clean_providers_returns_clean():
    providers = [
        _make("VirusTotal", malicious=False, confidence=0.85),
        _make("AbuseIPDB", malicious=False, confidence=0.9),
    ]
    score, verdict, *_ = score_indicator(providers)
    assert verdict == Verdict.CLEAN


# ── SUSPICIOUS verdict ───────────────────────────────────────────────────────

def test_suspicious_provider_returns_suspicious():
    providers = [_make("VirusTotal", suspicious=True, confidence=0.6)]
    score, verdict, risk, *_ = score_indicator(providers)
    assert verdict == Verdict.SUSPICIOUS
    assert score > 0
    assert risk in (RiskLevel.LOW, RiskLevel.MEDIUM)


# ── MALICIOUS verdict ────────────────────────────────────────────────────────

def test_single_malicious_provider_returns_malicious():
    providers = [_make("VirusTotal", malicious=True, confidence=0.9, detections=45, total_checks=70)]
    score, verdict, risk, *_ = score_indicator(providers)
    assert verdict == Verdict.MALICIOUS
    assert score > 0
    assert risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_high_confidence_malicious_vt_scores_high():
    providers = [_make("VirusTotal", malicious=True, confidence=0.9, detections=60, total_checks=70)]
    score, verdict, risk, *_ = score_indicator(providers)
    assert verdict == Verdict.MALICIOUS
    assert score >= 36  # 40 * 0.9


def test_malware_family_bonus_applied():
    providers = [_make("VirusTotal", malicious=True, confidence=0.9, malware_family="Emotet")]
    score_without_bonus = 40 * 0.9
    score, verdict, *_ = score_indicator(providers)
    assert score > score_without_bonus  # bonus applied
    assert verdict == Verdict.MALICIOUS


def test_threat_actor_bonus_applied():
    providers = [_make("VirusTotal", malicious=True, confidence=0.5, threat_actors=["APT28"])]
    base_score = 40 * 0.5
    score, *_ = score_indicator(providers)
    assert score > base_score


def test_campaign_bonus_applied():
    providers = [_make("VirusTotal", malicious=True, confidence=0.5, campaigns=["SolarWinds"])]
    score, *_ = score_indicator(providers)
    assert score > 40 * 0.5


def test_category_bonus_applied():
    providers = [_make("VirusTotal", malicious=True, confidence=0.5, categories=["trojan"])]
    score, *_ = score_indicator(providers)
    assert score > 40 * 0.5


# ── Risk level banding ────────────────────────────────────────────────────────

def test_score_below_20_is_low():
    providers = [_make("OTX", suspicious=True, confidence=0.3)]
    score, _, risk, *_ = score_indicator(providers)
    if score < 20:
        assert risk == RiskLevel.LOW


def test_score_80_plus_is_critical():
    providers = [
        _make("VirusTotal", malicious=True, confidence=1.0, malware_family="Emotet",
              threat_actors=["APT28"], campaigns=["op1"], categories=["malware"]),
        _make("AbuseIPDB", malicious=True, confidence=1.0),
    ]
    score, _, risk, *_ = score_indicator(providers)
    assert score >= 80
    assert risk == RiskLevel.CRITICAL


# ── Multi-provider ────────────────────────────────────────────────────────────

def test_two_malicious_providers_score_higher_than_one():
    single = [_make("VirusTotal", malicious=True, confidence=0.8)]
    both = [
        _make("VirusTotal", malicious=True, confidence=0.8),
        _make("AbuseIPDB", malicious=True, confidence=0.8),
    ]
    score_single, *_ = score_indicator(single)
    score_both, *_ = score_indicator(both)
    assert score_both > score_single


def test_provider_disagreement_explanation_present():
    providers = [
        _make("VirusTotal", malicious=True, confidence=0.6),
        _make("AbuseIPDB", malicious=False, confidence=0.9),
    ]
    score, verdict, _, _, explanation, *_ = score_indicator(providers)
    assert verdict == Verdict.MALICIOUS  # VT malicious wins
    assert any("disagreement" in e.lower() for e in explanation)


def test_provider_disagreement_confidence_reduced():
    no_disagreement = [_make("VirusTotal", malicious=True, confidence=0.8)]
    with_disagreement = [
        _make("VirusTotal", malicious=True, confidence=0.8),
        _make("AbuseIPDB", malicious=False, confidence=0.8),
    ]
    _, _, _, conf_no, *_ = score_indicator(no_disagreement)
    _, _, _, conf_dis, *_ = score_indicator(with_disagreement)
    assert conf_dis < conf_no


def test_explanation_contains_final_score_line():
    providers = [_make("VirusTotal", malicious=True, confidence=0.9)]
    _, _, _, _, explanation, *_ = score_indicator(providers)
    assert any("Final threat score" in e for e in explanation)


def test_score_clamped_to_100():
    providers = [
        _make("VirusTotal", malicious=True, confidence=1.0, malware_family="X",
              threat_actors=["APT1"], campaigns=["c1"], categories=["malware"]),
        _make("AbuseIPDB", malicious=True, confidence=1.0),
        _make("MISP", malicious=True, confidence=1.0),
        _make("OTX", malicious=True, confidence=1.0),
    ]
    score, *_ = score_indicator(providers)
    assert score <= 100.0
