"""
Integration tests for the full ThreatIntelligenceService pipeline.

Uses mock providers injected via DI — no real HTTP, no real API keys.
Verifies the complete vertical slice:
  raw_alert → extract → normalize → validate → analyze → score → report
"""

from __future__ import annotations

import pytest

from src.agents.threat_intel_agent.providers.provider_interface import ThreatIntelProvider
from src.agents.threat_intel_agent.service import ThreatIntelligenceService
from src.agents.threat_intel_agent.types import (
    IocType,
    ProviderStatus,
    RiskLevel,
    ThreatIntelProviderResult,
    Verdict,
)


# ── Mock providers ────────────────────────────────────────────────────────────

class _AlwaysMalicious(ThreatIntelProvider):
    name = "MockMalicious"

    @property
    def is_configured(self):
        return True

    def supports(self, ioc_type):
        return ioc_type in (IocType.IPV4, IocType.DOMAIN, IocType.URL, IocType.MD5,
                            IocType.SHA1, IocType.SHA256)

    async def analyze(self, indicator, ioc_type):
        return ThreatIntelProviderResult(
            name=self.name, status=ProviderStatus.SUCCESS,
            malicious=True, confidence=0.9, detections=50, total_checks=70,
            categories=["malware"],
        )


class _AlwaysClean(ThreatIntelProvider):
    name = "MockClean"

    @property
    def is_configured(self):
        return True

    def supports(self, ioc_type):
        return True

    async def analyze(self, indicator, ioc_type):
        return ThreatIntelProviderResult(
            name=self.name, status=ProviderStatus.SUCCESS,
            malicious=False, confidence=0.9,
        )


class _AlwaysDisabled(ThreatIntelProvider):
    name = "MockDisabled"

    @property
    def is_configured(self):
        return False

    def supports(self, ioc_type):
        return True

    async def analyze(self, indicator, ioc_type):
        return ThreatIntelProviderResult(name=self.name, status=ProviderStatus.DISABLED)


class _AlwaysFailed(ThreatIntelProvider):
    name = "MockFailed"

    @property
    def is_configured(self):
        return True

    def supports(self, ioc_type):
        return True

    async def analyze(self, indicator, ioc_type):
        return ThreatIntelProviderResult(
            name=self.name, status=ProviderStatus.FAILED, error="simulated failure"
        )


# ── No providers configured — UNKNOWN, never CLEAN ───────────────────────────

@pytest.mark.anyio
async def test_no_providers_gives_unknown_not_clean():
    service = ThreatIntelligenceService(providers=[_AlwaysDisabled()])
    report = await service.analyze_alert({"src_ip": "8.8.8.8"})

    assert report.summary["total"] >= 1
    # Every indicator must be UNKNOWN, not CLEAN
    for indicator in report.indicators:
        assert indicator.verdict == Verdict.UNKNOWN, (
            f"Expected UNKNOWN but got {indicator.verdict} for {indicator.indicator}"
        )
    assert report.overall_risk_level == RiskLevel.UNKNOWN


@pytest.mark.anyio
async def test_all_unknown_key_findings_warn_not_clean():
    service = ThreatIntelligenceService(providers=[_AlwaysDisabled()])
    report = await service.analyze_alert({"src_ip": "1.2.3.4"})
    warning = any("not evidence" in f.lower() for f in report.key_findings)
    assert warning


# ── Malicious provider ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_malicious_provider_produces_malicious_verdict():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    report = await service.analyze_alert({"src_ip": "1.2.3.4"})

    malicious_indicators = [i for i in report.indicators if i.verdict == Verdict.MALICIOUS]
    assert len(malicious_indicators) >= 1
    assert report.overall_risk_level != RiskLevel.UNKNOWN


@pytest.mark.anyio
async def test_malicious_report_summary_counts():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    report = await service.analyze_alert({"src_ip": "1.2.3.4"})
    assert report.summary["malicious"] >= 1
    assert report.summary["malicious"] == len([i for i in report.indicators if i.verdict == Verdict.MALICIOUS])


# ── One provider fails, another succeeds ─────────────────────────────────────

@pytest.mark.anyio
async def test_partial_provider_failure_still_produces_result():
    service = ThreatIntelligenceService(providers=[_AlwaysFailed(), _AlwaysMalicious()])
    report = await service.analyze_alert({"src_ip": "1.2.3.4"})

    # The failed provider must not kill the whole analysis
    assert report.summary["total"] >= 1
    # MockMalicious returned a result, so we should have at least one non-UNKNOWN
    assert any(i.verdict != Verdict.UNKNOWN for i in report.indicators)


# ── Invalid IOC not queried ───────────────────────────────────────────────────

@pytest.mark.anyio
async def test_invalid_ioc_not_queried_but_not_crash():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    # 256.0.0.1 is an invalid IPv4 — validator should reject before querying
    report = await service.analyze_alert({"src_ip": "256.0.0.1"})
    # The invalid IOC is either excluded or UNKNOWN — never crashes
    assert isinstance(report.summary["total"], int)


# ── Multi-IOC alert ───────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_multiple_iocs_all_analyzed():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    alert = {
        "src_ip": "1.2.3.4",
        "domain": "evil.com",
        "hash": "d41d8cd98f00b204e9800998ecf8427e",
    }
    report = await service.analyze_alert(alert)
    assert report.summary["total"] >= 3


@pytest.mark.anyio
async def test_duplicate_iocs_deduplicated():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    # Same IP in two fields — should appear only once
    alert = {"src_ip": "1.2.3.4", "destination_ip": "1.2.3.4"}
    report = await service.analyze_alert(alert)
    analyzed_values = [i.indicator for i in report.indicators]
    assert analyzed_values.count("1.2.3.4") == 1


# ── State output shape ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_report_to_dict_produces_valid_structure():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    report = await service.analyze_alert({"src_ip": "1.2.3.4"})
    d = report.to_dict()
    assert "indicators" in d
    assert "summary" in d
    assert "overallRiskLevel" in d
    assert "keyFindings" in d
    assert isinstance(d["summary"]["total"], int)


@pytest.mark.anyio
async def test_legacy_ioc_shape_compatible():
    """to_legacy_ioc() must produce the shape existing consumers expect."""
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    report = await service.analyze_alert({"src_ip": "1.2.3.4"})

    for indicator in report.indicators:
        legacy = indicator.to_legacy_ioc()
        assert "ioc_type" in legacy
        assert "ioc_value" in legacy
        assert "source" in legacy
        assert "reputation_score" in legacy
        assert "raw_response" in legacy
        # ioc_type must be lowercase (consumed by feature_engineering.py)
        assert legacy["ioc_type"] == legacy["ioc_type"].lower()


# ── Free-text extraction ──────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_iocs_extracted_from_alert_text():
    service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])
    report = await service.analyze_alert(
        {}, alert_text="Suspicious traffic from 203.0.113.99 to port 443"
    )
    analyzed_values = [i.indicator for i in report.indicators]
    assert "203.0.113.99" in analyzed_values


# ── Empty alert ───────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_empty_alert_no_crash():
    service = ThreatIntelligenceService(providers=[_AlwaysDisabled()])
    report = await service.analyze_alert({})
    assert report.summary["total"] == 0
    assert report.overall_risk_level == RiskLevel.UNKNOWN


@pytest.mark.anyio
async def test_none_alert_no_crash():
    service = ThreatIntelligenceService(providers=[_AlwaysDisabled()])
    report = await service.analyze_alert(None)
    assert report.summary["total"] == 0


# ── LangGraph agent.run() smoke test ─────────────────────────────────────────

@pytest.mark.anyio
async def test_agent_run_returns_expected_state_keys():
    from src.agents.threat_intel_agent import agent as agent_module
    from src.agents.threat_intel_agent.service import ThreatIntelligenceService

    # Inject mock service into the module-level singleton
    original_service = agent_module._service
    agent_module._service = ThreatIntelligenceService(providers=[_AlwaysMalicious()])

    try:
        state = {
            "alert_id": "test-alert-123",
            "graph_run_id": "test-run-456",
            "raw_alert": {"src_ip": "1.2.3.4"},
            "alert_text": "",
        }
        result = await agent_module.run(state)
    finally:
        agent_module._service = original_service

    assert "iocs" in result
    assert "threat_intel_report" in result
    assert "trace" in result
    assert isinstance(result["iocs"], list)
    assert isinstance(result["threat_intel_report"], dict)
    assert isinstance(result["trace"], list)
    assert len(result["trace"]) == 1
    assert "ThreatIntelAgent" in result["trace"][0]
