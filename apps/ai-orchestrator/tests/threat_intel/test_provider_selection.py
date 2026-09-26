"""
THREAT_INTEL_PROVIDERS decides which providers the ThreatIntelAgent queries. A provider left out is never called and
never reported (no NOT_CONFIGURED noise); the default keeps all four. Pure unit tests (no network). Run from
apps/ai-orchestrator:
  .venv/Scripts/python.exe -m pytest tests/threat_intel
"""
from __future__ import annotations

from src.agents.threat_intel_agent import service
from src.agents.threat_intel_agent.service import ThreatIntelligenceService, enabled_provider_names


def test_default_keeps_every_provider_in_order():
    assert enabled_provider_names("virustotal,otx,misp,abuseipdb") == ["virustotal", "otx", "misp", "abuseipdb"]


def test_only_misp():
    assert enabled_provider_names("misp") == ["misp"]


def test_names_are_trimmed_case_insensitive_deduplicated_and_unknown_ones_ignored():
    assert enabled_provider_names(" MISP , misp, shodan ,, otx") == ["misp", "otx"]


def test_empty_setting_queries_no_provider():
    assert enabled_provider_names("") == []


def test_service_builds_only_the_enabled_providers(monkeypatch):
    monkeypatch.setattr(service.settings, "threat_intel_providers", "misp")
    svc = ThreatIntelligenceService(cache=object(), rate_limiters=object())
    assert [p.name for p in svc.providers] == ["misp"]
