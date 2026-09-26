"""
IOC extraction must treat the reporting endpoint's identity as metadata, not as a threat IOC.
Pure unit tests (no network). Run from apps/ai-orchestrator:
  .venv/Scripts/python.exe -m pytest tests/threat_intel
"""
from __future__ import annotations

from src.agents.threat_intel_agent.ioc_extractor import endpoint_identity, extract_from_alert
from src.agents.threat_intel_agent.types import IocType
from src.ingestion.agent_state_builder import flatten_alert_text

# Shape of a real Wazuh sshd brute-force alert (values are generic, not lab-specific).
WAZUH_ALERT = {
    "id": "1700000000.1",
    "rule": {"id": "5712", "level": 10, "description": "sshd: brute force trying to get access to the system. Non existent user."},
    "agent": {"id": "001", "name": "web-01", "ip": "10.20.30.40"},
    "manager": {"name": "wazuh.manager"},
    "predecoder": {"hostname": "web-01", "program_name": "sshd"},
    "decoder": {"name": "sshd"},
    "data": {"srcip": "198.51.100.23", "srcuser": "admin"},
    "full_log": "Sep 24 07:04:19 web-01 sshd[8166]: Failed password for invalid user admin from 198.51.100.23 port 56596 ssh2",
    "location": "/var/log/auth.log",
}


def _extracted(alert: dict) -> set[tuple[str, str]]:
    return {(e.type.value if hasattr(e.type, "value") else str(e.type), e.value) for e in extract_from_alert(alert, flatten_alert_text(alert))}


def test_agent_name_is_not_an_ioc():
    values = {v.lower() for _, v in _extracted(WAZUH_ALERT)}
    assert "web-01" not in values  # agent.name / predecoder.hostname
    assert "wazuh.manager" not in values  # manager.name


def test_agent_ip_is_not_an_ioc():
    values = {v for _, v in _extracted(WAZUH_ALERT)}
    assert "10.20.30.40" not in values  # neither from agent.ip nor from the flattened text


def test_real_attacker_ip_remains_an_ioc():
    iocs = extract_from_alert(WAZUH_ALERT, flatten_alert_text(WAZUH_ALERT))
    assert any(e.value == "198.51.100.23" and e.type == IocType.IPV4 for e in iocs)


def test_other_indicator_types_still_extracted():
    alert = {
        **WAZUH_ALERT,
        "data": {
            "srcip": "198.51.100.23",
            "url": "http://evil.example.com/stage2.bin",
            "domain": "evil.example.com",
            "sha256": "a" * 64,
            "md5": "b" * 32,
        },
    }
    types = {t for t, _ in _extracted(alert)}
    values = {v for _, v in _extracted(alert)}
    assert {"198.51.100.23", "http://evil.example.com/stage2.bin", "evil.example.com", "a" * 64, "b" * 32} <= values
    assert {"IPV4", "URL", "DOMAIN", "SHA256", "MD5"} <= {t.upper() for t in types}


def test_endpoint_identity_values_and_no_identity_means_no_filtering():
    assert endpoint_identity(WAZUH_ALERT) == {"web-01", "10.20.30.40", "wazuh.manager"}
    assert endpoint_identity({"data": {"srcip": "198.51.100.23"}}) == set()
    assert endpoint_identity(None) == set()
    # A payload without endpoint metadata keeps every extracted value.
    plain = {"data": {"src_ip": "10.20.30.40"}}
    assert "10.20.30.40" in {v for _, v in _extracted(plain)}
