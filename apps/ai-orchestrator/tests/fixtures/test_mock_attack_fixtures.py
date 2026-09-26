"""
Mock Wazuh attack fixtures (resources/mock-attacks/) — fixture-layer checks:

1. every case file validates against the case schema below;
2. every alert (and related alert) goes through the existing
   WazuhAlertNormalizer and ThreatIntel IOC extractor, and the expected
   host / MITRE / IOCs are actually recoverable from it;
3. every re-hunt round is self-consistent under the SAME matching rules
   the backend's WazuhIndexerAdapter.buildRehuntDsl applies, and the
   declared scenario / verification / final outcome follow from it.

Run from apps/ai-orchestrator:  .venv/Scripts/python.exe -m pytest tests/fixtures
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Literal

import pytest
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agents.threat_intel_agent.ioc_extractor import extract_from_alert
from src.ingestion.agent_state_builder import flatten_alert_text
from src.ingestion.alert_normalizer import normalize_alert

FIXTURE_ROOT = Path(__file__).resolve().parents[4] / "resources" / "mock-attacks"
CASE_FILES = sorted(FIXTURE_ROOT.glob("*/case-*.json"))

MAX_ROUNDS = 3  # cluade.md §27: maximum re-hunt / investigation rounds

# WazuhIndexerAdapter.ts IOC_FIELDS
INDEXER_IOC_FIELDS = (
    ("full_log",),
    ("data", "srcip"),
    ("data", "dstip"),
    ("data", "url"),
    ("data", "hash"),
    ("data", "md5"),
    ("data", "sha1"),
    ("data", "sha256"),
    ("data", "dns", "question", "name"),
)
SEARCHABLE_IOC_TYPES = {"ip", "domain", "url", "hash"}
_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)


# ---------------------------------------------------------------- schema

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Ioc(_Strict):
    type: Literal["ip", "domain", "url", "hash", "registry", "file", "process", "command", "user", "request"]
    value: str = Field(min_length=1)


class PolicyInputs(_Strict):
    assetTier: Literal["tier1_critical", "tier2_high", "tier3_medium", "tier4_low"]
    ruleLevel: int = Field(ge=0, le=15)


class Expected(_Strict):
    severity: Literal["low", "medium", "high", "critical"]
    host: str
    mitreTechniques: list[str] = Field(min_length=1)
    iocs: list[Ioc] = Field(min_length=1)
    policyInputs: PolicyInputs
    approval: Literal["POLICY_DECIDES", "APPROVAL_EXPECTED"]
    approvalDecisions: list[Literal["APPROVED", "REJECTED"]] = Field(default_factory=list)
    primaryResult: Literal["RESOLVED", "NOT_RESOLVED", "SPREAD"]
    finalOutcome: Literal["RESOLVED", "ESCALATED_TO_IR"]


class Response(_Strict):
    action: str = Field(min_length=1)
    target: str | None = None


class RoundExpected(_Strict):
    matchingEvents: int = Field(ge=0)
    iocRecurrence: bool
    spreadDetected: bool
    threatContained: bool
    verification: Literal["RESOLVED", "NOT_RESOLVED"]


class RehuntRound(_Strict):
    round: int = Field(ge=1, le=MAX_ROUNDS)
    scenario: Literal["NO_MATCH", "MATCH", "SPREAD"]
    expected: RoundExpected
    events: list[dict] = Field(min_length=1)


class Rehunt(_Strict):
    rounds: list[RehuntRound] = Field(min_length=1, max_length=MAX_ROUNDS)


class MockAttackCase(_Strict):
    id: str = Field(pattern=r"^ATK-\d{2}$")
    attackType: Literal["SSH_BRUTE_FORCE", "MALWARE", "SQL_INJECTION", "ACCOUNT_COMPROMISE", "POWERSHELL"]
    title: str
    description: str
    alert: dict
    relatedAlerts: list[dict] = Field(default_factory=list)
    expected: Expected
    response: Response
    rehunt: Rehunt

    @model_validator(mode="after")
    def _rounds_are_sequential(self) -> "MockAttackCase":
        numbers = [r.round for r in self.rehunt.rounds]
        assert numbers == list(range(1, len(numbers) + 1)), f"rounds must be 1..n, got {numbers}"
        return self


def _load(path: Path) -> MockAttackCase:
    return MockAttackCase.model_validate(json.loads(path.read_text(encoding="utf-8")))


# ---------------------------------------------------------------- re-hunt mirror

def _dig(node, *keys):
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _extracted_iocs(case: MockAttackCase) -> list:
    alert = case.alert
    return extract_from_alert(alert, flatten_alert_text(alert))


def _rehunt_criteria(case: MockAttackCase) -> tuple[set[str], list[str]]:
    """Hosts + IOC values the backend's RunRehuntVerificationUseCase would search for:
    the alert's agent, IOCs extracted by threat intel, and the response target."""
    hosts = {case.alert["agent"]["name"].lower()}
    values = {i.value for i in case.expected.iocs if i.type in SEARCHABLE_IOC_TYPES}
    values |= {e.value for e in _extracted_iocs(case)}
    target = (case.response.target or "").strip()
    if target:
        if _IPV4.match(target) or _HASH.match(target) or target.lower().startswith(("http://", "https://")):
            values.add(target)
        else:
            hosts.add(target.lower())
    return hosts, sorted(values)


def _event_matches(event: dict, ioc_values: list[str], rule_id: str) -> tuple[bool, bool]:
    """(matched_at_all, matched_by_ioc) — phrase match over the indexer IOC fields, or same rule id."""
    haystacks = [str(v).lower() for v in (_dig(event, *path) for path in INDEXER_IOC_FIELDS) if v is not None]
    by_ioc = any(value.lower() in h for value in ioc_values for h in haystacks)
    by_rule = str(_dig(event, "rule", "id")) == rule_id
    return by_ioc or by_rule, by_ioc


def evaluate_round(case: MockAttackCase, round_: RehuntRound) -> dict:
    hosts, ioc_values = _rehunt_criteria(case)
    rule_id = str(case.alert["rule"]["id"])
    matched = [(e, by_ioc) for e in round_.events for hit, by_ioc in [_event_matches(e, ioc_values, rule_id)] if hit]
    affected = {str(_dig(e, "agent", "name")).lower() for e, _ in matched}
    matching = len(matched)
    ioc_recurrence = any(by_ioc for _, by_ioc in matched)
    spread = any(h not in hosts for h in affected)
    contained = matching == 0
    resolved = contained and not spread and not ioc_recurrence and matching == 0
    return {
        "matchingEvents": matching,
        "iocRecurrence": ioc_recurrence,
        "spreadDetected": spread,
        "threatContained": contained,
        "verification": "RESOLVED" if resolved else "NOT_RESOLVED",
    }


# ---------------------------------------------------------------- tests

def test_fixture_files_exist():
    assert CASE_FILES, f"no case files under {FIXTURE_ROOT}"


def test_case_ids_are_unique():
    ids = [_load(p).id for p in CASE_FILES]
    assert len(ids) == len(set(ids)), ids


# cluade.md §41 — the 10-case test matrix.
MATRIX = {
    "ATK-01": ("ssh-bruteforce/case-01-resolved.json", "SSH_BRUTE_FORCE", "RESOLVED"),
    "ATK-02": ("ssh-bruteforce/case-02-not-resolved.json", "SSH_BRUTE_FORCE", "NOT_RESOLVED"),
    "ATK-03": ("malware/case-01-resolved.json", "MALWARE", "RESOLVED"),
    "ATK-04": ("malware/case-02-not-resolved.json", "MALWARE", "NOT_RESOLVED"),
    "ATK-05": ("sql-injection/case-01-resolved.json", "SQL_INJECTION", "RESOLVED"),
    "ATK-06": ("sql-injection/case-02-spread.json", "SQL_INJECTION", "SPREAD"),
    "ATK-07": ("account-compromise/case-01-suspicious-login.json", "ACCOUNT_COMPROMISE", "RESOLVED"),
    "ATK-08": ("account-compromise/case-02-privilege-escalation.json", "ACCOUNT_COMPROMISE", "RESOLVED"),
    "ATK-09": ("powershell/case-01-suspicious-command.json", "POWERSHELL", "RESOLVED"),
    "ATK-10": ("powershell/case-02-persistence.json", "POWERSHELL", "NOT_RESOLVED"),
}


@pytest.mark.parametrize("case_id", sorted(MATRIX))
def test_matrix_case_present(case_id):
    file, attack_type, primary = MATRIX[case_id]
    case = _load(FIXTURE_ROOT / file)
    assert (case.id, case.attackType, case.expected.primaryResult) == (case_id, attack_type, primary)


def test_approval_expectations_follow_the_policy_engine():
    # Verified against the backend Policy Engine in Task 8 (apps/backend/test/PolicyApprovalWorkflow.test.ts):
    # ATK-08 (CRITICAL severity on DC-01, tier1_critical) needs Manager approval — both decisions are exercised.
    # ATK-10 (CRITICAL severity on FILESRV-01, tier2_high) gets IR review only: severity alone never forces approval.
    atk08 = _load(FIXTURE_ROOT / MATRIX["ATK-08"][0])
    assert (atk08.expected.approval, atk08.expected.severity, atk08.expected.policyInputs.assetTier) == ("APPROVAL_EXPECTED", "critical", "tier1_critical")
    assert set(atk08.expected.approvalDecisions) == {"APPROVED", "REJECTED"}
    atk10 = _load(FIXTURE_ROOT / MATRIX["ATK-10"][0])
    assert (atk10.expected.approval, atk10.expected.severity, atk10.expected.policyInputs.assetTier) == ("POLICY_DECIDES", "critical", "tier2_high")


@pytest.mark.parametrize("path", CASE_FILES, ids=lambda p: p.parent.name + "/" + p.stem)
class TestMockAttackCase:
    def test_schema(self, path):
        _load(path)

    def test_alert_normalizes_via_existing_wazuh_normalizer(self, path):
        case = _load(path)
        for i, alert in enumerate([case.alert, *case.relatedAlerts]):
            normalized = normalize_alert("wazuh", alert, alert_id=f"{case.id}-{i}", tenant_id="default")
            assert normalized.source == "wazuh"
            assert normalized.title, "rule.description must be present"
            assert normalized.timestamp is not None, "timestamp must parse"
            assert normalized.hostname == case.expected.host
        assert case.alert["rule"]["level"] == case.expected.policyInputs.ruleLevel

    def test_expected_mitre_is_declared_by_the_alerts(self, path):
        case = _load(path)
        declared = {t for a in [case.alert, *case.relatedAlerts] for t in (_dig(a, "rule", "mitre", "id") or [])}
        assert set(case.expected.mitreTechniques) <= declared

    def test_expected_iocs_are_recoverable(self, path):
        case = _load(path)
        extracted = {e.value.lower() for a in [case.alert, *case.relatedAlerts] for e in extract_from_alert(a, flatten_alert_text(a))}
        blob = json.dumps([case.alert, *case.relatedAlerts]).lower().replace("\\\\", "\\")
        for ioc in case.expected.iocs:
            value = ioc.value.lower()
            if ioc.type in SEARCHABLE_IOC_TYPES:
                assert any(value == x or value in x for x in extracted), f"{ioc.type} {ioc.value} not extracted; got {sorted(extracted)}"
            else:
                assert value in blob, f"{ioc.type} {ioc.value} not present in alert data"

    def test_ip_iocs_are_routable(self, path):
        # The AI text extractor drops non-routable addresses; attacker IPs must survive it.
        case = _load(path)
        for ioc in case.expected.iocs:
            if ioc.type == "ip":
                assert ipaddress.ip_address(ioc.value).is_global, ioc.value

    def test_rehunt_rounds_are_self_consistent(self, path):
        case = _load(path)
        for round_ in case.rehunt.rounds:
            actual = evaluate_round(case, round_)
            assert actual == round_.expected.model_dump(), f"round {round_.round}: {actual}"
            scenario = (
                "NO_MATCH" if actual["matchingEvents"] == 0
                else "SPREAD" if actual["spreadDetected"]
                else "MATCH"
            )
            assert round_.scenario == scenario, f"round {round_.round}"

    def test_rounds_include_non_matching_noise(self, path):
        case = _load(path)
        for round_ in case.rehunt.rounds:
            assert evaluate_round(case, round_)["matchingEvents"] < len(round_.events), f"round {round_.round} has no noise event"

    def test_primary_and_final_outcome_follow_from_rounds(self, path):
        case = _load(path)
        rounds = case.rehunt.rounds
        first = rounds[0]
        primary = "SPREAD" if first.scenario == "SPREAD" else first.expected.verification
        assert case.expected.primaryResult == primary

        # Loop stops at the first RESOLVED; only the last round may be RESOLVED.
        assert all(r.expected.verification == "NOT_RESOLVED" for r in rounds[:-1])
        if rounds[-1].expected.verification == "RESOLVED":
            assert case.expected.finalOutcome == "RESOLVED"
        else:
            assert len(rounds) == MAX_ROUNDS, "an unresolved case must exhaust the round limit"
            assert case.expected.finalOutcome == "ESCALATED_TO_IR"

    def test_rehunt_events_look_like_indexer_documents(self, path):
        case = _load(path)
        for round_ in case.rehunt.rounds:
            for event in round_.events:
                for key in ("id", "timestamp", "@timestamp", "rule", "agent", "full_log"):
                    assert key in event, f"round {round_.round} event missing {key}"
