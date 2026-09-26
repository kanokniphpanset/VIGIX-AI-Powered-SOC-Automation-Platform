"""VIGIX has exactly one severity: the Wazuh rule level mapped deterministically by the backend (state["severity"]).
No agent generates, suggests, classifies or changes a severity; there is no ML severity node and no risk score."""

import asyncio
import importlib

import pytest

from src.agents.decision_agent import agent as decision_agent
from src.agents.decision_agent.agent import run_decision
from src.agents.llm_analyst_agent import agent as llm_agent
from src.agents.recommendation_agent.selector import build_signals
from src.api.schemas import RunPipelineResponse
from src.contracts.evidence import EvidenceCategory, EvidenceKind, build_evidence, wazuh_severity_evidence
from src.graph.state import AgentState


@pytest.mark.parametrize(
    "severity, role, approval, approver, escalate",
    [
        ("low", "SOC", True, "IR_TEAM", False),
        ("medium", "SOC", True, "IR_TEAM", False),
        ("high", "SOC", True, "IR_TEAM", False),
        ("critical", "SOC", True, "IR_TEAM", True),
        ("", "SOC", True, "IR_TEAM", False),  # unknown severity -> a human must look (never "no approval")
    ],
)
def test_decision_follows_severity(severity, role, approval, approver, escalate):
    r = run_decision(classification="credential_attack", severity=severity, snapshot={})
    assert (r.responsible_role, r.approval_required, r.approval_role, r.escalate) == (role, approval, approver, escalate)


def test_a_legacy_risk_score_in_state_has_no_effect_on_the_decision():
    base = {"classification": {"label": "credential_attack"}, "severity": "medium"}
    outcomes = {
        str(asyncio.run(decision_agent.run({**base, "risk_score": risk, "risk": {"score": risk}}))["decision_result"])
        for risk in (10, 50, 90)
    }
    assert len(outcomes) == 1


def test_false_positive_is_dismissed_whatever_the_severity():
    assert run_decision("false_positive", "critical", {}).approval_required is False


def test_there_is_no_ml_severity_agent_or_model():
    for module in ("src.agents.ml_risk_agent", "src.agents.ml_risk_agent.agent", "src.ml_models"):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module)
    for key in ("severity_prediction", "severity_classification", "confidence_score", "ml_model_version"):
        assert key not in AgentState.__annotations__


def test_the_analysis_graphs_have_no_severity_node():
    from src.graph.build_graph import build_analysis_graph

    nodes = set(build_analysis_graph().get_graph().nodes)
    assert "ml_risk" not in nodes
    assert {"threat_intel", "mitre", "rag", "llm_analyst", "recommendation_agent", "decision_agent"} <= nodes


def test_wazuh_severity_is_factual_evidence_and_the_only_severity_evidence():
    items = wazuh_severity_evidence({"severity": "high"})
    assert len(items) == 1
    assert items[0].type == EvidenceCategory.SEVERITY and items[0].kind == EvidenceKind.FACTUAL_EVIDENCE
    assert items[0].agent == "wazuh" and items[0].value == "HIGH"
    # A stray model output is ignored: it can never become evidence.
    evidence = build_evidence({"severity": "low", "severity_prediction": "critical", "confidence_score": 0.9})
    severities = [e for e in evidence if e.type == EvidenceCategory.SEVERITY]
    assert [(e.agent, e.value) for e in severities] == [("wazuh", "LOW")]
    assert wazuh_severity_evidence({"severity_prediction": "high"}) == []


def test_recommendation_signal_uses_the_wazuh_severity_only():
    high = build_signals([], {}, {"severity": "critical"})
    low = build_signals([], {}, {"severity": "low", "severity_prediction": "critical", "risk_score": 99})
    assert high["high_severity"] is True and "high_risk" not in high
    assert low["high_severity"] is False


def test_decision_ignores_any_model_severity():
    state = {"classification": {"label": "credential_attack"}, "severity": "medium", "severity_prediction": "critical"}
    result = asyncio.run(decision_agent.run(state))["decision_result"]
    assert result["severity"] == "medium" and result["escalate"] is False


def test_llm_fallback_analysis_states_the_wazuh_severity_and_no_ai_severity():
    report = llm_agent._heuristic_analysis({"severity": "high", "severity_prediction": "low", "alert_text": "Failed password for root"})
    text = str(report)
    assert "Alert severity: high." in text
    assert "ML severity" not in text and "suggest" not in text.lower()


def test_pipeline_response_has_no_severity_suggestion_and_no_risk_score():
    fields = RunPipelineResponse.model_fields
    assert "risk_score" not in fields and "severity_prediction" not in fields
