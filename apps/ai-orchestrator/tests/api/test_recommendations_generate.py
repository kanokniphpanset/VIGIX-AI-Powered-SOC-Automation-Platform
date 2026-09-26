"""
POST /recommendations/generate — LLM recommendation + failure safety.
The LLM and RAG retriever are stubbed; no network. Run from apps/ai-orchestrator:
  .venv/Scripts/python.exe -m pytest tests/api
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routes import recommendations as rec

CONTEXT = {
    "incidentId": "inc-1",
    "investigationNumber": 1,
    "incidentTitle": "sshd: brute force trying to get access to the system. Authentication failed.",
    "iocs": [{"iocType": "IPV4", "iocValue": "185.220.101.45", "source": "aggregated", "reputationScore": None}],
    "mitreMappings": [{"techniqueId": "T1110", "tactic": "Credential Access", "confidence": 0.85}],
    "incidentType": "SSH_BRUTE_FORCE",
    "playbook": {"code": "PB-SSH-BRUTEFORCE", "incidentType": "SSH_BRUTE_FORCE", "allowedActions": ["ACT-BLOCK-SOURCE-IP"]},
    "actionProcedures": [{"actionCode": "ACT-BLOCK-SOURCE-IP", "actionName": "Block Source IP", "runbookCode": "RB-BLOCK-SOURCE-IP"}],
}
PROMPT = "You are the VIGIX Incident Response Recommendation Agent.\nDO NOT repeat the VIGIX Core Flow. ... Respond with JSON."

VALID = {
    "summary": "Block the SSH brute-force source 185.220.101.45 (T1110).",
    "steps": [
        {
            "stepOrder": 1,
            "action": "ACT-BLOCK-SOURCE-IP",
            "objective": "Prevent further communication from 185.220.101.45 to WKS-DEV-12.",
            "responsibleRole": "SOC",
            "target": "185.220.101.45",
            "reason": "Repeated failed root logins from 185.220.101.45 mapped to T1110.",
            "evidenceRefs": ["185.220.101.45", "T1110"],
            "instructions": [
                {"order": 1, "instruction": "Confirm 185.220.101.45 against the authentication evidence.", "target": "185.220.101.45", "expectedResult": "Source confirmed."},
                {"order": 2, "instruction": "Apply a deny rule for 185.220.101.45 on the perimeter firewall.", "target": "185.220.101.45", "expectedResult": "Rule active."},
            ],
            "playbook": "PB-SSH-BRUTEFORCE",
            "runbook": "RB-BLOCK-SOURCE-IP",
            "verificationCriteria": "Connection attempts from 185.220.101.45 are rejected.",
            "expectedResult": "No further attempts from the source IP.",
            "missingEvidence": [],
            "confidence": 0.8,
            "requiresApprovalSuggested": False,
        }
    ],
}


class _Result:
    status = "OK"
    documents = [{"title": "Brute Force Authentication Response", "metadata": {"runbookCode": "RB-BRUTEFORCE-001"}, "score": 0.7, "content": "Runbook: ..."}]


class _Retriever:
    async def retrieve_playbooks(self, query):
        return _Result()


class _Llm:
    def __init__(self, reply=None, exc=None, delay=0.0, replies=None):
        self.reply, self.exc, self.delay, self.calls = reply, exc, delay, []
        self.replies = list(replies) if replies else None

    async def complete(self, system, user):
        self.calls.append((system, user))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        return self.replies.pop(0) if self.replies else self.reply


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(rec, "_retriever", _Retriever())
    app = FastAPI()
    app.include_router(rec.router, prefix="/recommendations")
    return TestClient(app)


def _post(client, prompt=PROMPT):
    return client.post("/recommendations/generate", json={"context": CONTEXT, "prompt": prompt})


def test_valid_llm_candidate_is_returned_and_grounded_in_backend_prompt_and_rag(client, monkeypatch):
    llm = _Llm(reply=json.dumps(VALID))
    monkeypatch.setattr(rec, "_llm", llm)
    r = _post(client)
    assert r.status_code == 200
    assert r.json() == VALID
    system, user = llm.calls[0]
    assert "ONE JSON object" in system
    assert "DO NOT repeat the VIGIX Core Flow." in system
    assert "Expand only the selected response Action into concrete operational instructions for the responsible role." in system
    assert "AI does not authorize, approve, execute, or bypass Policy." in system
    assert user.startswith(PROMPT)
    assert "RB-BRUTEFORCE-001" in user  # RAG grounding appended


def test_multi_action_candidate_is_accepted(client, monkeypatch):
    second = {**VALID["steps"][0], "stepOrder": 2, "action": "ACT-DISABLE-ACCOUNT", "target": "root", "runbook": "RB-DISABLE-ACCOUNT"}
    reply = {**VALID, "steps": [VALID["steps"][0], second]}
    monkeypatch.setattr(rec, "_llm", _Llm(reply=json.dumps(reply)))
    r = _post(client)
    assert r.status_code == 200
    assert [s["action"] for s in r.json()["steps"]] == ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"]


def test_trailing_second_object_is_ignored_first_object_validated(client, monkeypatch):
    monkeypatch.setattr(rec, "_llm", _Llm(reply=json.dumps(VALID) + "\n" + json.dumps({"note": "extra"})))
    r = _post(client)
    assert r.status_code == 200
    assert r.json() == VALID


def test_code_fenced_json_is_accepted(client, monkeypatch):
    monkeypatch.setattr(rec, "_llm", _Llm(reply="```json\n" + json.dumps(VALID) + "\n```"))
    assert _post(client).status_code == 200


@pytest.mark.parametrize(
    "reply",
    [
        "I recommend blocking the IP.",  # prose, no JSON
        '{"summary": "x", "steps": [',  # truncated JSON
        json.dumps({"summary": "x", "steps": []}),  # empty recommendation
        json.dumps({"summary": "", "steps": VALID["steps"]}),  # empty summary
        json.dumps({"summary": "x", "steps": [{"title": "no order / reason"}]}),  # invalid step
        json.dumps({**VALID, "approved": True}),  # extra key (e.g. AI trying to self-approve)
        json.dumps({"summary": "x", "steps": [{**VALID["steps"][0], "confidence": 7}]}),  # out of range
        json.dumps({"summary": "x", "steps": [{**VALID["steps"][0], "instructions": []}]}),  # empty instructions
        json.dumps({"summary": "x", "steps": [{k: v for k, v in VALID["steps"][0].items() if k != "runbook"}]}),  # missing runbook
        json.dumps({"summary": "x", "steps": [{**VALID["steps"][0], "actionCode": "ACT-BLOCK-SOURCE-IP"}]}),  # v1 field
        json.dumps({"summary": "x", "steps": [{**VALID["steps"][0], "responsibleRole": ""}]}),  # empty role
        "",
    ],
)
def test_invalid_llm_output_is_502_never_a_candidate(client, monkeypatch, reply):
    monkeypatch.setattr(rec, "_llm", _Llm(reply=reply))
    r = _post(client)
    assert r.status_code == 502
    assert r.json()["detail"]["error"] == "INVALID_LLM_OUTPUT"


def test_unparseable_reply_is_re_asked_once_then_validated(client, monkeypatch):
    llm = _Llm(replies=['{"summary": "x", "steps": [', json.dumps(VALID)])
    monkeypatch.setattr(rec, "_llm", llm)
    r = _post(client)
    assert r.status_code == 200 and r.json() == VALID
    assert len(llm.calls) == 2 and "previous reply was rejected" in llm.calls[1][1]


def test_schema_error_names_the_field_in_the_re_ask_and_the_502(client, monkeypatch):
    bad = json.dumps({"summary": "x", "steps": [{**VALID["steps"][0], "confidence": 7}]})
    llm = _Llm(reply=bad)
    monkeypatch.setattr(rec, "_llm", llm)
    r = _post(client)
    assert r.status_code == 502
    assert "steps.0.confidence" in r.json()["detail"]["message"]
    assert "steps.0.confidence" in llm.calls[1][1]  # the model is told what to fix


def test_two_unparseable_replies_are_502(client, monkeypatch):
    llm = _Llm(reply="not json")
    monkeypatch.setattr(rec, "_llm", llm)
    assert _post(client).status_code == 502
    assert len(llm.calls) == 2


def test_llm_error_is_503(client, monkeypatch):
    monkeypatch.setattr(rec, "_llm", _Llm(exc=RuntimeError("connection refused")))
    r = _post(client)
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "LLM_UNAVAILABLE"


def test_llm_timeout_is_504(client, monkeypatch):
    monkeypatch.setattr(rec, "_llm", _Llm(reply=json.dumps(VALID), delay=0.5))
    monkeypatch.setattr(rec.settings, "llm_timeout_seconds", 0.05)
    r = _post(client)
    assert r.status_code == 504
    assert r.json()["detail"]["error"] == "LLM_TIMEOUT"


def test_missing_prompt_is_422_and_llm_not_called(client, monkeypatch):
    llm = _Llm(reply=json.dumps(VALID))
    monkeypatch.setattr(rec, "_llm", llm)
    r = _post(client, prompt="  ")
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "PROMPT_MISSING"
    assert llm.calls == []


def test_rag_failure_is_disclosed_not_fatal(client, monkeypatch):
    class _Broken:
        async def retrieve_playbooks(self, query):
            raise ConnectionError("qdrant down")

    llm = _Llm(reply=json.dumps(VALID))
    monkeypatch.setattr(rec, "_retriever", _Broken())
    monkeypatch.setattr(rec, "_llm", llm)
    assert _post(client).status_code == 200
    assert "unavailable" in llm.calls[0][1]
