"""
POST /pipeline/run — analysis_only (manual Run / Re-run AI Analysis from VIGIX).
The graph, database and outbound calls are stubbed; no network, no DB. Run from apps/ai-orchestrator:
  .venv/Scripts/python.exe -m pytest tests/api
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routes import run_pipeline as rp

ALERT = {
    "id": "alert-1", "tenant_id": "t-1", "external_alert_id": "1790233459.12882", "siem_source": "wazuh", "severity": "medium",
    "raw_payload": {"rule": {"id": "5712", "description": "sshd: brute force"}, "agent": {"id": "001", "name": "vigix-lab-ubuntu"}, "data": {"srcip": "172.31.250.50"}},
}


class FakeGraph:
    async def ainvoke(self, state, config=None):
        return {**state, "decision": "auto_response", "decision_result": {"stub": True}, "severity": "medium", "requires_approval": False, "errors": []}


@pytest.fixture()
def world(monkeypatch):
    calls = {"notify": 0, "notifications": 0, "persist": 0, "incident_alert_ids": []}

    async def fake_graph():
        return FakeGraph()

    async def fake_notify(**kwargs):
        calls["notify"] += 1

    class FakeNotifications:
        async def dispatch(self, **kwargs):
            calls["notifications"] += 1

    def fake_ensure_incident(_url, alert):
        calls["incident_alert_ids"].append(alert["id"])
        return "incident-1"

    def fake_persist(*_args, **_kwargs):
        calls["persist"] += 1

    monkeypatch.setattr(rp, "fetch_alert", lambda _url, alert_id, tenant_id: ALERT if alert_id == "alert-1" else None)
    monkeypatch.setattr(rp, "ensure_incident_for_alert", fake_ensure_incident)
    monkeypatch.setattr(rp, "incident_for_execution", lambda _url, exec_id: {"job-1": "incident-queued"}.get(exec_id))
    monkeypatch.setattr(rp, "ensure_execution_record", lambda _url, exec_id, _inc: exec_id or "exec-1")
    monkeypatch.setattr(rp, "get_checkpointed_graph", fake_graph)
    monkeypatch.setattr(rp, "build_output_contract", lambda *a, **k: {})
    monkeypatch.setattr(rp, "persist_agent_results", fake_persist)
    monkeypatch.setattr(rp, "notify_backend_of_decision", fake_notify)
    monkeypatch.setattr(rp, "notification_orchestrator", FakeNotifications())
    monkeypatch.setattr(rp, "get_incident_title", lambda *_a: "sshd: brute force")
    monkeypatch.setattr(rp.DecisionResult, "model_validate", staticmethod(lambda v: v))
    monkeypatch.setattr(rp, "IncidentContext", lambda **kw: kw)

    app = FastAPI()
    app.include_router(rp.router, prefix="/pipeline")
    return TestClient(app), calls


def test_analysis_only_persists_the_analysis_but_sends_no_callback_or_notification(world):
    client, calls = world
    res = client.post("/pipeline/run", json={"alert_id": "alert-1", "tenant_id": "t-1", "analysis_only": True})
    assert res.status_code == 200
    body = res.json()
    assert body["incident_id"] == "incident-1" and body["graph_run_id"] == "exec-1"
    assert body["status"] == "SUCCESS" and "severity_prediction" not in body and "risk_score" not in body
    assert calls["persist"] == 1
    assert calls["notify"] == 0
    assert calls["notifications"] == 0
    assert calls["incident_alert_ids"] == ["alert-1"]  # the existing alert's incident, never a new alert


def test_default_run_is_unchanged_and_still_hands_off_the_decision(world):
    client, calls = world
    res = client.post("/pipeline/run", json={"alert_id": "alert-1", "tenant_id": "t-1"})
    assert res.status_code == 200
    assert calls["persist"] == 1
    assert calls["notify"] == 1
    assert calls["notifications"] == 1


def test_unknown_alert_is_404_and_nothing_runs(world):
    client, calls = world
    res = client.post("/pipeline/run", json={"alert_id": "missing", "tenant_id": "t-1", "analysis_only": True})
    assert res.status_code == 404
    assert calls["persist"] == 0 and calls["incident_alert_ids"] == []


def test_queued_job_uses_the_backend_incident_and_never_opens_one(world):
    client, calls = world
    res = client.post("/pipeline/run", json={"alert_id": "alert-1", "tenant_id": "t-1", "analysis_only": True, "execution_id": "job-1"})
    assert res.status_code == 200
    body = res.json()
    assert body["incident_id"] == "incident-queued" and body["graph_run_id"] == "job-1"
    assert calls["incident_alert_ids"] == []  # ensure_incident_for_alert never called
    assert calls["persist"] == 1 and calls["notify"] == 0 and calls["notifications"] == 0


def test_unknown_execution_id_is_404_and_nothing_runs(world):
    client, calls = world
    res = client.post("/pipeline/run", json={"alert_id": "alert-1", "tenant_id": "t-1", "analysis_only": True, "execution_id": "nope"})
    assert res.status_code == 404
    assert calls["persist"] == 0 and calls["incident_alert_ids"] == []
