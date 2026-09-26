"""
Regression tests for the AI integration blockers found by the full-system E2E (2026-09-26):

1. LLM analyst: a wrong settings import made every LLM call fail, and a broad `except` silently replaced the
   analysis with a template. Now: the real LLM answer on success; on any failure the analysis is FAILED (CRITICAL
   error with a specific code, empty llm_summary, persisted status FAILED) — the heuristic is only a labelled record.
2. Validation agent: CheckResult has `check`, not `name`; results were written under a key LangGraph drops; the retry
   counter was never incremented.
3. RAG: one httpx.AsyncClient shared across the per-call event loops of rag_retrieval_tool ("Event loop is closed");
   retrieval failures were silent.

The LLM and the knowledge-search backend are stubbed here (unit level). The real LLM + Qdrant path is exercised by
the live E2E, not by these tests. Run from apps/ai-orchestrator:  .venv/Scripts/python.exe -m pytest tests/api
"""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from src.agents.llm_analyst_agent import agent as analyst
from src.agents.rag_agent import agent as rag_agent
from src.agents.rag_agent.retriever import RagRetriever
from src.agents.rag_agent.vector_search_client import VectorSearchClient, VectorSearchClientError
from src.agents.validation_agent import agent as validation_agent
from src.agents.validation_agent.llm_consistency import CheckResult
from src.agents.validation_agent.rules import ValidationReport
from src.api.database import final_execution_status
from src.api.output_contract import build_output_contract
from src.contracts.tool_result import ToolResult
from src.graph.router import MAX_RETRIES, after_validation
from src.graph.state import AgentState
from src.tools import rag_retrieval_tool

STATE = {
    "severity": "medium",
    "alert_text": "sshd: Failed password for root from 185.220.101.45 port 51122",
    "raw_alert": {"rule": {"id": "5712", "level": 10}, "agent": {"name": "WKS-DEV-12"}, "data": {"srcip": "185.220.101.45"}},
    "iocs": [{"type": "IPV4", "value": "185.220.101.45"}],
}
ALERT = {"id": "alert-1", "external_alert_id": "ext-1"}


class FakeLlm:
    def __init__(self, answer=None, exc: Exception | None = None):
        self.answer, self.exc, self.calls = answer, exc, 0

    async def complete(self, system_prompt: str, user_prompt: str):
        self.calls += 1
        if self.exc:
            raise self.exc
        return self.answer


def run_analyst(monkeypatch, llm: FakeLlm) -> dict:
    monkeypatch.setattr(analyst, "_get_llm", lambda: llm)
    return asyncio.run(analyst.run(dict(STATE)))


# ---------------------------------------------------------------- 1. LLM analyst: no silent fallback
def test_llm_provider_is_built_from_the_settings_instance(monkeypatch):
    """The regression itself: `from src.config import settings` bound the MODULE and raised AttributeError."""
    from src.config.settings import settings

    monkeypatch.setattr(analyst, "_llm", None)
    provider = analyst._get_llm()
    assert provider.base_url == settings.llm_base_url.rstrip("/")
    assert provider.model == settings.llm_model


def test_llm_success_is_the_real_llm_answer(monkeypatch):
    llm = FakeLlm(answer="Brute force against root from 185.220.101.45 on WKS-DEV-12; no successful login observed.")
    out = run_analyst(monkeypatch, llm)
    assert llm.calls == 1
    assert out["analysis_source"] == "LLM"
    assert out["llm_summary"] == llm.answer
    assert out["analyst_report"]["source"] == "LLM" and out["analyst_report"]["status"] == "SUCCESS"
    assert out["analyst_report"]["model"]
    assert "structured_errors" not in out
    assert "heuristic" not in out["llm_summary"].lower()


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (httpx.ReadTimeout("timed out"), "LLM_TIMEOUT"),
        (httpx.ConnectError("connection refused"), "LLM_UNAVAILABLE"),
        (httpx.HTTPStatusError("503", request=httpx.Request("POST", "http://llm"), response=httpx.Response(503)), "LLM_UNAVAILABLE"),
        (KeyError("choices"), "LLM_INVALID_RESPONSE"),
        (RuntimeError("boom"), "AGENT_EXECUTION_FAILED"),
    ],
)
def test_llm_failure_is_reported_as_failed_never_as_a_template(monkeypatch, exc, code):
    out = run_analyst(monkeypatch, FakeLlm(exc=exc))
    assert out["analysis_source"] == "FAILED"
    assert out["llm_summary"] is None  # nothing presented as an analysis
    assert out["llm_key_findings"] == []
    err = out["structured_errors"][0]
    assert err["code"] == code and err["severity"] == "CRITICAL" and err["agent"] == "llm_analyst"
    report = out["analyst_report"]
    assert report["status"] == "FAILED" and report["error"]["code"] == code
    # the heuristic survives ONLY as an explicitly labelled record, never as the summary
    assert report["fallback"]["source"] == "HEURISTIC_FALLBACK"
    assert "analysis" not in report


@pytest.mark.parametrize("answer", ["", "   ", None, {"not": "text"}])
def test_malformed_or_empty_llm_answer_is_invalid_response(monkeypatch, answer):
    out = run_analyst(monkeypatch, FakeLlm(answer=answer))
    assert out["analysis_source"] == "FAILED"
    assert out["structured_errors"][0]["code"] == "LLM_INVALID_RESPONSE"


def test_llm_failure_is_logged(monkeypatch, caplog):
    with caplog.at_level("WARNING"):
        run_analyst(monkeypatch, FakeLlm(exc=httpx.ReadTimeout("timed out")))
    assert any("LLM analysis failed" in r.getMessage() and "LLM_TIMEOUT" in r.getMessage() for r in caplog.records)


def test_analyst_state_keys_are_part_of_the_graph_state():
    """LangGraph drops keys that are not in AgentState — every key the analyst writes must be declared."""
    declared = set(AgentState.__annotations__)
    for key in ("analysis_source", "llm_summary", "llm_key_findings", "analyst_report", "structured_errors", "trace", "classification"):
        assert key in declared, key


# ---------------------------------------------------------------- persisted status
def _contract(state: dict) -> dict:
    return build_output_contract("exec-1", ALERT, "inc-1", state)


def test_persisted_status_is_failed_with_the_llm_error_code(monkeypatch):
    failed = {**STATE, **run_analyst(monkeypatch, FakeLlm(exc=httpx.ReadTimeout("timed out")))}
    contract = _contract(failed)
    assert contract["status"] == "FAILED"
    assert contract["analysis"]["source"] == "FAILED" and contract["analysis"]["summary"] is None
    status, code, message = final_execution_status(failed, contract)
    assert (status, code) == ("FAILED", "LLM_TIMEOUT") and "timed out" in message


def test_persisted_status_success_carries_the_llm_source_and_model(monkeypatch):
    ok = {**STATE, **run_analyst(monkeypatch, FakeLlm(answer="Grounded analysis."))}
    contract = _contract(ok)
    assert contract["analysis"]["source"] == "LLM" and contract["analysis"]["model"]
    assert final_execution_status(ok, contract) == ("SUCCESS", None, None)


def test_structured_only_errors_are_no_longer_reported_as_success():
    """Before: the status looked only at legacy `errors`, so a RAG / validation failure still said SUCCESS."""
    state = {**STATE, "llm_summary": "x", "analysis_source": "LLM", "structured_errors": [
        {"id": "rag-search_failed-retrieval", "agent": "rag", "code": "SEARCH_FAILED", "message": "down", "retryable": True, "severity": "ERROR"}
    ]}
    assert final_execution_status(state, _contract(state))[0] == "PARTIAL_SUCCESS"


# ---------------------------------------------------------------- 2. Validation agent
def test_validation_completes_and_writes_the_keys_the_pipeline_reads():
    out = asyncio.run(validation_agent.run({**STATE, "llm_summary": "Brute force from 185.220.101.45.", "retry_count": 0}))
    assert "structured_errors" not in out  # no more 'CheckResult' object has no attribute 'name'
    assert isinstance(out["validation_passed"], bool)
    assert out["validation_status"] in ("VALID", "WARNING", "INVALID")
    assert out["validation_checks"] and all(c["name"] and c["status"] in ("PASS", "WARNING", "FAIL") for c in out["validation_checks"])
    assert "validation" not in out  # would collide with the node name and be dropped
    declared = set(AgentState.__annotations__)
    assert set(out) <= declared, set(out) - declared


def test_check_result_field_is_check():
    c = CheckResult("mitre_confidence", "PASS", "ok")
    assert c.check == "mitre_confidence" and not hasattr(c, "name")


def test_failed_validation_increments_retry_count_so_the_loop_terminates(monkeypatch):
    invalid = ValidationReport(status="INVALID", is_valid=False, checks=[CheckResult("evidence_support", "FAIL", "unsupported claim")], issues=["unsupported claim"])
    monkeypatch.setattr(validation_agent, "validate_full", lambda state: invalid)
    state = {**STATE, "retry_count": 0}
    routes = []
    for _ in range(MAX_RETRIES + 2):
        state.update(asyncio.run(validation_agent.run(state)))
        routes.append(after_validation(state))
        if routes[-1] == "proceed":
            break
    assert state["validation_passed"] is False
    # retry_count is incremented before routing, so the graph runs validation at most MAX_RETRIES times, then proceeds
    assert routes == ["retry"] * (MAX_RETRIES - 1) + ["proceed"]


def test_validation_crash_fails_closed(monkeypatch):
    def boom(state):
        raise RuntimeError("rule engine crashed")

    monkeypatch.setattr(validation_agent, "validate_full", boom)
    out = asyncio.run(validation_agent.run({**STATE, "retry_count": 1}))
    assert out["validation_passed"] is False and out["validation_status"] == "ERROR"
    assert out["retry_count"] == 2
    assert out["structured_errors"][0]["agent"] == "validation"


# ---------------------------------------------------------------- 3. RAG lifecycle + no silent failure
class _SearchHandler(BaseHTTPRequestHandler):
    status = 200
    calls = 0

    def do_POST(self):  # noqa: N802 - http.server API
        type(self).calls += 1
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        body = json.dumps({"results": [{"documentId": "kb-ssh-bruteforce", "title": "SSH brute force playbook", "content": "Block the source IP.", "score": 0.82, "metadata": {"documentType": "PLAYBOOK"}}]}) if self.status == 200 else json.dumps({"error": "VECTOR_DB_UNAVAILABLE"})
        self.send_response(self.status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):  # silence
        pass


@pytest.fixture
def search_server():
    handler = type("Handler", (_SearchHandler,), {"status": 200, "calls": 0})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", handler
    server.shutdown()
    server.server_close()


class FakeEmbedding:
    def embed(self, text: str) -> list[float]:
        return [0.1] * 8


def test_vector_search_client_survives_repeated_event_loops(search_server):
    """The exact production pattern: every retrieval in its own asyncio.run() (a new loop) on ONE client object."""
    url, handler = search_server
    client = VectorSearchClient(url, timeout_s=5, max_retries=0)
    for _ in range(4):
        results = asyncio.run(client.search([0.1] * 8, top_k=3))
        assert results and results[0]["documentId"] == "kb-ssh-bruteforce"
    assert handler.calls == 4


def test_vector_search_unavailable_is_a_clear_error_not_an_empty_result(search_server):
    url, handler = search_server
    handler.status = 503
    client = VectorSearchClient(url, timeout_s=5, max_retries=0)
    with pytest.raises(VectorSearchClientError):
        asyncio.run(client.search([0.1] * 8, top_k=3))


def test_rag_node_repeated_graph_executions_no_event_loop_closed(search_server, monkeypatch):
    """LangGraph runs the (sync) RAG node from inside a running loop; the tool then uses its own loop per call."""
    url, _ = search_server
    retriever = RagRetriever(FakeEmbedding(), VectorSearchClient(url, timeout_s=5, max_retries=0), top_k=3, playbook_top_k=3)
    monkeypatch.setattr(rag_retrieval_tool, "_retriever", retriever)

    async def one_graph_execution():
        return [rag_agent.run(dict(STATE)) for _ in range(2)]

    for _ in range(3):  # three separate graph executions (three event loops)
        for out in asyncio.run(one_graph_execution()):
            assert "structured_errors" not in out, out.get("structured_errors")
            assert out["rag_result"].get("chunks"), out["rag_result"]
            assert "Event loop is closed" not in json.dumps(out)


def test_rag_failure_is_recorded_not_silent(monkeypatch):
    monkeypatch.setattr(rag_agent, "run_rag", lambda *a, **k: ToolResult.failure("error", "rag_retrieval", "Vector search failed after 3 attempt(s): 503"))
    out = rag_agent.run(dict(STATE))
    assert out["rag_result"]["status"] == "error" and out["rag_result"]["chunks"] == []
    err = out["structured_errors"][0]
    assert err["agent"] == "rag" and err["code"] == "SEARCH_FAILED" and err["severity"] == "ERROR"


def test_rag_not_found_is_an_answer_not_an_error(monkeypatch):
    monkeypatch.setattr(rag_agent, "run_rag", lambda *a, **k: ToolResult.failure("not_found", "rag_retrieval", "no relevant documents"))
    out = rag_agent.run(dict(STATE))
    assert out["rag_result"]["status"] == "not_found"
    assert "structured_errors" not in out


# ---------------------------------------------------------------- found by the real-LLM E2E after the fixes above
def test_ioc_consistency_accepts_ips_from_the_raw_alert_the_llm_was_given():
    """Quoting the host's own agent.ip (in raw_alert, passed to the LLM) is not a fabricated IP."""
    from src.agents.validation_agent.llm_consistency import check_ioc_consistency

    state = {**STATE, "raw_alert": {**STATE["raw_alert"], "agent": {"name": "WKS-DEV-12", "ip": "10.0.5.44"}},
             "llm_summary": "Brute force from 185.220.101.45 against WKS-DEV-12 (10.0.5.44)."}
    assert check_ioc_consistency(state).status == "PASS"


def test_ioc_consistency_still_fails_an_invented_ip():
    from src.agents.validation_agent.llm_consistency import check_ioc_consistency

    state = {**STATE, "llm_summary": "Lateral movement to 203.0.113.99 was observed."}
    result = check_ioc_consistency(state)
    assert result.status == "FAIL" and "203.0.113.99" in result.details


def test_analyst_prompt_forbids_an_ai_severity(monkeypatch):
    seen = {}

    class CapturingLlm(FakeLlm):
        async def complete(self, system_prompt: str, user_prompt: str):
            seen["system"] = system_prompt
            return "Grounded analysis."

    run_analyst(monkeypatch, CapturingLlm())
    assert "Do NOT assign, estimate, change or rate a severity" in seen["system"]


def test_llm_context_carries_no_severity(monkeypatch):
    """The model echoed a context severity back as its own rating; severity is not an LLM input any more."""
    seen = {}

    class CapturingLlm(FakeLlm):
        async def complete(self, system_prompt: str, user_prompt: str):
            seen["user"] = user_prompt
            return "Grounded analysis."

    run_analyst(monkeypatch, CapturingLlm())
    assert "'severity'" not in seen["user"]
