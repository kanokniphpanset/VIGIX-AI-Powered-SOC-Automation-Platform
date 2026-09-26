"""LLM analyst agent.

Main reasoning step: evidence + threat intel + MITRE + alert.
The LLM produces a grounded analysis; structured findings are built
deterministically from AgentState.

No silent fallback: when the LLM call fails (unreachable, timeout, error
status, malformed or empty answer) the analysis is reported as FAILED —
`llm_summary` stays empty, a CRITICAL structured error with a specific code
is recorded (the pipeline status becomes FAILED, see output_contract.py) and
the failure is logged. The deterministic heuristic is kept ONLY as an
explicitly labelled `analyst_report.fallback` (source HEURISTIC_FALLBACK) for
the record; it is never written to `llm_summary` and never presented as an
LLM analysis.
"""

from __future__ import annotations

import logging

import httpx

from src.contracts.error import ErrorCode
from src.contracts.error_builder import build_error
from src.graph.state import AgentState
from src.llm.llama_provider import LlamaProvider

from .findings import build_key_findings
from .schema import AnalystReport

logger = logging.getLogger(__name__)

ANALYSIS_SOURCE_LLM = "LLM"
ANALYSIS_SOURCE_FAILED = "FAILED"
FALLBACK_SOURCE = "HEURISTIC_FALLBACK"

_llm: LlamaProvider | None = None


class LlmAnalysisError(Exception):
    """The LLM answered, but not with a usable analysis (empty / not text)."""


def _get_llm() -> LlamaProvider:
    global _llm

    if _llm is None:
        # The Settings INSTANCE (src.config.settings.settings) — `from src.config import settings` would bind the
        # settings MODULE, whose missing llm_* attributes made every call fail and fall back silently.
        from src.config.settings import settings

        _llm = LlamaProvider(
            settings.llm_base_url,
            settings.llm_model,
            settings.llm_timeout_seconds,
            api_key=settings.llm_api_key,
        )

    return _llm


def _llm_model() -> str | None:
    from src.config.settings import settings

    return settings.llm_model


def _build_context(state: AgentState) -> dict:
    """Build only evidence already present in AgentState.

    The incident severity is deliberately NOT part of the LLM context: it is set only by the Wazuh rule level, and
    given to the model it was echoed back as a "Severity: …" rating inside the analysis (seen in the real-LLM E2E).
    """

    return {
        "alert": state.get("raw_alert") or {},
        "alert_text": state.get("alert_text", ""),
        "iocs": state.get("iocs") or [],
        "threat_intel": state.get("threat_intel_report") or {},
        "mitre": state.get("mitre_mapping_report") or {},
        "rag": state.get("rag_result") or {},
    }


def _heuristic_analysis(state: AgentState) -> AnalystReport:
    """Deterministic, non-LLM summary. Kept only as a labelled fallback record — never shown as an LLM analysis."""

    # The Wazuh rule-level severity (the only severity VIGIX has). The analyst never produces one.
    severity = state.get("severity") or "unknown"
    alert_text = state.get("alert_text", "")

    text_lower = alert_text.lower()

    if any(term in text_lower for term in ("failed password", "brute force", "invalid user")):
        classification = "BRUTE_FORCE"
        hypothesis = "Repeated authentication failures may indicate brute-force activity."
    else:
        classification = "UNKNOWN"
        hypothesis = "The available evidence does not support a more specific classification."

    findings = build_key_findings(state)

    evidence_ids: list[str] = []
    for finding in findings:
        for evidence in finding.get("evidence", []):
            if evidence not in evidence_ids:
                evidence_ids.append(evidence)

    analysis_parts = [
        f"Alert severity: {severity}.",
        hypothesis,
    ]

    if findings:
        analysis_parts.append(
            f"{len(findings)} evidence-backed finding(s) were identified."
        )

    return AnalystReport(
        classification=classification,
        hypotheses=[hypothesis],
        analysis=" ".join(analysis_parts),
        unknowns=["LLM analysis was unavailable; heuristic analysis was used."],
        evidence_ids=evidence_ids,
    )


async def run_analyst_async(state: AgentState) -> AnalystReport:
    """Run the LLM analysis. Raises on any failure — the caller (run) records it; nothing is swallowed here."""

    context = _build_context(state)

    findings = build_key_findings(state)

    system_prompt = """You are a cybersecurity SOC analyst.

Analyze only the evidence provided in the context.
Do not invent facts, indicators, MITRE techniques, or actions.

Return a concise analyst assessment containing:
1. classification
2. hypotheses
3. analysis
4. unknowns

Every conclusion must be grounded in the supplied evidence.
If evidence is insufficient, explicitly state the uncertainty.

Do NOT assign, estimate, change or rate a severity or risk level. Severity is
set only by the Wazuh rule level and is not part of your assessment.
"""

    user_prompt = (
        "Analyze this security alert using only the following context:\n\n"
        f"{context}\n\n"
        f"Structured evidence-backed findings:\n{findings}\n"
    )

    response = await _get_llm().complete(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
    )

    if not isinstance(response, str) or not response.strip():
        raise LlmAnalysisError("The LLM returned an empty or non-text analysis.")

    evidence_ids: list[str] = []
    for finding in findings:
        for evidence in finding.get("evidence", []):
            if evidence not in evidence_ids:
                evidence_ids.append(evidence)

    return AnalystReport(
        classification="SECURITY_EVENT",
        hypotheses=[],
        analysis=response.strip(),
        unknowns=[],
        evidence_ids=evidence_ids,
    )


def _failure_code(exc: Exception) -> ErrorCode:
    """Map an LLM failure to the Universal Error Contract code the SOC and the report can count."""

    if isinstance(exc, httpx.TimeoutException):
        return ErrorCode.LLM_TIMEOUT
    if isinstance(exc, (httpx.HTTPStatusError, httpx.TransportError)):
        return ErrorCode.LLM_UNAVAILABLE
    if isinstance(exc, (LlmAnalysisError, KeyError, IndexError, TypeError, ValueError)):
        return ErrorCode.LLM_INVALID_RESPONSE
    return ErrorCode.AGENT_EXECUTION_FAILED


async def run(state: AgentState) -> AgentState:
    """LangGraph LLM analyst node."""

    try:
        report = await run_analyst_async(state)
    except Exception as exc:  # noqa: BLE001 - every failure is recorded below, never swallowed
        code = _failure_code(exc)
        logger.warning(
            "LLM analysis failed: code=%s exception=%s message=%s",
            code.value,
            type(exc).__name__,
            str(exc)[:300],
        )
        error = build_error(
            agent="llm_analyst",
            code=code.value,
            message=f"LLM analysis failed ({type(exc).__name__}): {str(exc)[:500]}",
            retryable=code is not ErrorCode.LLM_INVALID_RESPONSE,
            # CRITICAL: without the LLM analysis the AI Analysis itself failed -> pipeline status FAILED.
            severity="CRITICAL",
            id=f"llm_analyst-{code.value.lower()}",
            metadata={"exceptionClass": type(exc).__name__, "model": _llm_model()},
        )
        fallback = _heuristic_analysis(state)
        return {
            "analysis_source": ANALYSIS_SOURCE_FAILED,
            "llm_summary": None,
            "llm_key_findings": [],
            "analyst_report": {
                "status": "FAILED",
                "source": ANALYSIS_SOURCE_FAILED,
                "error": {"code": code.value, "message": error.message},
                # Kept for the record only — NOT an LLM output, never shown as the AI Analysis.
                "fallback": {
                    "source": FALLBACK_SOURCE,
                    "classification": fallback.classification,
                    "hypotheses": fallback.hypotheses,
                    "analysis": fallback.analysis,
                    "evidence_ids": fallback.evidence_ids,
                },
            },
            "structured_errors": [error.model_dump(by_alias=True, mode="json")],
            "trace": [f"LLMAnalystAgent: FAILED ({code.value}, {type(exc).__name__}) — no LLM analysis produced"],
        }

    findings = build_key_findings(state)
    model = _llm_model()

    return {
        "analysis_source": ANALYSIS_SOURCE_LLM,
        "analyst_report": {
            "status": "SUCCESS",
            "source": ANALYSIS_SOURCE_LLM,
            "model": model,
            "classification": report.classification,
            "hypotheses": report.hypotheses,
            "analysis": report.analysis,
            "unknowns": report.unknowns,
            "evidence_ids": report.evidence_ids,
            "key_findings": findings,
        },
        "classification": {
            "type": report.classification,
            "confidence": None,  # no model confidence: VIGIX has no ML severity/risk classifier
            "evidence_ids": report.evidence_ids,
        },
        "llm_summary": report.analysis,
        "llm_key_findings": findings,
        "trace": [
            (
                f"LLMAnalystAgent: source=LLM model={model} "
                f"classification={report.classification}, "
                f"evidence_count={len(report.evidence_ids)}"
            )
        ],
    }
