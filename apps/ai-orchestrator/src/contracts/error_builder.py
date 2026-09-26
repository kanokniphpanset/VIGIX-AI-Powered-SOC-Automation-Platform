"""
build_error() + per-agent ErrorItem adapters.

Every adapter below reads a structured field an agent ALREADY writes today
— it never parses/guesses from `trace`'s free text where a structured
field exists, and it never touches threat_intel_agent/mitre_agent/
rag_agent/llm_analyst_agent. One exception, called out
explicitly where it happens: LlmAnalystAgent has no structured failure
field at all today (only `trace` strings), so `llm_analyst_errors()` is a
documented best-effort trace-string match against that agent's own,
already-stable wording (see agent.py::_call_llm) — the one adapter here
that isn't a pure structured-field read.
"""

from __future__ import annotations

import re
import uuid
from itertools import count

from .error import ErrorCode, ErrorItem, Severity

# Per-provider statuses that represent an actual failure to get an answer —
# see threat_intel_agent/types.py::ProviderStatus. SUCCESS/NO_MATCH are real
# answers (not failures); NOT_SUPPORTED is expected/legitimate (that
# provider was never going to handle this IOC type), not a failure either.
_THREAT_INTEL_FAILURE_STATUSES = {"TIMEOUT", "RATE_LIMITED", "FAILED", "NOT_CONFIGURED", "INVALID_INDICATOR"}

_THREAT_INTEL_STATUS_TO_CODE: dict[str, tuple[ErrorCode, bool, Severity]] = {
    # status -> (code, retryable, severity)
    "TIMEOUT": (ErrorCode.PROVIDER_TIMEOUT, True, "WARNING"),
    "RATE_LIMITED": (ErrorCode.PROVIDER_UNAVAILABLE, True, "WARNING"),
    "FAILED": (ErrorCode.PROVIDER_UNAVAILABLE, True, "WARNING"),
    "NOT_CONFIGURED": (ErrorCode.PROVIDER_NOT_CONFIGURED, False, "INFO"),
    "INVALID_INDICATOR": (ErrorCode.AGENT_INPUT_INVALID, False, "INFO"),
}

# Legacy plain-text `errors: list[str]` entries already structurally covered
# by an adapter below — a leftover-wrapping fallback (see
# _legacy_leftover_errors) skips anything starting with these so a real
# failure is never reported twice under two different codes.
_COVERED_LEGACY_PREFIXES = ("ThreatIntelAgent:", "MitreAgent:")

_LLM_UNAVAILABLE_RE = re.compile(r"LlmAnalystAgent: LLM unavailable \(([^)]+)\), used fallback (\w+)")
_LLM_INVALID_RESPONSE_RE = re.compile(r"LlmAnalystAgent: invalid LLM response, used fallback (\w+)")
_LLM_PROMPT_FAILED_RE = re.compile(r"LlmAnalystAgent: prompt loading failed, used fallback (\w+)")


def build_error(
    agent: str,
    code: str,
    message: str,
    retryable: bool,
    severity: Severity,
    id: str | None = None,
    timestamp: str | None = None,
    traceability: dict | None = None,
    metadata: dict | None = None,
) -> ErrorItem:
    """
    The small, explicit constructor section 5 asks for — normalizes the
    optional fields (never `None` for dict fields, so a consumer never has
    to null-check `traceability`/`metadata`) and generates an id when the
    caller doesn't need a deterministic one. Intentionally not a
    "framework": no retry logic, no side effects, just a validated
    ErrorItem.
    """
    return ErrorItem(
        id=id or f"{agent}-{code.lower()}-{uuid.uuid4().hex[:8]}",
        agent=agent,
        code=code,
        message=message,
        retryable=retryable,
        severity=severity,
        timestamp=timestamp,
        traceability=traceability or {},
        metadata=metadata or {},
    )


def threat_intel_errors(state: dict) -> list[ErrorItem]:
    """
    Reads threat_intel_report.indicators[].providers[] — the same
    structured report ioc_and_threat_intel_evidence() (evidence.py) already
    reads for the success side of this same data.

    BUG FIX (LangGraph Integration task, found via live smoke test): this
    previously read `indicator.get("indicator")`/`.get("type")`, matching
    ThreatIntelData.to_dict()'s shape rather than the REAL contract
    threat_intel_agent/result_contract.py::build_result_contract actually
    produces (`ioc`/`iocType`) — every ErrorItem's traceability silently
    carried `indicator: null` in production. See
    evidence.py::ioc_and_threat_intel_evidence's own docstring for the same
    root cause fixed there.
    """
    report = state.get("threat_intel_report") or {}
    indicators = report.get("indicators") or []
    counter = count()
    items: list[ErrorItem] = []

    for indicator in indicators:
        for provider_result in indicator.get("providers") or []:
            status = provider_result.get("status")
            if status not in _THREAT_INTEL_FAILURE_STATUSES:
                continue
            code, retryable, severity = _THREAT_INTEL_STATUS_TO_CODE[status]
            provider_name = provider_result.get("provider", "unknown provider")
            items.append(
                build_error(
                    agent="threat_intel",
                    code=code,
                    message=provider_result.get("error") or f"{provider_name} returned {status} for {indicator.get('ioc', 'unknown indicator')}",
                    retryable=retryable,
                    severity=severity,
                    id=f"threat_intel-{code.value.lower()}-{next(counter)}",
                    traceability={"indicator": indicator.get("ioc"), "indicatorType": indicator.get("iocType")},
                    metadata={"provider": provider_name},
                )
            )
    return items


def mitre_errors(state: dict) -> list[ErrorItem]:
    """
    Reads mitre_mapping_report — the "reason" key is only ever set by
    mitre_agent/agent.py when the MITRE catalog itself couldn't be fetched
    (a real failure), never for the legitimate "no behavioral evidence
    matched any technique" outcome (same result value, no "reason" key) —
    see mitre_agent/agent.py's own two NO_SUPPORTED_MAPPING construction
    sites. Only the former is an error; the latter is a normal, non-error
    finding (mirrors how rag_agent's noRelevantPlaybook isn't an error
    either).
    """
    report = state.get("mitre_mapping_report") or {}
    if report.get("result") == "NO_SUPPORTED_MAPPING" and "reason" in report:
        return [
            build_error(
                agent="mitre",
                code=ErrorCode.PROVIDER_UNAVAILABLE,
                message=report["reason"],
                retryable=True,
                severity="ERROR",
                id="mitre-provider_unavailable-0",
                metadata={"mitreVersion": report.get("mitreVersion")},
            )
        ]
    return []


def rag_errors(state: dict) -> list[ErrorItem]:
    """Reads rag_result.traceability.knowledgeRetrievalStatus/playbookRetrievalStatus — the exact structured status retriever.py's SourceRetrievalResult already produces (OK|EMBEDDING_FAILED|SEARCH_FAILED)."""
    rag_result = state.get("rag_result") or {}
    traceability = rag_result.get("traceability") or {}
    status_code_map = {"EMBEDDING_FAILED": ErrorCode.EMBEDDING_FAILED, "SEARCH_FAILED": ErrorCode.SEARCH_FAILED}
    items: list[ErrorItem] = []

    for collection_key, label in (("knowledgeRetrievalStatus", "knowledge"), ("playbookRetrievalStatus", "playbook")):
        status = traceability.get(collection_key)
        code = status_code_map.get(status)
        if code is None:
            continue
        items.append(
            build_error(
                agent="rag",
                code=code,
                message=f"RAG {label} retrieval failed ({status})",
                retryable=True,
                severity="ERROR",
                id=f"rag-{code.value.lower()}-{label}",
                metadata={"collection": label},
            )
        )
    return items


def llm_analyst_errors(state: dict) -> list[ErrorItem]:
    """
    The one adapter in this module that reads `trace` instead of a
    structured field — llm_analyst_agent/agent.py has no structured failure
    field today (see its own module docstring: "this architecture has no
    JSON schema for the LLM's response"), only these three exact,
    already-tested trace phrasings from _call_llm().

    Trace entries may be either plain strings or structured dictionaries.
    Normalize them to text before applying the regex match so that error
    reporting never crashes when a structured trace entry is present.
    """
    items: list[ErrorItem] = []
    counter = count()

    for entry in state.get("trace") or []:
        # Trace can contain either a plain string or a structured dict.
        # The error matcher operates on text, so normalize safely.
        if isinstance(entry, dict):
            entry_text = (
                entry.get("message")
                or entry.get("error")
                or entry.get("detail")
                or str(entry)
            )
        else:
            entry_text = str(entry)

        match = _LLM_UNAVAILABLE_RE.search(entry_text)
        if match:
            exception_class, label = match.group(1), match.group(2)
            is_timeout = "timeout" in exception_class.lower()
            items.append(
                build_error(
                    agent="llm_analyst",
                    code=(
                        ErrorCode.LLM_TIMEOUT
                        if is_timeout
                        else ErrorCode.LLM_UNAVAILABLE
                    ),
                    message=entry_text,
                    retryable=True,
                    severity="WARNING",
                    id=(
                        f"llm_analyst-"
                        f"{'llm_timeout' if is_timeout else 'llm_unavailable'}-"
                        f"{next(counter)}"
                    ),
                    metadata={
                        "exceptionClass": exception_class,
                        "call": label,
                    },
                )
            )
            continue

        match = _LLM_INVALID_RESPONSE_RE.search(entry_text)
        if match:
            items.append(
                build_error(
                    agent="llm_analyst",
                    code=ErrorCode.LLM_INVALID_RESPONSE,
                    message=entry_text,
                    retryable=False,
                    severity="WARNING",
                    id=f"llm_analyst-llm_invalid_response-{next(counter)}",
                    metadata={"call": match.group(1)},
                )
            )
            continue

        match = _LLM_PROMPT_FAILED_RE.search(entry_text)
        if match:
            items.append(
                build_error(
                    agent="llm_analyst",
                    code=ErrorCode.AGENT_EXECUTION_FAILED,
                    message=entry_text,
                    retryable=False,
                    severity="WARNING",
                    id=f"llm_analyst-agent_execution_failed-{next(counter)}",
                    metadata={"call": match.group(1)},
                )
            )

    return items


def _legacy_leftover_errors(state: dict) -> list[ErrorItem]:
    """
    Safety net, not a primary source: wraps any plain-text `errors` entry
    NOT already explained by a structured adapter above, so migrating to
    the structured contract never silently drops information a legacy
    agent (validation/decision/business_analytics/feedback — out of scope
    for this task's agent mapping) already reported. Deliberately
    conservative: UNKNOWN_ERROR / not retryable / ERROR severity, since
    nothing more specific can be inferred from a free-text string.
    """
    counter = count()
    items: list[ErrorItem] = []
    for entry in state.get("errors") or []:
        if any(entry.startswith(prefix) for prefix in _COVERED_LEGACY_PREFIXES):
            continue
        agent_guess = entry.split(":", 1)[0].strip() if ":" in entry else "unknown"
        items.append(
            build_error(
                agent=agent_guess,
                code=ErrorCode.UNKNOWN_ERROR,
                message=entry,
                retryable=False,
                severity="ERROR",
                id=f"legacy-unknown_error-{next(counter)}",
            )
        )
    return items


def _emitted_errors(state: dict) -> list[ErrorItem]:
    """ErrorItems agents wrote directly to state["structured_errors"] — e.g. an
    agent's last-resort `except` in run(), which writes no report for the
    adapters above to derive from. Entries that don't validate are skipped."""
    items: list[ErrorItem] = []
    for entry in state.get("structured_errors") or []:
        try:
            items.append(ErrorItem.model_validate(entry))
        except Exception:  # noqa: BLE001 - a malformed entry must not break error reporting
            continue
    return items


def build_errors(state: dict) -> list[ErrorItem]:
    """Concatenates every agent's structured errors plus any unexplained legacy leftovers, in a fixed order. Never raises just because one source is absent."""
    items = [
        *threat_intel_errors(state),
        *mitre_errors(state),
        *rag_errors(state),
        *llm_analyst_errors(state),
        *_emitted_errors(state),
        *_legacy_leftover_errors(state),
    ]
    seen: set[str] = set()
    unique: list[ErrorItem] = []
    for item in items:
        if item.id not in seen:
            seen.add(item.id)
            unique.append(item)
    return unique
