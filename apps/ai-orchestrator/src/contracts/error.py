"""
ErrorItem — the Universal Error Contract.

A structured, machine-readable failure/degradation record every agent's
output can be adapted into, sitting alongside (never conflated with)
`trace` (free-text execution/debug log) and `evidence` (facts the analysis
is grounded in). Same CamelModel convention as contracts/normalized_alert.py
and contracts/evidence.py (camelCase JSON, snake_case Python).

Like evidence.py, this module never touches threat_intel_agent, mitre_agent,
rag_agent, or llm_analyst_agent — see error_builder.py for
the adapters that read each agent's already-existing structured output and
produce ErrorItem lists from it.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field

from ._base import CamelModel

Severity = Literal["INFO", "WARNING", "ERROR", "CRITICAL"]


class ErrorCode(str, Enum):
    """
    The centralized error-code convention (section 2). Deliberately small —
    one code per *class* of failure an agent can actually produce today, not
    one per agent/provider/exception-type combination. `ErrorItem.code` is
    typed as a plain `str` (not this enum) so a future agent can introduce a
    new code without a contract-layer change; this enum is the known,
    reusable menu every adapter in error_builder.py picks from.
    """

    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PROVIDER_NOT_CONFIGURED = "PROVIDER_NOT_CONFIGURED"
    PROVIDER_INVALID_RESPONSE = "PROVIDER_INVALID_RESPONSE"

    VALIDATION_FAILED = "VALIDATION_FAILED"

    EMBEDDING_FAILED = "EMBEDDING_FAILED"
    SEARCH_FAILED = "SEARCH_FAILED"
    RETRIEVAL_FAILED = "RETRIEVAL_FAILED"

    LLM_TIMEOUT = "LLM_TIMEOUT"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    LLM_INVALID_RESPONSE = "LLM_INVALID_RESPONSE"

    AGENT_INPUT_INVALID = "AGENT_INPUT_INVALID"
    AGENT_EXECUTION_FAILED = "AGENT_EXECUTION_FAILED"

    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class ErrorItem(CamelModel):
    """
    Section 7's semantics, enforced by convention (never inferred from one
    another — retryable and severity are independent axes, exactly as
    required):
      INFO     — informational degradation, normally doesn't block the pipeline
      WARNING  — degraded functionality, pipeline continues
      ERROR    — significant agent failure, pipeline may continue if downstream can operate safely
      CRITICAL — pipeline cannot safely continue
      retryable=True  — a transient failure that may succeed on retry
      retryable=False — retrying is unlikely to help
    """

    id: str
    agent: str
    code: str
    message: str
    retryable: bool
    severity: Severity

    timestamp: datetime | None = None
    traceability: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)
