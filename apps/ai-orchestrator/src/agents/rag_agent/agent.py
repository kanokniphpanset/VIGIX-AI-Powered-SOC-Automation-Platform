"""RAG agent.

Finds extra context (policy, playbook, procedure text) for the case through
rag_retrieval_tool.

Rule:
- It does NOT choose the runbook.
- It does NOT build the RunbookSnapshot.
- runbook/resolver.py owns runbook selection deterministically from
  incident type + severity.
- RAG retrieval only provides supporting text.
"""

from __future__ import annotations

from typing import Any

import logging

from src.contracts.error import ErrorCode
from src.contracts.error_builder import build_error
from src.contracts.tool_result import ToolResult
from src.graph.state import AgentState

from .query_builder import build_semantic_query, extract_query_input

logger = logging.getLogger(__name__)


def run_rag(
    query: str,
    *,
    incident_type: str | None = None,
    severity: str | None = None,
    document_type: str | None = None,
    top_k: int = 5,
) -> ToolResult:
    """Retrieve supporting RAG context.

    This function only performs semantic retrieval. It does not select
    or construct a runbook snapshot.
    """
    from src.tools.rag_retrieval_tool import retrieve

    return retrieve(
        query,
        incident_type=incident_type,
        severity=severity,
        document_type=document_type,
        active_only=True,
        top_k=top_k,
    )


def run(state: AgentState) -> dict[str, Any]:
    """LangGraph adapter for the RAG agent.

    Builds a deterministic semantic query from the current AgentState,
    retrieves supporting document chunks, and writes only rag_result.
    """
    query_input = extract_query_input(state)
    query = build_semantic_query(query_input)

    result = run_rag(
        query,
        incident_type=query_input.incident_type,
        severity=state.get("severity"),
        top_k=5,
    )

    if result.ok:
        return {
            "rag_result": result.data,
        }

    rag_result = {
        "chunks": [],
        "status": result.status,
        "source": result.source,
        "error": result.error,
    }

    # "not_found" is an answer (the knowledge base has nothing relevant), not a failure.
    if result.is_answer:
        return {"rag_result": rag_result}

    # No silent RAG failure: the knowledge base / vector search could not answer (Qdrant down, backend search
    # error, embedding failure). Recorded as a structured error -> pipeline status PARTIAL_SUCCESS, never SUCCESS.
    logger.warning("RAG retrieval failed: status=%s error=%s", result.status, (result.error or "")[:300])
    error = build_error(
        agent="rag",
        code=ErrorCode.SEARCH_FAILED.value,
        message=f"RAG retrieval failed ({result.status}): {result.error or 'no detail'}",
        retryable=True,
        severity="ERROR",
        id="rag-search_failed-retrieval",
        metadata={"toolStatus": result.status},
    )
    return {
        "rag_result": rag_result,
        "structured_errors": [error.model_dump(by_alias=True, mode="json")],
        "trace": [f"RagAgent: retrieval FAILED ({result.status})"],
    }