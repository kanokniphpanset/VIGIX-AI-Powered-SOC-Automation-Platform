"""RAG retrieval tool.

Search only. It does NOT choose the runbook; runbook/resolver.py does that
from incident type + severity.

The retrieval path reuses the existing RagRetriever:
query -> BGE embedding -> Backend Vector Search API -> Qdrant.

Only active knowledge/playbook documents are retrieved through the existing
retriever contract. This tool does not execute actions or build runbooks.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from src.agents.rag_agent.retriever import RagRetriever
from src.agents.rag_agent.vector_search_client import VectorSearchClient
from src.config.settings import settings
from src.contracts.tool_result import ToolResult
from src.embeddings.bge_embedding_provider import BgeEmbeddingProvider

SOURCE = "rag_retrieval"

_embedding_provider = BgeEmbeddingProvider(settings.embedding_model)

_vector_search_client = VectorSearchClient(
    settings.backend_url,
    service_token=settings.backend_service_token or None,
    timeout_s=settings.rag_vector_search_timeout_s,
    max_retries=settings.rag_vector_search_max_retries,
)

_retriever = RagRetriever(
    _embedding_provider,
    _vector_search_client,
    top_k=settings.rag_top_k,
    playbook_top_k=settings.rag_playbook_top_k,
)


def _build_filters(
    *,
    incident_type: Optional[str],
    severity: Optional[str],
    document_type: Optional[str],
    active_only: bool,
) -> dict:
    """Build only filters supported by the existing RagRetriever/backend."""

    filters: dict[str, list[str | bool]] = {}

    if incident_type:
        filters["incidentTypes"] = [incident_type]

    # Severity is intentionally not used as a metadata filter because
    # the current indexed documents do not expose a verified severity key.

    # PLAYBOOK is represented by sourceType=PLAYBOOK in the current
    # backend metadata, so it must not be sent as documentType=PLAYBOOK.
    if document_type and document_type != "PLAYBOOK":
        filters["documentType"] = [document_type]

    # active_only is intentionally not converted into a guessed metadata
    # filter because the current backend retrieval contract does not expose
    # a verified active-version filter key.

    return filters


def _normalize_chunk(document: dict) -> dict:
    """Map backend search results into the tool's stable chunk contract."""

    metadata = document.get("metadata") or {}

    return {
        "doc_id": document.get("documentId") or document.get("id"),
        "document_type": (
            document.get("documentType")
            or metadata.get("documentType")
            or metadata.get("document_type")
        ),
        "version": metadata.get("version"),
        "section": metadata.get("section") or document.get("title"),
        "content": document.get("content", ""),
        "score": document.get("score"),
    }


async def _retrieve_async(
    query: str,
    *,
    incident_type: Optional[str],
    severity: Optional[str],
    document_type: Optional[str],
    active_only: bool,
    top_k: int,
) -> tuple[str, list[dict], str | None]:

    filters = _build_filters(
        incident_type=incident_type,
        severity=severity,
        document_type=document_type,
        active_only=active_only,
    )

    # The current RAG retriever has two verified source types:
    # KNOWLEDGE and PLAYBOOK.
    if document_type == "POLICY":
        result = await _retriever.retrieve_knowledge(
            query,
            filters=filters,
        )
    else:
        result = await _retriever.retrieve_playbooks(
            query,
            filters=filters,
        )

    if result.status != "OK":
        return result.status.lower(), [], result.error

    chunks = [
        _normalize_chunk(document)
        for document in result.documents[:top_k]
    ]

    if not chunks:
        return "not_found", [], None

    return "ok", chunks, None


def _run_async(coro):
    """Run the async retrieval from the synchronous tool contract."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # The normal LangGraph tool path is synchronous. If called while an event
    # loop is already running, execute the coroutine in a dedicated thread so
    # asyncio.run() does not conflict with the caller's loop.
    import threading

    result: dict[str, object] = {}
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:
            error.append(exc)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()

    if error:
        raise error[0]

    return result["value"]


def retrieve(
    query: str,
    *,
    incident_type: Optional[str] = None,
    severity: Optional[str] = None,
    document_type: Optional[str] = None,   # POLICY | PLAYBOOK | PROCEDURE
    active_only: bool = True,
    top_k: int = 5,
) -> ToolResult:
    """Retrieve supporting RAG context.

    This function only performs retrieval. It does not select a runbook,
    construct a runbook snapshot, authorize a response, or execute actions.
    """

    queried_at = datetime.now(timezone.utc)

    if not query or not query.strip():
        return ToolResult(
            status="error",
            source=SOURCE,
            query=query,
            data={"chunks": []},
            queried_at=queried_at,
            error="RAG query must not be empty.",
        )

    if top_k <= 0:
        return ToolResult(
            status="error",
            source=SOURCE,
            query=query,
            data={"chunks": []},
            queried_at=queried_at,
            error="top_k must be greater than 0.",
        )

    try:
        status, chunks, error = _run_async(
            _retrieve_async(
                query,
                incident_type=incident_type,
                severity=severity,
                document_type=document_type,
                active_only=active_only,
                top_k=top_k,
            )
        )
    except Exception as exc:
        return ToolResult(
            status="error",
            source=SOURCE,
            query=query,
            data={"chunks": []},
            queried_at=queried_at,
            error=str(exc),
        )

    return ToolResult(
        status=status,
        source=SOURCE,
        query=query,
        data={"chunks": chunks},
        queried_at=queried_at,
        error=error,
    )