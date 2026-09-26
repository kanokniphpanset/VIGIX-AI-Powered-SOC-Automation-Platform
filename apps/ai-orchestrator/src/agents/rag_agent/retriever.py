"""
Steps 2-4 of the RAG pipeline — Generate an embedding, Perform vector
search, Retrieve Top K documents.

Phase D adds dual-collection retrieval: RagAgent now needs one search
scoped to KNOWLEDGE content ("what is this / how does it work") and an
independent one scoped to PLAYBOOK content ("how do I respond") — see
retrieve_knowledge()/retrieve_playbooks() below. A failure in either search
must never block the other (a playbook-collection outage shouldn't cost
the agent knowledge results it already has, and vice versa) — each is
caught independently and reported as a SourceRetrievalResult rather than
raised, so agent.py never has to wrap these two in yet another try/except
to keep the graph node from crashing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal

from src.embeddings.provider_interface import IEmbeddingProvider
from .vector_search_client import VectorSearchClient, VectorSearchClientError

# Filter keys the backend's /api/v1/knowledge/search contract actually
# documents today (see vector_search_client.py's module docstring). Only
# these are ever forwarded over the wire — anything else RagQueryConstructor
# threads through (e.g. `platform`, used for query *phrasing* rather than as
# a hard filter — see query_constructor.py) is silently dropped here rather
# than sent as a field the backend's schema doesn't expect.
_BACKEND_FILTER_KEYS = {
    "mitreTechniques",
    "incidentTypes",
    "malwareFamilies",
    "documentType",
    "source",
    "sourceType",
    "sourceProvider",
    "scenario",
    # Explainable Retrieval task — the backend's buildFilter() (Qdrant
    # QdrantVectorSearchService.ts) now translates these too. Whitelisted
    # here so a caller CAN pass them through as a real hard filter if
    # explicitly configured to — agent.py deliberately does not do so by
    # default (see its own comment on the 2026-08-26 empirical recall
    # finding); this only makes the capability available, doesn't turn it on.
    "platforms",
    "tags",
    "phase",
}

SourceRetrievalStatus = Literal["OK", "EMBEDDING_FAILED", "SEARCH_FAILED"]


class EmbeddingGenerationError(Exception):
    """The embedding provider failed to embed the query text — never silently treated as 'no results'."""


@dataclass
class SourceRetrievalResult:
    """
    Outcome of one KNOWLEDGE- or PLAYBOOK-scoped search — deliberately
    distinct from the "no relevant match" concept computed later by
    grounded_context_builder.py's knowledgeStatus/playbookStatus flags.
    This status describes whether the *call itself* succeeded; documents==[]
    with status=="OK" just means nothing matched, while a non-OK status
    means the search couldn't be attempted/completed at all — both end up
    surfaced (differently) in the final output's limitations.
    """

    documents: list[dict]
    status: SourceRetrievalStatus
    error: str | None = None


def _whitelist_filters(filters: dict | None) -> dict:
    if not filters:
        return {}
    return {key: value for key, value in filters.items() if key in _BACKEND_FILTER_KEYS and value}


class RagRetriever:
    """
    Composes the existing embedding provider (reused unchanged, in-process
    — RagAgent runs in the same Python process as BgeEmbeddingProvider, so
    no HTTP hop is needed here, unlike the backend's HttpEmbeddingService)
    with VectorSearchClient (the HTTP surface onto the existing, already-
    implemented Vector Search Service). Retrieval itself is unfiltered
    semantic search *within a source type*: MITRE/incident-type/malware-
    family/threat-category/scenario/source-priority matching are
    re-ranking *signals* (see reranker.py), not retrieval-time filters — a
    semantically strong candidate isn't excluded just because its metadata
    doesn't happen to tag every criterion. `sourceType` is the one filter
    retrieval itself always applies (via retrieve_knowledge/
    retrieve_playbooks below) — the two collections serve different
    downstream purposes and are never mixed at retrieval time.
    """

    def __init__(
        self,
        embedding_provider: IEmbeddingProvider,
        vector_search_client: VectorSearchClient,
        top_k: int,
        playbook_top_k: int | None = None,
    ):
        self._embedding_provider = embedding_provider
        self._vector_search_client = vector_search_client
        self._top_k = top_k
        # Defaults to top_k when unset so every pre-Phase-D caller/test
        # keeps constructing this with just `top_k=` and behaves exactly
        # as before — see config.py::RagConfig's own note on why the two
        # are independently configurable.
        self._playbook_top_k = playbook_top_k if playbook_top_k is not None else top_k

    async def retrieve(self, query: str, top_k: int | None = None, filters: dict | None = None) -> list[dict]:
        """The single-search primitive (Phase C behavior, preserved as-is): embeds `query`, then searches with `top_k` (defaults to the knowledge-side top_k from construction) and whatever `filters` are passed straight through — no whitelisting here, callers own that (see retrieve_knowledge/retrieve_playbooks, which do whitelist before calling this)."""
        try:
            # BgeEmbeddingProvider.embed() is a blocking sentence-transformers
            # call — offloaded to a thread so it doesn't stall the event loop
            # the rest of the FastAPI process (including other in-flight
            # graph runs) shares with this one.
            embedding = await asyncio.to_thread(self._embedding_provider.embed, query)
        except Exception as exc:
            raise EmbeddingGenerationError(str(exc)) from exc

        return await self._vector_search_client.search(
            embedding, top_k=top_k if top_k is not None else self._top_k, filters=filters
        )

    async def retrieve_knowledge(self, query: str, filters: dict | None = None) -> SourceRetrievalResult:
        return await self._retrieve_for_source(query, self._top_k, "KNOWLEDGE", filters)

    async def retrieve_playbooks(self, query: str, filters: dict | None = None) -> SourceRetrievalResult:
        return await self._retrieve_for_source(query, self._playbook_top_k, "PLAYBOOK", filters)

    async def _retrieve_for_source(
        self, query: str, top_k: int, source_type: Literal["KNOWLEDGE", "PLAYBOOK"], filters: dict | None
    ) -> SourceRetrievalResult:
        merged_filters = _whitelist_filters(filters)
        merged_filters["sourceType"] = [source_type]
        try:
            documents = await self.retrieve(query, top_k=top_k, filters=merged_filters)
            return SourceRetrievalResult(documents=documents, status="OK")
        except EmbeddingGenerationError as exc:
            return SourceRetrievalResult(documents=[], status="EMBEDDING_FAILED", error=str(exc))
        except VectorSearchClientError as exc:
            return SourceRetrievalResult(documents=[], status="SEARCH_FAILED", error=str(exc))
