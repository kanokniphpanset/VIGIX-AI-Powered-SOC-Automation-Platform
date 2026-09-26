"""
Steps 2-3 of the RAG pipeline (the HTTP half) — calls the backend's
existing Vector Search Service instead of talking to Qdrant directly.

The backend already implements the Knowledge Base, embedding pipeline, and
Vector Search Service (see apps/backend/src/domain/knowledge/services/
VectorSearchService.ts and apps/backend/src/presentation/http/controllers/
KnowledgeSearchController.ts, mounted at POST /api/v1/knowledge/search).
This module is the ONLY place RagAgent reaches that endpoint — reusing the
existing dimension validation, filter building, and error handling rather
than reimplementing any of it against Qdrant a second time.
"""

from __future__ import annotations

import asyncio

import httpx


class VectorSearchClientError(Exception):
    """
    The backend's vector search failed — network error, timeout, or the
    backend itself reported a vector-database failure. Always raised,
    never swallowed into an empty result: RagAgent's own caller decides
    whether/how to degrade gracefully (see agent.py), but this client
    itself never fabricates a "no results" answer out of a real failure.
    """


class VectorSearchClient:
    def __init__(
        self,
        backend_url: str,
        timeout_s: float = 10.0,
        max_retries: int = 2,
        http_client: httpx.AsyncClient | None = None,
    ):
        self._base_url = backend_url.rstrip("/")
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        # Client lifecycle (fixes "Event loop is closed"): rag_retrieval_tool
        # is a SYNCHRONOUS tool that runs every retrieval in its own
        # asyncio.run() — a new event loop per call, closed when the call
        # returns. An httpx.AsyncClient's connection pool is bound to the
        # loop that first used it, so one client created at import time and
        # reused by the next call (a different, new loop) fails with "Event
        # loop is closed". Therefore:
        #   - no client injected -> search() opens its own AsyncClient for the
        #     duration of that call (`async with`): created, used and closed
        #     inside the running loop, never shared across loops;
        #   - client injected (tests: httpx.MockTransport) -> the caller owns
        #     it and its lifecycle; it is reused and never closed here.
        self._http_client = http_client

    async def search(
        self,
        embedding: list[float],
        top_k: int,
        min_score: float | None = None,
        filters: dict | None = None,
    ) -> list[dict]:
        body: dict = {"embedding": embedding, "topK": top_k}
        if min_score is not None:
            body["minScore"] = min_score
        if filters:
            body["filters"] = filters

        if self._http_client is not None:
            return await self._search_with(self._http_client, body)
        async with httpx.AsyncClient(timeout=self._timeout_s) as client:
            return await self._search_with(client, body)

    async def _search_with(self, client: httpx.AsyncClient, body: dict) -> list[dict]:
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await client.post(f"{self._base_url}/api/v1/knowledge/search", json=body)
                response.raise_for_status()
                return response.json().get("results", [])
            except httpx.HTTPStatusError as exc:
                # A 4xx means the request itself was rejected (bad embedding
                # dimension, invalid topK) — retrying an unchanged request
                # would just fail identically.
                if exc.response.status_code < 500:
                    raise VectorSearchClientError(
                        f"Vector search rejected the request: HTTP {exc.response.status_code}"
                    ) from exc
                last_error = exc
            except httpx.HTTPError as exc:
                last_error = exc

            if attempt < self._max_retries:
                await asyncio.sleep(0.5 * (2**attempt))

        raise VectorSearchClientError(
            f"Vector search failed after {self._max_retries + 1} attempt(s): {last_error}"
        ) from last_error
