"""
MitreKnowledgeBaseClient — fetches the real MITRE ATT&CK technique catalog
(~697 techniques, synced from the official mitre-attack/attack-stix-data
bundle) from the backend's existing GET /api/v1/mitre/techniques endpoint,
rather than re-reading apps/backend/data/mitre/techniques/*.json across the
app boundary or duplicating the catalog into this service. Same
reuse-the-backend-over-Qdrant-directly pattern rag_agent/vector_search_client.py
already uses for the Vector Search Service.

In-process TTL cache: 697 techniques is a few hundred KB of JSON — cheap to
hold in memory for the process lifetime and refresh periodically, rather
than re-fetching on every single alert.
"""

from __future__ import annotations

import asyncio
import time

import httpx

from .types import MitreTechniqueRecord


class MitreKnowledgeBaseError(Exception):
    """The backend's MITRE catalog couldn't be fetched — network error,
    timeout, or a non-2xx response. Always raised, never silently swallowed
    into an empty catalog: TechniqueMapper's caller decides how to degrade
    (see agent.py), but this client never fabricates "no techniques exist"
    out of a real fetch failure."""


class MitreKnowledgeBaseClient:
    def __init__(
        self,
        backend_url: str,
        timeout_s: float = 10.0,
        max_retries: int = 2,
        cache_ttl_s: float = 900.0,
        http_client: httpx.AsyncClient | None = None,
    ):
        self._base_url = backend_url.rstrip("/")
        self._timeout_s = timeout_s
        self._max_retries = max_retries
        self._cache_ttl_s = cache_ttl_s
        self._http_client = http_client or httpx.AsyncClient(timeout=timeout_s)
        self._cache: dict[str, MitreTechniqueRecord] | None = None
        self._cache_loaded_at: float = 0.0
        self._lock = asyncio.Lock()
        self._version_cache: str | None = None
        self._version_cache_loaded_at: float = 0.0

    async def get_catalog(self) -> dict[str, MitreTechniqueRecord]:
        """Returns {techniqueId: MitreTechniqueRecord} for the full real catalog. Cached, refreshed after cache_ttl_s."""
        async with self._lock:
            if self._cache is not None and (time.monotonic() - self._cache_loaded_at) < self._cache_ttl_s:
                return self._cache

            last_error: Exception | None = None
            for attempt in range(self._max_retries + 1):
                try:
                    response = await self._http_client.get(f"{self._base_url}/api/v1/mitre/techniques")
                    response.raise_for_status()
                    raw = response.json().get("techniques", [])
                    catalog = {
                        item["techniqueId"]: MitreTechniqueRecord(
                            technique_id=item["techniqueId"],
                            name=item["name"],
                            tactics=item.get("tactics", []),
                            description=item.get("description", ""),
                            detection=item.get("detection", ""),
                        )
                        for item in raw
                    }
                    self._cache = catalog
                    self._cache_loaded_at = time.monotonic()
                    return catalog
                except httpx.HTTPStatusError as exc:
                    last_error = exc
                    if exc.response.status_code < 500:
                        break  # a 4xx won't fix itself on retry
                except httpx.HTTPError as exc:
                    last_error = exc

                if attempt < self._max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))

            if self._cache is not None:
                # Serve the stale cache rather than fail outright — a
                # temporarily unreachable backend shouldn't stop mapping
                # entirely when we already have a recent, real catalog.
                return self._cache
            raise MitreKnowledgeBaseError(
                f"Failed to fetch MITRE technique catalog after {self._max_retries + 1} attempt(s): {last_error}"
            ) from last_error

    async def get_technique(self, technique_id: str) -> MitreTechniqueRecord | None:
        catalog = await self.get_catalog()
        return catalog.get(technique_id)

    async def get_mitre_version(self) -> str:
        """MITRE gap-fill — the currently synced MITRE ATT&CK version, from
        the backend's new GET /api/v1/mitre/sync/status (backed by the
        normalized Postgres knowledge base's MitreSyncVersion audit trail).
        This is a SEPARATE store from the file-based catalog get_catalog()
        reads — the file catalog itself carries no version concept. Never
        raises: an unreachable/not-yet-synced backend degrades to "unknown"
        rather than failing the whole mapping pipeline over a traceability
        field. Same in-process TTL-cache shape as get_catalog() — including
        caching the "unknown" fallback itself, so a backend that's down for
        an extended period doesn't cost a real network round-trip on every
        single alert."""
        if self._version_cache is not None and (time.monotonic() - self._version_cache_loaded_at) < self._cache_ttl_s:
            return self._version_cache

        version = "unknown"
        try:
            response = await self._http_client.get(f"{self._base_url}/api/v1/mitre/sync/status")
            response.raise_for_status()
            body = response.json()
            latest = body.get("latest")
            if isinstance(latest, dict) and latest.get("mitreVersion"):
                version = str(latest["mitreVersion"])
        except httpx.HTTPError:
            pass

        self._version_cache = version
        self._version_cache_loaded_at = time.monotonic()
        return version
