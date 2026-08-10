from typing import Any
from qdrant_client import QdrantClient
from qdrant_client.models import PointStruct, VectorParams, Distance
from .provider_interface import IVectorStore


class QdrantProvider(IVectorStore):
    """
    Qdrant implementation of IVectorStore.
    Collections used by RagAgent: playbook_embeddings, sop_embeddings, incident_embeddings.
    """

    def __init__(self, url: str, vector_size: int = 384):
        self.client = QdrantClient(url=url)
        self.vector_size = vector_size

    def ensure_collection(self, collection: str) -> None:
        existing = [c.name for c in self.client.get_collections().collections]
        if collection not in existing:
            self.client.create_collection(
                collection_name=collection,
                vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
            )

    def search(self, collection: str, vector: list[float], limit: int = 5) -> list[dict[str, Any]]:
        try:
            results = self.client.search(collection_name=collection, query_vector=vector, limit=limit)
        except Exception:
            # Collection doesn't exist yet (nothing indexed) — return no matches
            # rather than raising, so the pipeline can still proceed.
            return []
        return [{"id": str(r.id), "score": r.score, **(r.payload or {})} for r in results]

    def upsert(self, collection: str, point_id: str, vector: list[float], payload: dict) -> None:
        self.ensure_collection(collection)
        self.client.upsert(
            collection_name=collection,
            points=[PointStruct(id=point_id, vector=vector, payload=payload)],
        )
