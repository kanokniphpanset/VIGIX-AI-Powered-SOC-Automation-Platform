from abc import ABC, abstractmethod
from typing import Any


class IVectorStore(ABC):
    """
    Abstract vector store. RagAgent depends only on this.
    Swap QdrantProvider for pgvector/Weaviate/Milvus by adding a new class
    here — nothing in the agent changes.
    """

    @abstractmethod
    def search(self, collection: str, vector: list[float], limit: int = 5) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def upsert(self, collection: str, point_id: str, vector: list[float], payload: dict) -> None:
        raise NotImplementedError
