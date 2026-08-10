from src.vectorstore.provider_interface import IVectorStore
from src.embeddings.provider_interface import IEmbeddingProvider


class RagRetriever:
    """Wraps embedding + search across the three RAG collections."""

    def __init__(self, vector_store: IVectorStore, embedding_provider: IEmbeddingProvider):
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider

    def retrieve(self, alert_text: str, limit_per_collection: int = 3) -> list[dict]:
        vector = self.embedding_provider.embed(alert_text)

        results: list[dict] = []
        for collection, kind in [
            ("playbook_embeddings", "playbook"),
            ("sop_embeddings", "sop"),
            ("incident_embeddings", "similar_incident"),
        ]:
            hits = self.vector_store.search(collection, vector, limit=limit_per_collection)
            for hit in hits:
                results.append(
                    {
                        "kind": kind,
                        "id": hit.get("id"),
                        "title": hit.get("title", hit.get("name", "untitled")),
                        "score": hit.get("score", 0.0),
                    }
                )
        return results
