from src.graph.state import AgentState
from src.vectorstore.qdrant_provider import QdrantProvider
from src.embeddings.bge_embedding_provider import BgeEmbeddingProvider
from src.config.settings import settings
from .retriever import RagRetriever

_vector_store = QdrantProvider(settings.qdrant_url)
_embedding_provider = BgeEmbeddingProvider(settings.embedding_model)
_retriever = RagRetriever(_vector_store, _embedding_provider)


async def run(state: AgentState) -> AgentState:
    """
    RagAgent — embeds the alert text (BAAI/bge-small-en-v1.5) and retrieves the
    closest playbooks, SOPs, and similar past incidents from Qdrant. Returns an
    empty list gracefully if the relevant collection hasn't been populated yet
    (fresh install) rather than failing the pipeline.
    """
    text = state.get("alert_text", "")

    try:
        matches = _retriever.retrieve(text)
    except Exception as exc:  # embedding model not downloaded yet, Qdrant unreachable, etc.
        return {
            "rag_matches": [],
            "trace": [f"RagAgent: retrieval unavailable ({exc.__class__.__name__}), returning no matches"],
        }

    return {"rag_matches": matches, "trace": [f"RagAgent: retrieved {len(matches)} match(es)"]}
