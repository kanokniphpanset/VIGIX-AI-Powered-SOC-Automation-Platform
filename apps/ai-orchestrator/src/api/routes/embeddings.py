import logging
from fastapi import APIRouter, HTTPException

from src.config.settings import settings
from src.embeddings.bge_embedding_provider import BgeEmbeddingProvider
from src.api.schemas import GenerateEmbeddingRequest, GenerateEmbeddingResponse

router = APIRouter()
logger = logging.getLogger("soar.ai-orchestrator")

# Same lazy-singleton pattern BgeEmbeddingProvider already documents itself
# (the model is ~130MB — loaded on first request, not at import time).
# Reused as-is from src/embeddings/ — this endpoint adds no embedding logic
# of its own, only an HTTP entry point onto the existing provider, for the
# backend's Knowledge Embedding Pipeline (a Node process, which cannot load
# a sentence-transformers model directly) to call.
_embedding_provider = BgeEmbeddingProvider(settings.embedding_model)


@router.post("/", response_model=GenerateEmbeddingResponse)
def generate_embedding(request: GenerateEmbeddingRequest) -> GenerateEmbeddingResponse:
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=422, detail="text must not be empty")

    try:
        vector = _embedding_provider.embed(request.text)
    except Exception as exc:
        logger.exception("Embedding generation failed")
        raise HTTPException(status_code=500, detail=f"Embedding generation failed: {exc}") from exc

    return GenerateEmbeddingResponse(embedding=vector, dimension=len(vector), model=settings.embedding_model)
