from .provider_interface import IEmbeddingProvider

_model = None  # lazy-loaded singleton — the model is ~130MB, don't load it at import time


class BgeEmbeddingProvider(IEmbeddingProvider):
    """
    BAAI/bge-small-en-v1.5 (384-dim) via sentence-transformers.
    Downloads the model from Hugging Face on first use (needs internet once,
    then it's cached locally under ~/.cache/huggingface).
    """

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5"):
        self.model_name = model_name

    def _get_model(self):
        global _model
        if _model is None:
            from sentence_transformers import SentenceTransformer

            _model = SentenceTransformer(self.model_name)
        return _model

    def embed(self, text: str) -> list[float]:
        model = self._get_model()
        vector = model.encode(text, normalize_embeddings=True)
        return vector.tolist()
