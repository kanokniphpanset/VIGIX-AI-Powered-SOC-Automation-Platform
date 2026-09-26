import os
import threading

from .provider_interface import IEmbeddingProvider

# transformers/sentence-transformers probe for a TensorFlow backend even
# though this project only ever uses the PyTorch one — on this environment
# the installed TensorFlow's bundled protobuf message classes are
# incompatible with the newer protobuf package actually installed
# ("AttributeError: 'MessageFactory' object has no attribute
# 'GetPrototype'"), which hangs/breaks model loading. Disabling the TF
# probe (must happen before sentence_transformers/transformers is ever
# imported — see _get_model below) sidesteps the broken TF import path
# entirely without touching any package version.
os.environ.setdefault("USE_TF", "0")

_model = None  # lazy-loaded singleton — the model is ~130MB, don't load it at import time
_model_lock = threading.Lock()  # see _get_model — first load races across threads without this


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
        # RagAgent's dual retrieval (retrieve_knowledge/retrieve_playbooks)
        # calls embed() concurrently via asyncio.gather, each dispatched to
        # its own thread via asyncio.to_thread — on the very first call in a
        # process, both threads can see `_model is None` simultaneously and
        # both start constructing SentenceTransformer(...) at once. That's a
        # real, observed failure mode (both retrievals came back
        # EMBEDDING_FAILED together), not hypothetical. Double-checked
        # locking: cheap on every call after the first (lock only taken when
        # _model is still None), and guarantees exactly one thread ever
        # constructs the model.
        if _model is None:
            with _model_lock:
                if _model is None:
                    from sentence_transformers import SentenceTransformer

                    _model = SentenceTransformer(self.model_name)
        return _model

    def embed(self, text: str) -> list[float]:
        model = self._get_model()
        vector = model.encode(text, normalize_embeddings=True)
        return vector.tolist()
