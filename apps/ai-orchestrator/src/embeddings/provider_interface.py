from abc import ABC, abstractmethod


class IEmbeddingProvider(ABC):
    """Abstract embedding provider. RagAgent depends only on this."""

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        raise NotImplementedError
