"""RagAgent's own tunables — separate from settings.py's connection config, mirroring backend precedent (e.g. EmbeddingPipelineConfig vs EmbeddingServiceConfig)."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.config.settings import settings

from .reranker import DEFAULT_SOURCE_PRIORITY, RerankWeights


@dataclass(frozen=True)
class RagConfig:
    top_k: int = 5
    final_top_k: int = 3
    # Empirically calibrated (2026-08-26) against the real ingested playbook
    # corpus + BAAI/bge-small-en-v1.5: a topically relevant query's best
    # matches score ~0.39-0.43 after re-ranking, while a deliberately
    # unrelated query's best matches score ~0.30-0.33 — a real, measured
    # separation band, not a guess. The previous default (0.5) sat above
    # every real match this corpus ever produces, so filter_by_relevance
    # discarded 100% of retrieval results regardless of actual relevance
    # (verified: all 6 representative alert scenarios — brute force,
    # phishing, ransomware, malware, PowerShell, unknown — returned
    # noRelevantPlaybook=True even when a clearly-on-topic playbook was
    # retrieved). 0.35 sits with margin inside the observed gap. Revisit if
    # the corpus grows enough to shift the score distribution.
    relevance_threshold: float = 0.35
    vector_search_timeout_s: float = 10.0
    vector_search_max_retries: int = 2
    # Phase D — dual retrieval. Kept independently configurable rather than
    # reusing top_k/final_top_k for both collections: KNOWLEDGE content is
    # typically denser and more redundant (many chunks explain the same
    # technique) while PLAYBOOK content is comparatively sparse and
    # specific, so operators may reasonably want to tune each collection's
    # recall on its own rather than one shared knob fighting both use
    # cases. Both default to the same values as their knowledge-side
    # counterparts above, since one sane default is easier to operate than
    # forcing four values to be set from day one.
    playbook_top_k: int = 5
    playbook_final_top_k: int = 3
    # Not settings.py-backed (unlike the scalars above): these are
    # structured values, not simple env-var-friendly scalars. Still fully
    # overridable in tests via dataclasses.replace(...) — see
    # tests/agents/rag_agent's _patch_config() convention.
    rerank_weights: RerankWeights = field(default_factory=RerankWeights)
    source_priority: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_SOURCE_PRIORITY))


def load_rag_config() -> RagConfig:
    return RagConfig(
        top_k=settings.rag_top_k,
        final_top_k=settings.rag_final_top_k,
        relevance_threshold=settings.rag_relevance_threshold,
        vector_search_timeout_s=settings.rag_vector_search_timeout_s,
        vector_search_max_retries=settings.rag_vector_search_max_retries,
        playbook_top_k=settings.rag_playbook_top_k,
        playbook_final_top_k=settings.rag_playbook_final_top_k,
    )
