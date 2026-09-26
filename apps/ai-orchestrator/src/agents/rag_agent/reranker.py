"""
Steps 5-6 of the RAG pipeline — Re-rank results, then filter low-relevance
results.

Deterministic and explainable by construction: a fixed weighted sum of
vector similarity plus four metadata-match ratios, each independently
computable from the candidate's own metadata (no hidden state, no
randomness, no model call). Every component is preserved in the output so
the final score is never a black box.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.contracts.response_phase import map_lifecycle_phase_to_response_phase

from .types import RagQueryInput


@dataclass(frozen=True)
class RerankWeights:
    """
    Phase D: `vector_similarity` was trimmed from 0.6 to 0.5 (and the
    remaining 0.1 handed to scenario_match/source_priority) so the weights
    still summed to 1.0 without cutting into any of the four Phase C match
    terms. Explainable Retrieval task follows the exact same precedent for
    its two new terms (platform_match, response_phase_match): trims
    vector_similarity again (0.5 -> 0.35) rather than reducing any existing
    term, so every pre-existing weight value — and every test asserting one
    — is unchanged. vector_similarity staying the single largest individual
    term is still deliberate and load-bearing: it's what keeps
    `source_priority` a nudge rather than an override (see
    DEFAULT_SOURCE_PRIORITY's docstring) — a low-relevance SOCFortress doc
    (e.g. 0.1 vector score) still loses to a high-relevance AWS one (e.g.
    0.9) despite SOCFortress's higher priority:
    0.1*0.35 + 0.85*0.05 = 0.0775 vs 0.9*0.35 + 0.5*0.05 = 0.34.

    These weights are VIGIX design parameters (not a claimed industry
    standard) and fully configurable — construct a different RerankWeights
    and pass it to rerank()/RagConfig.rerank_weights rather than editing
    these defaults for a one-off tuning experiment.
    """

    vector_similarity: float = 0.35
    mitre_match: float = 0.15
    incident_type_match: float = 0.1
    malware_family_match: float = 0.1
    threat_category_match: float = 0.05
    scenario_match: float = 0.05
    source_priority: float = 0.05
    # Explainable Retrieval task — two new terms matching the two
    # retrieval-context signals (platform, response_phase) that previously
    # had no re-ranking weight at all despite the underlying metadata
    # already existing on candidates.
    platform_match: float = 0.1
    response_phase_match: float = 0.05


DEFAULT_WEIGHTS = RerankWeights()

# Playbook source-priority order (Phase D). INTERNAL (VIGIX's own
# hand-authored content) ranks above every external provider — it's
# authored specifically for this platform and its own SOPs, so it gets the
# platform's own highest editorial trust, not just "another feed". Among
# the three external providers, the plan is explicit: SOCFORTRESS=primary,
# DFIR_PLAYBOOKS=secondary, AWS_REFERENCE=reference-only. An
# unrecognized/missing sourceProvider scores 0.0 — never guessed into one
# of the four known buckets.
DEFAULT_SOURCE_PRIORITY: dict[str, float] = {
    "INTERNAL": 1.0,
    "SOCFORTRESS": 0.85,
    "DFIR_PLAYBOOKS": 0.7,
    "AWS_REFERENCE": 0.5,
}


def _ratio_match(query_values: list[str], candidate_values: list[str] | None) -> float:
    """Fraction of query_values found in candidate_values — 0.0 when query_values is empty (the signal doesn't apply, not a penalty)."""
    query_set = {v.strip().lower() for v in query_values if v and v.strip()}
    if not query_set:
        return 0.0
    candidate_set = {v.strip().lower() for v in (candidate_values or []) if v}
    return len(query_set & candidate_set) / len(query_set)


def _single_match(query_value: str | None, candidate_values: list[str] | None) -> float:
    if not query_value or not query_value.strip():
        return 0.0
    candidate_set = {v.strip().lower() for v in (candidate_values or []) if v}
    return 1.0 if query_value.strip().lower() in candidate_set else 0.0


def _as_list(value: object) -> list[str]:
    """The backend's chunk metadata carries `scenario` as a single string, unlike the existing list-valued metadata fields (mitreTechniques/tags/...) — normalized to a one-element list so _single_match can treat it uniformly."""
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v]
    return []


def rerank(
    candidates: list[dict],
    query_input: RagQueryInput,
    weights: RerankWeights = DEFAULT_WEIGHTS,
    source_priority: dict[str, float] | None = None,
) -> list[dict]:
    """
    Returns a new list (input is never mutated), sorted by final score
    descending. Each candidate is expected to already carry a raw vector
    `score` (0.0-1.0, cosine similarity) and a `metadata` dict with
    mitreTechniques/incidentTypes/malwareFamilies/tags/scenario/
    sourceProvider — exactly what VectorSearchResult already returns.

    Phase D adds two more weighted terms on top of Phase C's four:
    scenario_match (does this chunk's metadata.scenario match the
    investigation's own scenario — see types.InvestigationContext.scenario)
    and source_priority (DEFAULT_SOURCE_PRIORITY, overridable via
    RagConfig.source_priority — see config.py). Explainable Retrieval task
    adds two more on top of those: platform_match (metadata.platforms, a
    real chunk field — see apps/backend's DocumentChunkMetadata.platforms)
    and response_phase_match (metadata.phase, the existing lifecycle-phase
    tag, mapped through the controlled ResponsePhase vocabulary before
    comparison — see contracts/response_phase.py). All apply identically
    whether `candidates` is a KNOWLEDGE or a PLAYBOOK result set; the two
    sets are never ranked against each other (agent.py calls this function
    once per set), only independently within their own set.
    """
    priority_map = source_priority if source_priority is not None else DEFAULT_SOURCE_PRIORITY
    query_technique_ids = [technique.technique_id for technique in query_input.mitre if technique.technique_id]

    ranked: list[dict] = []
    for candidate in candidates:
        metadata = candidate.get("metadata") or {}
        vector_score = float(candidate.get("score") or 0.0)

        mitre_score = _ratio_match(query_technique_ids, metadata.get("mitreTechniques"))
        incident_score = _single_match(query_input.incident_type, metadata.get("incidentTypes"))
        malware_score = _single_match(query_input.malware_family, metadata.get("malwareFamilies"))
        category_score = _ratio_match(query_input.threat_categories, metadata.get("tags"))
        scenario_score = _single_match(query_input.scenario, _as_list(metadata.get("scenario")))
        priority_score = priority_map.get(metadata.get("sourceProvider"), 0.0)
        platform_score = _single_match(query_input.platform, metadata.get("platforms"))
        candidate_response_phase = map_lifecycle_phase_to_response_phase(metadata.get("phase"))
        response_phase_score = _single_match(query_input.response_phase, _as_list(candidate_response_phase))

        final_score = (
            vector_score * weights.vector_similarity
            + mitre_score * weights.mitre_match
            + incident_score * weights.incident_type_match
            + malware_score * weights.malware_family_match
            + category_score * weights.threat_category_match
            + scenario_score * weights.scenario_match
            + priority_score * weights.source_priority
            + platform_score * weights.platform_match
            + response_phase_score * weights.response_phase_match
        )

        reranked = dict(candidate)
        reranked["vectorScore"] = vector_score
        reranked["score"] = round(final_score, 6)
        reranked["rerankBreakdown"] = {
            "vectorSimilarity": vector_score,
            "mitreMatch": mitre_score,
            "incidentTypeMatch": incident_score,
            "malwareFamilyMatch": malware_score,
            "threatCategoryMatch": category_score,
            "scenarioMatch": scenario_score,
            "sourcePriority": priority_score,
            "platformMatch": platform_score,
            "responsePhaseMatch": response_phase_score,
        }
        ranked.append(reranked)

    ranked.sort(key=lambda candidate: candidate["score"], reverse=True)
    return ranked


def filter_by_relevance(ranked: list[dict], threshold: float) -> list[dict]:
    """Only documents whose final (re-ranked) score meets the configured relevance threshold survive — never padded back up to any target count."""
    return [candidate for candidate in ranked if candidate["score"] >= threshold]
