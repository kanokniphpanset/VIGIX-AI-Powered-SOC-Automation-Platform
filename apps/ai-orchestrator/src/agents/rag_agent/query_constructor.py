"""
RagQueryConstructor (Phase D) — deterministic, no LLM calls. Turns an
InvestigationContext into the two independent query sets dual retrieval
needs (retriever.py's retrieve_knowledge/retrieve_playbooks) plus the
filter set both searches should apply.

Deliberately a separate module from query_builder.py rather than an
extension of it: build_semantic_query() produces ONE query string biased
toward "incident response containment recovery" vocabulary (a Phase C
decision baked into its own tests — see test_query_builder.py's exact-match
assertions), which is a reasonable single query when there's only one
collection to search. Phase D searches two collections that want
differently-phrased queries (KNOWLEDGE reads better as "what is this /how
does it work", PLAYBOOK reads better as "incident response containment for
X") — reusing build_semantic_query for both would mean fighting its fixed
suffix for one of the two, so this module builds its own term list instead
of importing that function's specific phrasing.
"""

from __future__ import annotations

from .types import InvestigationContext

_GENERIC_KNOWLEDGE_QUERY = "what is this security alert and how does it work"
_GENERIC_PLAYBOOK_QUERY = "incident response containment and recovery playbook"


def _dedupe(terms: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for term in terms:
        key = term.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(term.strip())
    return deduped


def _concept_terms(context: InvestigationContext) -> list[str]:
    """
    Fixed priority order — scenario (most specific, e.g. a malware family
    or threat category) first, then each MITRE technique
    ("T1059.001 PowerShell"), then any remaining named behaviors not
    already covered by a technique name — deduplicated case-insensitively,
    same convention as query_builder.build_semantic_query's own term
    collection.
    """
    terms: list[str] = []
    if context.scenario:
        terms.append(context.scenario)
    for technique in context.mitreTechniques:
        terms.append(f"{technique.technique_id} {technique.technique_name}".strip())
    terms.extend(context.behaviors)
    return _dedupe(terms)


class RagQueryConstructor:
    """Pure and deterministic: the same InvestigationContext always produces the same {knowledgeQueries, playbookQueries, filters}."""

    def build(self, context: InvestigationContext) -> dict:
        concept_terms = _concept_terms(context)

        if concept_terms:
            knowledge_queries = [f"what is {term} and how does it work" for term in concept_terms]
            playbook_queries = [f"incident response containment for {term}" for term in concept_terms]
        else:
            # Nothing but the classification label (or nothing at all) was
            # available — e.g. a first pass before MitreAgent found
            # anything. Fall back to the alert's own classification label
            # rather than the four generic words alone, same "still say
            # something about *this* alert" reasoning as
            # query_builder.build_semantic_query's alert_text fallback.
            label = context.alertClassification if context.alertClassification != "UNCLASSIFIED" else None
            if label:
                readable = label.replace("_", " ").lower()
                knowledge_queries = [f"what is {readable} and how does it work"]
                playbook_queries = [f"incident response containment for {readable}"]
            else:
                knowledge_queries = [_GENERIC_KNOWLEDGE_QUERY]
                playbook_queries = [_GENERIC_PLAYBOOK_QUERY]

        filters: dict = {}
        if context.scenario:
            filters["scenario"] = [context.scenario]
        if context.platform:
            # Not a filter key the backend's /api/v1/knowledge/search
            # contract documents today (see retriever.py's
            # _BACKEND_FILTER_KEYS) — carried here anyway per this
            # module's own contract (agent.py may use it for query
            # phrasing or a future backend filter), and retriever.py is
            # the layer responsible for dropping it before the HTTP call.
            filters["platform"] = context.platform
        # Explainable Retrieval task — service/responsePhase kept here for
        # the same observability-only reason as `platform` above (visible
        # in traceability.filters, never sent as a hard backend filter).
        # incident_type intentionally omitted: it's derived from
        # investigation_context.mitreTechniques via incident_type_mapper.py
        # in agent.py, not from this InvestigationContext-only builder.
        if context.service:
            filters["service"] = context.service
        filters["responsePhase"] = context.responsePhase
        technique_ids = [technique.technique_id for technique in context.mitreTechniques if technique.technique_id]
        if technique_ids:
            filters["mitreTechniques"] = technique_ids

        return {
            "knowledgeQueries": knowledge_queries,
            "playbookQueries": playbook_queries,
            "filters": filters,
        }


def join_queries(queries: list[str], fallback: str) -> str:
    """
    retrieve_knowledge/retrieve_playbooks each take one query string (one
    embedding per search — see retriever.py), so agent.py collapses each
    query list from build() above into a single deduplicated string before
    calling them. A shared helper (rather than inlined in agent.py) so its
    "never send an empty query" fallback is unit-testable on its own.
    """
    deduped = _dedupe(queries)
    return " ".join(deduped) if deduped else fallback
