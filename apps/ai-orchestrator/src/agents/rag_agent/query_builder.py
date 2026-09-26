"""
Step 1 of the RAG pipeline — Build a semantic query.

Split into a pure, fully-deterministic builder (build_semantic_query) and a
separate AgentState adapter (extract_query_input), so the query-construction
logic itself is testable without any LangGraph/state concerns.
"""

from __future__ import annotations

from src.graph.state import AgentState
from .types import MitreTechniqueRef, RagQueryInput

_QUERY_SUFFIX = "incident response containment recovery"


def build_semantic_query(query_input: RagQueryInput) -> str:
    """
    Deterministic query construction — the same input always produces the
    same query text. Terms are collected in a fixed priority order
    (incident type, malware family, threat categories, MITRE techniques,
    then a fixed operational-vocabulary suffix that biases retrieval
    toward actionable documents) and deduplicated case-insensitively, so
    overlapping terms (e.g. incidentType "Ransomware" and
    threatCategories=["ransomware"]) don't repeat — matches the documented
    example exactly: incidentType="Ransomware", malwareFamily="LockBit",
    threatCategories=["ransomware"], mitre=[{T1486, "Data Encrypted for
    Impact"}] produces "Ransomware LockBit T1486 Data Encrypted for Impact
    incident response containment recovery" (the duplicate "ransomware"
    from threatCategories is deduplicated against incidentType).
    """
    terms: list[str] = []
    if query_input.incident_type:
        terms.append(query_input.incident_type)
    if query_input.malware_family:
        terms.append(query_input.malware_family)
    terms.extend(query_input.threat_categories)
    for technique in query_input.mitre:
        terms.append(f"{technique.technique_id} {technique.technique_name}".strip())
    terms.append(_QUERY_SUFFIX)

    seen: set[str] = set()
    deduped: list[str] = []
    for term in terms:
        key = term.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(term.strip())

    if deduped == [_QUERY_SUFFIX] and query_input.alert_text.strip():
        # Nothing but the generic suffix was available (no incident type,
        # malware family, categories, or MITRE context yet — e.g. a first
        # pass before ThreatIntelAgent/MitreAgent have produced anything).
        # Fall back to the raw alert text so the query still reflects this
        # specific alert rather than four generic words with no connection
        # to it at all.
        return f"{query_input.alert_text.strip()} {_QUERY_SUFFIX}"

    return " ".join(deduped)


def extract_query_input(state: AgentState) -> RagQueryInput:
    """
    Best-effort extraction from whatever AgentState already holds. RagAgent
    runs sequentially after ThreatIntelAgent and MitreAgent (see
    build_graph.py), so on a normal pass their output is already present in
    state by the time this runs; still written defensively (state.get with
    defaults) so a state missing either key — e.g. a unit test constructing
    a partial state — degrades to empty values instead of raising.
    `incident_type` is left unset — nothing upstream of RagAgent classifies
    an incident type yet.
    """
    mitre = [
        MitreTechniqueRef(technique_id=match["technique_id"], technique_name=match.get("name", ""))
        for match in state.get("mitre_techniques", [])
        if match.get("technique_id")
    ]

    malware_family: str | None = None
    categories: list[str] = []
    for ioc in state.get("iocs", []):
        raw_response = ioc.get("raw_response") or {}
        for provider_result in raw_response.values():
            if not isinstance(provider_result, dict):
                continue
            if not malware_family and provider_result.get("malwareFamily"):
                malware_family = provider_result["malwareFamily"]
            categories.extend(provider_result.get("categories") or [])

    seen_categories: set[str] = set()
    deduped_categories: list[str] = []
    for category in categories:
        key = category.strip().lower()
        if key and key not in seen_categories:
            seen_categories.add(key)
            deduped_categories.append(category)

    return RagQueryInput(
    incident_type=state.get("incident_type"),
    malware_family=malware_family,
    threat_categories=deduped_categories,
    mitre=mitre,
    alert_text=state.get("alert_text", ""),
)
    
