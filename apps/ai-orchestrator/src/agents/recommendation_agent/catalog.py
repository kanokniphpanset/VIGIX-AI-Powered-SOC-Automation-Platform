"""
RecommendationCatalog — deterministic lookup layer over the Investigation
Recommendation mapping resources (resources/mappings/*.yaml), converting
raw resource strings into this agent's own enums (RecommendationCategory /
RecommendationPriority) exactly the way policy_engine.py's
ResourcePolicyConfigProvider converts PolicyResource strings into
AssetCriticality/DecisionOutcome — the resources/schema layer stays free of
any src.agents.* import (see resources/schema/mapping_schema.py's own
note), so that conversion happens here instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.agents.recommendation_agent.models import (
    NistReference,
    PlaybookReference,
    RecommendationCategory,
    RecommendationPriority,
)


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    title: str
    category: RecommendationCategory
    default_priority: RecommendationPriority
    evidence_any_of: tuple[str, ...]
    evidence_all_of: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    automation_hint: bool
    recommended_action: str | None
    # Recommendation Agent task: an unvalidated reference to a real Decision
    # Agent Action Catalog id, straight from the resource file — see
    # recommendation-catalog.yaml's own header note. Validated against the
    # real catalog by selector.py, never here (this module stays a plain
    # resource->dataclass reshape, same as every other field above).
    action_id: str | None


class RecommendationCatalog:
    """Reads recommendation-catalog.yaml + nist-800-61-r3-mapping.yaml +
    playbook-index.yaml (lazily, via the resource loaders' own caching) and
    answers per-incident-type lookups. A catalog entry whose category or
    priority string doesn't match a known enum value is skipped rather than
    raising — a malformed resource file should degrade gracefully to "no
    recommendation from this entry", never crash the graph."""

    def __init__(self, catalog_loader=None, nist_loader=None, playbook_loader=None) -> None:
        from resources.mapping_loader import (
            NistMappingLoader,
            PlaybookIndexLoader,
            RecommendationCatalogLoader,
        )

        self._catalog_loader = catalog_loader or RecommendationCatalogLoader()
        self._nist_loader = nist_loader or NistMappingLoader()
        self._playbook_loader = playbook_loader or PlaybookIndexLoader()

    def entries_for(self, incident_type: str) -> list[CatalogEntry]:
        resource = self._catalog_loader.get()
        if resource is None:
            return []
        raw_entries = resource.incident_types.get(incident_type, [])
        entries: list[CatalogEntry] = []
        for e in raw_entries:
            try:
                category = RecommendationCategory(e.category)
                priority = RecommendationPriority(e.default_priority)
            except ValueError:
                continue
            entries.append(
                CatalogEntry(
                    id=e.id,
                    title=e.title,
                    category=category,
                    default_priority=priority,
                    evidence_any_of=tuple(e.evidence_conditions.any_of),
                    evidence_all_of=tuple(e.evidence_conditions.all_of),
                    mitre_techniques=tuple(e.mitre_techniques),
                    automation_hint=e.automation_hint,
                    recommended_action=e.recommended_action,
                    action_id=e.action_id,
                )
            )
        return entries

    def nist_reference_for(self, category: RecommendationCategory) -> NistReference:
        resource = self._nist_loader.get()
        if resource is None:
            return NistReference(function=None, section="reference_required")
        mapping = resource.categories.get(category.value)
        if mapping is None:
            return NistReference(function=None, section="reference_required")
        return NistReference(function=mapping.function, section=mapping.section, notice=resource.notice)

    def playbook_references_for(self, incident_type: str) -> list[PlaybookReference]:
        resource = self._playbook_loader.get()
        if resource is None:
            return []
        entry = resource.incident_types.get(incident_type)
        if entry is None:
            return []
        refs: list[PlaybookReference] = []
        if entry.local_playbook_id:
            # `playbook` is a display name shown directly to a SOC analyst —
            # never entry.local_path (a repo-relative filesystem path,
            # internal-only). Falls back to the catalog id only if a real
            # title is somehow missing, never to the path.
            refs.append(
                PlaybookReference(
                    repository="vigix/local",
                    playbook=entry.local_title or entry.local_playbook_id,
                    playbook_id=entry.local_playbook_id,
                )
            )
        for ext in entry.external_references:
            refs.append(PlaybookReference(repository=ext.repository, playbook=ext.playbook, playbook_id=None))
        return refs

