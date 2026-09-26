"""
mapping_loader.py — restores a missing, previously-documented module (see
prompt_loader.py's own docstring for the full context of why
`apps/ai-orchestrator/resources/` had to be recreated).

Reconstructed from, in order of confidence:
  1. The ONE real call site (src/agents/recommendation_agent/catalog.py),
     which names every class (RecommendationCatalogLoader, NistMappingLoader,
     PlaybookIndexLoader), every method (.get()), and every attribute it
     reads off each loader's result (e.g. resource.incident_types,
     e.evidence_conditions.any_of, resource.categories[...].function).
  2. The three real, complete, already-existing YAML files this loader
     reads (resources/mappings/{recommendation-catalog,
     nist-800-61-r3-mapping,playbook-index}.yaml) — every field below has
     a concrete example in those files, nothing was invented.
  3. resources/mappings/README.md, which documents this exact
     file-to-loader-to-class mapping.
  4. tests/agents/recommendation_agent/test_catalog.py — a real,
     un-mocked test suite that exercises this loader indirectly through
     RecommendationCatalog and will fail loudly if this reconstruction's
     shape is wrong.

Follows the same reload()-caches-into-memory pattern as the sibling
loaders restored alongside it (prompt_loader.py, policy_loader.py,
asset_criticality_loader.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_MAPPINGS_DIR = _REPO_ROOT / "resources" / "mappings"


# ---------------------------------------------------------------------------
# recommendation-catalog.yaml
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceConditions:
    any_of: list[str] = field(default_factory=list)
    all_of: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RecommendationCatalogEntry:
    id: str
    title: str
    category: str
    default_priority: str
    evidence_conditions: EvidenceConditions
    mitre_techniques: list[str] = field(default_factory=list)
    automation_hint: bool = False
    recommended_action: str | None = None
    action_id: str | None = None


@dataclass(frozen=True)
class RecommendationCatalogResource:
    id: str
    version: str
    incident_types: dict[str, list[RecommendationCatalogEntry]]


class RecommendationCatalogLoader:
    def __init__(self, path: Path | None = None):
        self._path = path or (_MAPPINGS_DIR / "recommendation-catalog.yaml")
        self._resource: RecommendationCatalogResource | None = None
        self.reload()

    def reload(self) -> None:
        if not self._path.exists():
            self._resource = None
            return
        data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        incident_types: dict[str, list[RecommendationCatalogEntry]] = {}
        for incident_type, raw_entries in (data.get("incident_types") or {}).items():
            entries = []
            for e in raw_entries or []:
                conditions = e.get("evidence_conditions") or {}
                entries.append(
                    RecommendationCatalogEntry(
                        id=e["id"],
                        title=e["title"],
                        category=e["category"],
                        default_priority=e["default_priority"],
                        evidence_conditions=EvidenceConditions(
                            any_of=list(conditions.get("any_of") or []),
                            all_of=list(conditions.get("all_of") or []),
                        ),
                        mitre_techniques=list(e.get("mitre_techniques") or []),
                        automation_hint=bool(e.get("automation_hint", False)),
                        recommended_action=e.get("recommended_action"),
                        action_id=e.get("action_id"),
                    )
                )
            incident_types[incident_type] = entries
        self._resource = RecommendationCatalogResource(
            id=data.get("id", ""), version=str(data.get("version", "1")), incident_types=incident_types
        )

    def get(self) -> RecommendationCatalogResource | None:
        return self._resource


# ---------------------------------------------------------------------------
# nist-800-61-r3-mapping.yaml
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NistCategoryMapping:
    function: str | None
    section: str


@dataclass(frozen=True)
class NistMappingResource:
    id: str
    version: str
    notice: str | None
    categories: dict[str, NistCategoryMapping]


class NistMappingLoader:
    def __init__(self, path: Path | None = None):
        self._path = path or (_MAPPINGS_DIR / "nist-800-61-r3-mapping.yaml")
        self._resource: NistMappingResource | None = None
        self.reload()

    def reload(self) -> None:
        if not self._path.exists():
            self._resource = None
            return
        data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        categories = {
            category: NistCategoryMapping(function=mapping.get("function"), section=mapping.get("section", "reference_required"))
            for category, mapping in (data.get("categories") or {}).items()
        }
        self._resource = NistMappingResource(
            id=data.get("id", ""), version=str(data.get("version", "1")), notice=data.get("notice"), categories=categories
        )

    def get(self) -> NistMappingResource | None:
        return self._resource


# ---------------------------------------------------------------------------
# playbook-index.yaml
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalPlaybookReference:
    repository: str
    playbook: str


@dataclass(frozen=True)
class PlaybookIndexEntry:
    local_playbook_id: str | None
    local_title: str | None
    local_path: str | None
    external_references: list[ExternalPlaybookReference] = field(default_factory=list)


@dataclass(frozen=True)
class PlaybookIndexResource:
    id: str
    version: str
    incident_types: dict[str, PlaybookIndexEntry]


class PlaybookIndexLoader:
    def __init__(self, path: Path | None = None):
        self._path = path or (_MAPPINGS_DIR / "playbook-index.yaml")
        self._resource: PlaybookIndexResource | None = None
        self.reload()

    def reload(self) -> None:
        if not self._path.exists():
            self._resource = None
            return
        data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        incident_types: dict[str, PlaybookIndexEntry] = {}
        for incident_type, entry in (data.get("incident_types") or {}).items():
            incident_types[incident_type] = PlaybookIndexEntry(
                local_playbook_id=entry.get("local_playbook_id"),
                local_title=entry.get("local_title"),
                local_path=entry.get("local_path"),
                external_references=[
                    ExternalPlaybookReference(repository=ref["repository"], playbook=ref["playbook"])
                    for ref in entry.get("external_references") or []
                ],
            )
        self._resource = PlaybookIndexResource(
            id=data.get("id", ""), version=str(data.get("version", "1")), incident_types=incident_types
        )

    def get(self) -> PlaybookIndexResource | None:
        return self._resource
