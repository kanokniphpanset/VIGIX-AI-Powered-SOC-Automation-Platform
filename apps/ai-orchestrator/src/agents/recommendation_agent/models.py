"""
Recommendation domain models — the Investigation -> Recommendation
capability (NIST SP 800-61 Rev.3-aligned, MITRE ATT&CK-contextualized,
evidence-traceable). Sits between the existing analysis agents
(threat_intel/mitre/rag/llm_analyst[/classification_agent]) and
DecisionAgent: this module answers "what should the SOC analyst
investigate/collect/contain/eradicate/recover/improve", never "is this
allowed" — DecisionAgent/PolicyEngine/ApprovalEngine (untouched by this
capability) still own that exclusively.

`recommendedAction` is prose only — a human-readable description, never an
executable action id. `actionId` (Recommendation Agent task) is the one
field that CAN carry a real, executable Decision Agent Action Catalog id —
set only when RecommendationSelector resolved and re-validated one against
that real catalog; still never a command to execute, approve, or bypass
policy with. `automation.allowed` remains a metadata hint only. See agent.py's
own module docstring for the full "NEVER" list.

Same `_CamelModel` convention as decision_agent/models.py (camelCase JSON,
snake_case Python, frozen) — redeclared here rather than imported, same
reasoning contracts/_base.py gives for its own copy: this package should
not depend on decision_agent's module for an unrelated concept.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from src.contracts.evidence import EvidenceItem

RECOMMENDATION_AGENT_VERSION = "RecommendationAgent/v1.0.0"


class _CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, frozen=True)


class RecommendationCategory(str, Enum):
    """VIGIX's own operational taxonomy (spec section 8) — broader than
    detect/respond/recover, covering the full IR lifecycle. NOT NIST
    terminology; see nist-800-61-r3-mapping.yaml for how each value maps
    onto the verified NIST SP 800-61 Rev.3 / CSF 2.0 structure."""

    INVESTIGATION = "INVESTIGATION"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    ANALYSIS = "ANALYSIS"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    POST_INCIDENT = "POST_INCIDENT"
    CONTINUOUS_IMPROVEMENT = "CONTINUOUS_IMPROVEMENT"


class RecommendationPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class NistReference(_CamelModel):
    """Traceability to NIST SP 800-61 Rev.3. `function` is the verified
    CSF 2.0 function-level alignment (see nist-800-61-r3-mapping.yaml);
    `section` is "reference_required" whenever a finer-grained citation
    could not be independently verified — never a fabricated section
    number (VIGIX spec section 3)."""

    name: str = "NIST SP 800-61 Rev.3"
    function: str | None = None
    section: str = "reference_required"
    notice: str | None = None


class MitreReference(_CamelModel):
    tactic: str | None = None
    techniques: list[str] = Field(default_factory=list)


class PlaybookReference(_CamelModel):
    """Non-authoritative structural reference (spec section 4) — either the
    real local playbook (`repository="vigix/local"`) or one of the two
    reference GitHub repositories, never treated as an authoritative
    standard."""

    repository: str
    playbook: str
    playbook_id: str | None = None


class AutomationEligibility(_CamelModel):
    """Metadata hint only. `allowed=True` means this recommendation's
    catalog entry is plausibly automatable by SOME existing Action Catalog
    entry — it is never itself a command to execute, and RecommendationAgent
    never dispatches anything based on this flag."""

    allowed: bool = False
    notes: str = ""


class Recommendation(_CamelModel):
    id: str
    title: str
    category: RecommendationCategory
    priority: RecommendationPriority
    reason: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    mitre: MitreReference | None = None
    framework: NistReference
    playbook_references: list[PlaybookReference] = Field(default_factory=list)
    rationale: str
    recommended_action: str | None = None
    # Recommendation Agent task: a REAL, executable Decision Agent Action
    # Catalog id (decision_agent/action_catalog.py) — e.g. "NET-001" — set
    # only when selector.py resolved and re-validated one against the real
    # catalog for this entry; None means "no catalog action currently maps
    # to this recommendation" (spec section 5's "mark as unsupported /
    # unavailable"), never a fabricated id. Deliberately a DIFFERENT field
    # from recommended_action, which stays prose-only (see this class's own
    # docstring and tests/agents/recommendation_agent/test_selector.py::
    # test_recommended_action_is_prose_never_an_action_catalog_id) —
    # DecisionAgent still does not read this field; it is additive
    # traceability on RecommendationAgent's own output only.
    action_id: str | None = None
    automation: AutomationEligibility = Field(default_factory=AutomationEligibility)
    confidence: float = Field(ge=0.0, le=1.0)


class InvestigationRecommendationReport(_CamelModel):
    incident_id: str
    generated_at: datetime
    generated_by: str = RECOMMENDATION_AGENT_VERSION
    incident_type: str
    classification_confidence: float = Field(ge=0.0, le=1.0)
    investigation_summary: str
    # Recommendation Agent task (spec section 11): READY means either
    # ValidationAgent passed, or no validation ran at all for this state
    # (validation_passed absent — same "nothing to gate on" reasoning
    # decision_engine.py::_resolve_validation already documents).
    # VALIDATION_FAILED means the graph's own retry-then-proceed semantics
    # (graph/router.py::after_validation, MAX_RETRIES) already exhausted
    # retries and moved forward anyway — recommendations below are still
    # real and evidence-grounded (selection never reads validation_passed),
    # but this flag preserves the warning rather than silently hiding it,
    # per spec section 11's "preserve the warning/traceability". Does not
    # itself change graph routing or DecisionAgent's fail-safe behavior.
    recommendation_status: Literal["READY", "VALIDATION_FAILED"] = "READY"
    validation_notes: list[str] = Field(default_factory=list)
    evidence_summary: list[EvidenceItem] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    nist_traceability: list[NistReference] = Field(default_factory=list)
    playbook_references: list[PlaybookReference] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    overall_priority: RecommendationPriority
    automation_eligible_count: int = 0

    def to_json(self) -> str:
        return self.model_dump_json(by_alias=True)
