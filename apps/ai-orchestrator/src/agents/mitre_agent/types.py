"""
Core types for the evidence-grounded MITRE ATT&CK mapping system (Phase 3).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Evidence:
    """One field-level fact that supports a technique mapping — spec
    section 5's exact per-item shape. `source` names where the fact came
    from ("alert" | "threat_intel"), `field` names the specific signal
    ("failedAttempts", "commandLine", "processName", ...), `value` is the
    literal observed value (never fabricated, never a guess)."""

    source: str
    field: str
    value: object

    def to_dict(self) -> dict:
        return {"source": self.source, "field": self.field, "value": self.value}


@dataclass
class MitreTechniqueRecord:
    """
    One technique from the real ~697-technique catalog (backend
    GET /api/v1/mitre/techniques) — see knowledge_base_client.py. Every
    field here traces back to that fetched record; `is_sub_technique` /
    `parent_technique_id` are derived from the ID itself (MITRE's own
    convention: "T1110.001" is a sub-technique of "T1110"), since the
    on-disk file format carries no separate relationship field.
    """

    technique_id: str
    name: str
    tactics: list[str]
    description: str
    detection: str = ""

    @property
    def is_sub_technique(self) -> bool:
        return "." in self.technique_id

    @property
    def parent_technique_id(self) -> str | None:
        return self.technique_id.split(".")[0] if self.is_sub_technique else None


@dataclass
class MappedTechnique:
    """Spec section 5's exact output contract for one mapped technique.

    mapping_status/validation/reason (MITRE gap-fill) are additive,
    defaulted fields set by TechniqueMapper via mapping_status.py's
    classify_mapping_status() — never by this dataclass itself, which
    stays a plain data holder. Defaulted to None/empty so every existing
    caller constructing a MappedTechnique without them keeps working
    unchanged."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    evidence_source: str = ""
    is_sub_technique: bool = False
    parent_technique_id: str | None = None
    mapping_status: str | None = None
    validation: dict | None = None
    reason: str | None = None

    def to_dict(self) -> dict:
        result = {
            "techniqueId": self.technique_id,
            "techniqueName": self.technique_name,
            "tactic": self.tactic,
            "confidence": round(self.confidence, 2),
            "evidence": [e.to_dict() for e in self.evidence],
            "evidenceSource": self.evidence_source,
            "isSubTechnique": self.is_sub_technique,
            "parentTechniqueId": self.parent_technique_id,
        }
        if self.mapping_status is not None:
            result["mappingStatus"] = self.mapping_status
        if self.validation is not None:
            result["validation"] = self.validation
        if self.reason is not None:
            result["reason"] = self.reason
        return result
