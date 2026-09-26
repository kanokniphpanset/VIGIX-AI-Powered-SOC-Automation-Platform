"""
IncidentClassification — the deterministic Incident Classification contract.

Sits between Evidence[] (contracts/evidence.py) and AnalysisResult
(api/output_contract.py): answers "what TYPE of incident is this", never
"what should we DO about it" (that is the future Decision Agent's job, out
of scope here). Same CamelModel convention as every other contract in this
package (camelCase JSON, snake_case Python).

`category` is typed as a plain `str` (not `IncidentCategory`), mirroring
contracts/error.py::ErrorItem.code — `IncidentCategory` is the fixed,
deliberately small taxonomy every rule in classification_rules.py picks
from, not a hard Pydantic constraint on the field itself.

`status` reconciles two different levels of detail given for this field:
the task's own worked "insufficient evidence" example uses a plain
CLASSIFIED/UNCLASSIFIED split, while its confidence-threshold section
spells out four buckets (HIGH_CONFIDENCE/MEDIUM_CONFIDENCE/LOW_CONFIDENCE/
UNCLASSIFIED). The four-bucket form is strictly more informative and still
satisfies the simpler example (UNKNOWN always pairs with UNCLASSIFIED), so
that is what is implemented.

`signals` holds each contributing SOURCE's score for the winning category
(mitre/threatIntel/mlRisk/rag/llmAnalyst) — the shape used by the task's
canonical example. Conflict/competing-category information (the shape used
by the task's separate conflict-handling example, keyed by CATEGORY name
instead) lives in `metadata.competingCategories` instead of overloading
`signals` with two incompatible key vocabularies.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field

from ._base import CamelModel


class IncidentCategory(str, Enum):
    """The fixed taxonomy (section 3) — deliberately small. Never extended per-alert; a category with no real signal is UNKNOWN, not a new label invented on the spot."""

    BRUTE_FORCE = "BRUTE_FORCE"
    PHISHING = "PHISHING"
    RANSOMWARE = "RANSOMWARE"
    MALWARE = "MALWARE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    INSIDER_THREAT = "INSIDER_THREAT"
    CREDENTIAL_ATTACK = "CREDENTIAL_ATTACK"
    ACCOUNT_COMPROMISE = "ACCOUNT_COMPROMISE"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    UNKNOWN = "UNKNOWN"


ClassificationStatus = Literal["HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE", "LOW_CONFIDENCE", "UNCLASSIFIED"]


class IncidentClassification(CamelModel):
    category: str
    confidence: float
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    matched_techniques: list[str] = Field(default_factory=list)
    signals: dict[str, float] = Field(default_factory=dict)
    status: ClassificationStatus
    metadata: dict = Field(default_factory=dict)
