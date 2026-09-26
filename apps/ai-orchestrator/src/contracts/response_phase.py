"""
ResponsePhase — a small, controlled VIGIX operational vocabulary for
"where in the incident-response lifecycle does this knowledge/chunk
apply". Lives in contracts/ (the existing shared cross-agent vocabulary
layer — same home as classification.py/evidence.py) because both
rag_agent (retrieval-context matching) and, in the future, any other
agent that reasons about response lifecycle stage need the same five
values, never a locally-invented near-duplicate.

IMPORTANT (explicitly required by the task that introduced this file):
these five values are a VIGIX-defined operational taxonomy inspired by
incident-response guidance and common playbook structure — NOT a literal
claim that NIST SP 800-61 Rev.3 mandates exactly these five labels. See
resources/mappings/nist-800-61-r3-mapping.yaml for the (separate, already
existing) traceability from VIGIX's own RecommendationCategory values to
real NIST CSF 2.0 functions.

These five values are a coincidental superset match with 5 of
RecommendationAgent's 8 RecommendationCategory values
(recommendation_agent/models.py) — INVESTIGATION/CONTAINMENT/ERADICATION/
RECOVERY/POST_INCIDENT appear in both. This module does NOT import from
recommendation_agent (agents never import another agent's internals — see
rag_agent/types.py's own docstring for the established convention); the
values are simply the same real-world lifecycle stages, defined once here
as literal strings.
"""

from __future__ import annotations

from typing import Literal

ResponsePhase = Literal["INVESTIGATION", "CONTAINMENT", "ERADICATION", "RECOVERY", "POST_INCIDENT"]

RESPONSE_PHASES: tuple[ResponsePhase, ...] = ("INVESTIGATION", "CONTAINMENT", "ERADICATION", "RECOVERY", "POST_INCIDENT")

# Deterministic, rule-based mapping (never LLM-assisted) from the existing
# playbook lifecycle-phase vocabulary already used for chunk-level tagging
# (apps/backend/.../domain/knowledge/types/NormalizedPlaybookMetadata.ts's
# PLAYBOOK_LIFECYCLE_PHASES: detection/triage/containment/eradication/
# recovery/postIncident — the real values already stored per-chunk in
# Qdrant's `phase` payload field) onto this controlled vocabulary.
# "detection" and "triage" both collapse to INVESTIGATION: VIGIX's own
# taxonomy doesn't distinguish the two as separate response phases (see
# RecommendationCategory, which also has no separate "triage" value).
_LIFECYCLE_PHASE_TO_RESPONSE_PHASE: dict[str, ResponsePhase] = {
    "detection": "INVESTIGATION",
    "triage": "INVESTIGATION",
    "containment": "CONTAINMENT",
    "eradication": "ERADICATION",
    "recovery": "RECOVERY",
    "postIncident": "POST_INCIDENT",
}


def map_lifecycle_phase_to_response_phase(lifecycle_phase: str | None) -> ResponsePhase | None:
    """
    Deterministic, rule-based (never LLM/guessed) mapping. Returns None for
    an unrecognized or absent phase — e.g. a chunk's `phase` is null for a
    scenario-overview or "additional guidance" chunk (see
    PlaybookSectionChunker.ts) — never fabricates a best-guess phase for it.
    """
    if not lifecycle_phase:
        return None
    return _LIFECYCLE_PHASE_TO_RESPONSE_PHASE.get(lifecycle_phase)
