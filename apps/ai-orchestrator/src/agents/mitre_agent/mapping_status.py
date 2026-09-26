"""
mapping_status — buckets a matched technique's already-computed, continuous
confidence into the spec's 5-value mappingStatus enum (CONFIRMED /
HIGH_CONFIDENCE / POSSIBLE / CONTEXT_ONLY / NO_MAPPING), applying the same
confidence-gating rule as the backend's
domain/mitre/services/mapping-status/MappingStatusClassifierService.ts —
deliberately mirrored, not shared code (TS vs Python, no cross-language
module is feasible here), so both implementations of the spec's contract
apply the identical rule: a high raw confidence can never override missing
required evidence, and a specific sub-technique pick needs at least 2
independent corroborating evidence sources before it survives — a single
weak signal (the spec's "Tor Exit Node alone" example) is never enough to
confirm a sub-technique, only its broader technique-level context.

Pure, deterministic, explainable — no LLM involved, same principle as
technique_mapper.py's own confidence scoring.
"""

from __future__ import annotations

from dataclasses import dataclass

MIN_CORROBORATION_FOR_SUB_TECHNIQUE = 2
MIN_CORROBORATION_FOR_CONTEXT_ESCALATION = 2
HIGH_CONFIDENCE_THRESHOLD = 0.5
CONFIRMED_THRESHOLD = 0.85


@dataclass
class MappingStatusValidation:
    evidence_supported: bool
    behavior_matched: bool
    context_consistent: bool

    def to_dict(self) -> dict:
        return {
            "evidenceSupported": self.evidence_supported,
            "behaviorMatched": self.behavior_matched,
            "contextConsistent": self.context_consistent,
        }


@dataclass
class MappingStatusResult:
    status: str
    validation: MappingStatusValidation
    reason: str


def classify_mapping_status(
    *,
    confidence: float,
    evidence_supported: bool,
    behavior_matched: bool,
    context_consistent: bool,
    is_sub_technique_pick: bool,
    corroborating_evidence_count: int,
) -> MappingStatusResult:
    validation = MappingStatusValidation(evidence_supported, behavior_matched, context_consistent)

    if not behavior_matched:
        return MappingStatusResult(
            "NO_MAPPING",
            validation,
            "No required behavior for this technique was actually observed; no mapping can be asserted regardless of confidence.",
        )

    insufficient_corroboration = corroborating_evidence_count < MIN_CORROBORATION_FOR_CONTEXT_ESCALATION
    sub_technique_under_supported = is_sub_technique_pick and corroborating_evidence_count < MIN_CORROBORATION_FOR_SUB_TECHNIQUE

    if not evidence_supported or insufficient_corroboration or sub_technique_under_supported:
        reason = (
            f"The observed behavior is consistent with this technique's category, but only "
            f"{corroborating_evidence_count} independent source(s) corroborate it — not enough to confirm the "
            f"specific sub-technique, only its broader context."
            if is_sub_technique_pick
            else "The observed behavior is consistent with this technique, but supporting evidence is too thin "
            "(missing or fewer than 2 independent sources) to treat it as more than contextual."
        )
        return MappingStatusResult("CONTEXT_ONLY", validation, reason)

    if confidence < HIGH_CONFIDENCE_THRESHOLD:
        return MappingStatusResult(
            "POSSIBLE",
            validation,
            f"Confidence {confidence:.2f} is below the 0.50 threshold for HIGH_CONFIDENCE, even though evidence and context are consistent.",
        )

    confirmed_eligible = (
        confidence >= CONFIRMED_THRESHOLD
        and context_consistent
        and corroborating_evidence_count >= MIN_CORROBORATION_FOR_SUB_TECHNIQUE
    )
    if confirmed_eligible:
        return MappingStatusResult(
            "CONFIRMED",
            validation,
            f"Confidence {confidence:.2f} meets the 0.85 threshold, backed by {corroborating_evidence_count} "
            f"independent corroborating source(s) and a consistent context.",
        )

    return MappingStatusResult(
        "HIGH_CONFIDENCE",
        validation,
        f"Confidence {confidence:.2f} and consistent supporting evidence justify high confidence, but not yet full confirmation.",
    )
