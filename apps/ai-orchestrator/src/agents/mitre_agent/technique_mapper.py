"""
TechniqueMapper — maps ObservedSignal(s) onto real, catalog-validated MITRE
techniques with attached evidence and a deterministic confidence score.

Every technique ID below is a *candidate* only — it is never returned
unless (a) the signal that names it actually fired with real evidence, and
(b) that ID is confirmed to exist in the real ~697-technique catalog
fetched from the backend (spec: "All IDs must be validated against the
MITRE knowledge base"). A candidate whose ID isn't in the live catalog is
dropped and logged, never guessed at or substituted.

The category -> technique-ID table itself is ported from the real (if
previously dead) apps/backend/src/domain/mitre/services/rule-engine/
mitre-rules/*.ts — not invented — extended to a few more categories
(discovery, C2, exfiltration) using technique IDs confirmed present in the
real catalog during Phase 3's inspection. One candidate ID from that
inspection (T1562.001) turned out not to exist in this catalog at all and
was dropped rather than shipped anyway — direct proof the validation step
does real work, not just decoration.

No LLM is involved in generating or validating these mappings (spec
section 6 makes LLM involvement optional; this module works standalone so
an LLM-based re-ranking layer could be added later without this contract
changing — it would only ever be handed already-validated candidates to
rank, never asked to invent an ID).
"""

from __future__ import annotations

import logging

from .behavior_extractor import ObservedSignal
from .behavior_signals import BRUTE_FORCE_HIGH_CONFIDENCE_MULTIPLIER, BRUTE_FORCE_MIN_FAILED_ATTEMPTS
from .knowledge_base_client import MitreKnowledgeBaseClient
from .mapping_status import classify_mapping_status
from .types import MappedTechnique

logger = logging.getLogger("soar.ai-orchestrator.mitre-agent")

# category -> [(techniqueId, baseConfidence), ...]. A category may map to
# more than one technique (e.g. encoding a PowerShell command is
# simultaneously "how it ran" and "how it hid" — two distinct techniques,
# same evidence) — ported verbatim from EncodedPowerShellExecutionRule +
# ObfuscatedPowerShellDefenseEvasionRule.
_CATEGORY_TO_TECHNIQUES: dict[str, list[tuple[str, float]]] = {
    "BRUTE_FORCE": [("T1110", 0.8)],
    "CREDENTIAL_DUMPING": [("T1003.001", 0.9)],
    "ENCODED_POWERSHELL": [("T1059.001", 0.9), ("T1027", 0.6)],
    "POWERSHELL_CRADLE": [("T1059.001", 0.85)],
    "PERSISTENCE_SCHTASKS": [("T1053.005", 0.75)],
    "PERSISTENCE_REGISTRY": [("T1547.001", 0.75)],
    "LATERAL_MOVEMENT": [("T1021.002", 0.8)],
    "DISCOVERY": [("T1082", 0.6)],
    "COMMAND_AND_CONTROL": [("T1071.001", 0.7)],
    "EXFILTRATION_ARCHIVE": [("T1560.001", 0.65)],
    "EXFILTRATION_TRANSFER": [("T1041", 0.65)],
    "IMPACT_SHADOW_COPY": [("T1490", 0.85)],
    "IMPACT_RANSOM_EXTENSION": [("T1486", 0.85)],
}

NO_SUPPORTED_MAPPING = "NO_SUPPORTED_MAPPING"

# Base confidence for a technique ID asserted directly by the SIEM's own
# rule metadata (behavior_extractor.py's "NATIVE_MITRE:<id>" signals) —
# lower than a strong keyword match with multiple corroborating fields
# (e.g. CREDENTIAL_DUMPING's 0.9), but higher than a single weak keyword
# hit (DISCOVERY's 0.6), since it reflects the SIEM vendor's own curated
# rule-to-technique attribution rather than this agent's own inference.
_NATIVE_MITRE_BASE_CONFIDENCE = 0.8


def _display_tactic(raw_tactic: str) -> str:
    """"CREDENTIAL_ACCESS" -> "Credential Access" — the catalog (via the
    backend's MitreTacticMapper) already normalizes tactics onto the fixed
    14-entry MitreTactic enum, so this is a plain string transform, not a
    second lookup table."""
    return raw_tactic.replace("_", " ").title()


def _confidence_for(category: str, base: float, evidence_count: int, has_threat_intel: bool, signal: ObservedSignal) -> float:
    confidence = base
    if evidence_count > 1:
        confidence += 0.05 * (evidence_count - 1)
    if has_threat_intel:
        confidence += 0.05

    if category == "BRUTE_FORCE":
        # Ported from BRUTE_FORCE_HIGH_CONFIDENCE_MULTIPLIER's original
        # intent: a failed-attempt count at least double the minimum
        # threshold is corroborating evidence in itself, not just a
        # pass/fail signal.
        for e in signal.evidence:
            if e.field == "failedAttempts" and isinstance(e.value, int):
                if e.value >= BRUTE_FORCE_MIN_FAILED_ATTEMPTS * BRUTE_FORCE_HIGH_CONFIDENCE_MULTIPLIER:
                    confidence = max(confidence, 0.92)

    return min(1.0, round(confidence, 2))


class TechniqueMapper:
    def __init__(self, knowledge_base_client: MitreKnowledgeBaseClient):
        self._kb = knowledge_base_client

    async def map_signals(self, signals: list[ObservedSignal]) -> list[MappedTechnique]:
        if not signals:
            return []

        catalog = await self._kb.get_catalog()
        merged: dict[str, MappedTechnique] = {}

        for observed_signal in signals:
            if observed_signal.category.startswith("NATIVE_MITRE:"):
                candidates = [(observed_signal.category.removeprefix("NATIVE_MITRE:"), _NATIVE_MITRE_BASE_CONFIDENCE)]
            else:
                candidates = _CATEGORY_TO_TECHNIQUES.get(observed_signal.category, [])
            has_threat_intel = any(e.source == "threat_intel" for e in observed_signal.evidence)

            for technique_id, base_confidence in candidates:
                record = catalog.get(technique_id)
                if record is None:
                    # Validation failing IS the point — never substitute a
                    # nearby ID or fabricate a record. Log and drop.
                    logger.warning(
                        "mitre_agent.technique.not_in_catalog",
                        extra={"techniqueId": technique_id, "category": observed_signal.category},
                    )
                    continue

                confidence = _confidence_for(
                    observed_signal.category, base_confidence, len(observed_signal.evidence), has_threat_intel, observed_signal
                )
                evidence_sources = sorted({e.source for e in observed_signal.evidence})

                if technique_id in merged:
                    existing = merged[technique_id]
                    existing.evidence.extend(observed_signal.evidence)
                    existing.confidence = min(1.0, round(max(existing.confidence, confidence) + 0.05, 2))
                    existing.evidence_source = "+".join(sorted(set(existing.evidence_source.split("+")) | set(evidence_sources)))
                else:
                    merged[technique_id] = MappedTechnique(
                        technique_id=technique_id,
                        technique_name=record.name,
                        tactic=_display_tactic(record.tactics[0]) if record.tactics else "",
                        confidence=confidence,
                        evidence=list(observed_signal.evidence),
                        evidence_source="+".join(evidence_sources),
                        is_sub_technique=record.is_sub_technique,
                        parent_technique_id=record.parent_technique_id,
                    )

        for technique in merged.values():
            self._apply_mapping_status(technique)

        return sorted(merged.values(), key=lambda m: m.confidence, reverse=True)

    def _apply_mapping_status(self, technique: MappedTechnique) -> None:
        """MITRE gap-fill — buckets this already-computed confidence into
        the spec's 5-value mappingStatus, gating a sub-technique pick on
        independent evidence-source corroboration exactly like the
        backend's MappingStatusClassifierService. `context_consistent`
        stays True by default: this pipeline has no explicit
        contradicting-context signal today (unlike the backend's
        classification/risk-based check), so there is nothing to flag it
        false against."""
        corroborating_evidence_count = len({source for source in technique.evidence_source.split("+") if source})
        result = classify_mapping_status(
            confidence=technique.confidence,
            evidence_supported=len(technique.evidence) > 0,
            behavior_matched=True,
            context_consistent=True,
            is_sub_technique_pick=technique.is_sub_technique,
            corroborating_evidence_count=corroborating_evidence_count,
        )
        technique.mapping_status = result.status
        technique.validation = result.validation.to_dict()
        technique.reason = result.reason
