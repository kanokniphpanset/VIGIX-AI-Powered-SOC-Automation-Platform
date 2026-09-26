"""
RecommendationSelector — the deterministic core of Investigation
Recommendation selection (spec section 9): for a given incident
classification and the cross-agent Evidence[] list
(contracts/evidence.py::build_evidence — never recomputed here), evaluates
the Recommendation Catalog's declarative `evidence_conditions` against a
small derived signal set and returns only the recommendations whose
preconditions are actually satisfied, plus which catalog entries were
skipped for lack of evidence (-> InvestigationRecommendationReport's
`missingEvidence`).

Never selects from classification/category alone: every catalog entry
either fires on `always`/`classification_high_confidence` (a baseline
investigation/evidence-collection step any confidently-classified incident
of this type warrants) or on a concrete evidence signal (ioc_malicious,
mitre_present, ...) — see recommendation-catalog.yaml. `reason`/`rationale`
text is built deterministically here, from the matched evidence titles and
the resolved NIST/playbook references — never LLM-written, so a
hallucinated citation can never reach a per-recommendation field (the
LLM's only role in this agent is the whole-report investigation_summary,
see summary.py).

Confidence and priority both scale with how much evidence CONVERGES on a
recommendation, not just whether its condition was met at all (spec
section 6's worked example: a malicious IP alone should produce weaker
recommendations than a malicious IP + successful auth + suspicious account
activity + high-risk asset).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from src.agents.recommendation_agent.catalog import CatalogEntry, RecommendationCatalog
from src.agents.recommendation_agent.models import (
    AutomationEligibility,
    MitreReference,
    Recommendation,
    RecommendationPriority,
)
from src.contracts.evidence import EvidenceCategory, EvidenceItem

logger = logging.getLogger("soar.ai-orchestrator")

_PRIORITY_ORDER = [
    RecommendationPriority.LOW,
    RecommendationPriority.MEDIUM,
    RecommendationPriority.HIGH,
    RecommendationPriority.CRITICAL,
]

# The signal keys recommendation-catalog.yaml's evidence_conditions may
# reference. "always" is trivially true (a baseline step with no evidence
# precondition beyond the incident having been classified at all).
_KNOWN_SIGNALS = frozenset(
    {
        "always",
        "classification_high_confidence",
        "ioc_malicious",
        "mitre_present",
        "playbook_match",
        "knowledge_match",
        "llm_support",
        "high_severity",
        "asset_tier_high",
        "regulated_or_customer_facing",
    }
)

_HIGH_SEVERITIES = {"high", "critical"}
_HIGH_ASSET_TIERS = {"tier1_critical", "tier2_high"}
_FLOOR_BUSINESS_TAGS = {"regulated", "customer_facing"}


def build_signals(evidence: list[EvidenceItem], classification: dict, state: dict) -> dict[str, bool]:
    """Pure `(Evidence[], IncidentClassification-as-dict, AgentState) -> signals`
    derivation. Every signal traces to a real, already-computed fact — never
    invented here."""
    ioc_malicious = any(
        item.type == EvidenceCategory.IOC and (item.metadata or {}).get("verdict") == "MALICIOUS" for item in evidence
    )
    mitre_present = any(item.type == EvidenceCategory.MITRE_TECHNIQUE for item in evidence)
    playbook_match = any(item.type == EvidenceCategory.PLAYBOOK for item in evidence)
    knowledge_match = any(item.type == EvidenceCategory.KNOWLEDGE for item in evidence)
    llm_support = any(item.type == EvidenceCategory.LLM_ANALYSIS for item in evidence)

    high_severity = str(state.get("severity") or "").lower() in _HIGH_SEVERITIES  # Wazuh rule-level severity

    asset_tier_high = state.get("asset_criticality") in _HIGH_ASSET_TIERS
    business_tags = set(state.get("business_policy_tags") or [])
    regulated_or_customer_facing = bool(business_tags & _FLOOR_BUSINESS_TAGS)

    classification_status = (classification or {}).get("status")
    classification_high_confidence = classification_status in {"HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE"}

    return {
        "always": True,
        "classification_high_confidence": classification_high_confidence,
        "ioc_malicious": ioc_malicious,
        "mitre_present": mitre_present,
        "playbook_match": playbook_match,
        "knowledge_match": knowledge_match,
        "llm_support": llm_support,
        "high_severity": high_severity,
        "asset_tier_high": asset_tier_high,
        "regulated_or_customer_facing": regulated_or_customer_facing,
    }


def _condition_met(entry: CatalogEntry, signals: dict[str, bool]) -> bool:
    if entry.evidence_all_of and not all(signals.get(k, False) for k in entry.evidence_all_of):
        return False
    if entry.evidence_any_of and not any(signals.get(k, False) for k in entry.evidence_any_of):
        return False
    return True


def _evidence_for(entry: CatalogEntry, evidence: list[EvidenceItem], referenced_keys: set[str]) -> list[EvidenceItem]:
    matched: list[EvidenceItem] = []
    if "ioc_malicious" in referenced_keys:
        matched += [e for e in evidence if e.type == EvidenceCategory.IOC and (e.metadata or {}).get("verdict") == "MALICIOUS"]
    if "mitre_present" in referenced_keys:
        matched += [
            e
            for e in evidence
            if e.type == EvidenceCategory.MITRE_TECHNIQUE and (not entry.mitre_techniques or e.value in entry.mitre_techniques)
        ]
    if "playbook_match" in referenced_keys:
        matched += [e for e in evidence if e.type == EvidenceCategory.PLAYBOOK]
    if "knowledge_match" in referenced_keys:
        matched += [e for e in evidence if e.type == EvidenceCategory.KNOWLEDGE]
    if "llm_support" in referenced_keys:
        matched += [e for e in evidence if e.type == EvidenceCategory.LLM_ANALYSIS]
    if "high_severity" in referenced_keys:
        matched += [e for e in evidence if e.type == EvidenceCategory.SEVERITY]

    seen: set[str] = set()
    unique: list[EvidenceItem] = []
    for item in matched:
        if item.id not in seen:
            seen.add(item.id)
            unique.append(item)
    return unique


def _confidence_for(evidence_items: list[EvidenceItem], classification_confidence: float, signals: dict[str, bool]) -> float:
    """Weighted, bounded combination — never a flat/invented number.
    Converging evidence (more satisfied corroborating signals) raises
    confidence above what a single weak signal alone would earn."""
    score = 0.4 * classification_confidence
    item_confidences = [e.confidence for e in evidence_items if e.confidence is not None]
    if item_confidences:
        score += 0.4 * (sum(item_confidences) / len(item_confidences))
    corroborating = sum(1 for k in ("ioc_malicious", "mitre_present", "playbook_match", "knowledge_match", "high_severity") if signals.get(k))
    score += min(corroborating, 3) * 0.05
    return round(min(max(score, 0.0), 1.0), 2)


def _bump(priority: RecommendationPriority) -> RecommendationPriority:
    idx = _PRIORITY_ORDER.index(priority)
    return _PRIORITY_ORDER[min(idx + 1, len(_PRIORITY_ORDER) - 1)]


def _priority_for(default_priority: RecommendationPriority, signals: dict[str, bool]) -> RecommendationPriority:
    priority = default_priority
    if signals.get("high_severity") or signals.get("asset_tier_high") or signals.get("regulated_or_customer_facing"):
        priority = _bump(priority)
    return priority


def _reason_for(entry: CatalogEntry, incident_type: str, matched_evidence: list[EvidenceItem]) -> str:
    if matched_evidence:
        titles = ", ".join(e.title for e in matched_evidence[:3])
        return f"{entry.title} — supported by {titles} for a {incident_type} incident."
    return f"{entry.title} — a baseline step for a confidently classified {incident_type} incident."


def _resolve_action_id(entry: CatalogEntry) -> str | None:
    """
    Recommendation Agent does not resolve executable actions.

    The recommendation catalog may contain an action_id as metadata,
    but executable action validation belongs to the Decision Agent.

    The current Decision Agent implementation does not expose an
    Action Catalog, so Recommendation Agent must not fabricate or
    expose an executable action_id.
    """
    if entry.action_id is None or not entry.automation_hint:
        return None

    logger.debug(
        "RecommendationAgent: action_id=%r is deferred to Decision Agent",
        entry.action_id,
    )

    return None


def _rationale_for(entry: CatalogEntry, nist, playbook_refs) -> str:
    playbooks = ", ".join(p.playbook for p in playbook_refs[:2]) or "no specific playbook on file"
    return (
        f"Selected deterministically from the Recommendation Catalog for category {entry.category.value}; "
        f"aligned to {nist.name} ({nist.function or 'function not verified'}); informed by: {playbooks}."
    )


@dataclass(frozen=True)
class SelectionResult:
    recommendations: list[Recommendation]
    missing_evidence: list[str]


class RecommendationSelector:
    def __init__(self, catalog: RecommendationCatalog | None = None) -> None:
        self._catalog = catalog or RecommendationCatalog()

    def select(self, incident_type: str, classification: dict, evidence: list[EvidenceItem], state: dict) -> SelectionResult:
        signals = build_signals(evidence, classification, state)
        classification_confidence = float((classification or {}).get("confidence") or 0.0)
        entries = self._catalog.entries_for(incident_type)
        playbook_refs = self._catalog.playbook_references_for(incident_type)

        recommendations: list[Recommendation] = []
        missing_evidence: list[str] = []

        for entry in entries:
            if not _condition_met(entry, signals):
                referenced = [k for k in (*entry.evidence_all_of, *entry.evidence_any_of) if k in _KNOWN_SIGNALS]
                unmet = sorted({k for k in referenced if not signals.get(k, False)})
                missing_evidence.append(f"{entry.title}: missing {', '.join(unmet) or 'required evidence'}")
                continue

            referenced_keys = set(entry.evidence_all_of) | set(entry.evidence_any_of)
            matched_evidence = _evidence_for(entry, evidence, referenced_keys)
            nist = self._catalog.nist_reference_for(entry.category)
            confidence = _confidence_for(matched_evidence, classification_confidence, signals)
            priority = _priority_for(entry.default_priority, signals)
            # Only techniques actually PRESENT in this run's matched evidence are
            # surfaced — entry.mitre_techniques is the catalog's static "typically
            # associated technique" hint, not a claim about this specific alert, and
            # must never be presented as if it were observed (spec: "never invent a
            # MITRE technique" / every field must trace to real evidence).
            observed_techniques = sorted({e.value for e in matched_evidence if e.type == EvidenceCategory.MITRE_TECHNIQUE and e.value})
            mitre_ref = MitreReference(techniques=observed_techniques) if observed_techniques else None

            recommendations.append(
                Recommendation(
                    id=entry.id,
                    title=entry.title,
                    category=entry.category,
                    priority=priority,
                    reason=_reason_for(entry, incident_type, matched_evidence),
                    evidence=matched_evidence,
                    mitre=mitre_ref,
                    framework=nist,
                    playbook_references=playbook_refs,
                    rationale=_rationale_for(entry, nist, playbook_refs),
                    recommended_action=entry.recommended_action,
                    action_id=_resolve_action_id(entry),
                    automation=AutomationEligibility(
                        allowed=entry.automation_hint,
                        notes=(
                            "Metadata hint only — never auto-executed by RecommendationAgent; "
                            "mapping to a real Action Catalog entry, if any, remains the Decision "
                            "Agent / Action Selector's job."
                        ),
                    ),
                    confidence=confidence,
                )
            )

        return SelectionResult(recommendations=recommendations, missing_evidence=missing_evidence)