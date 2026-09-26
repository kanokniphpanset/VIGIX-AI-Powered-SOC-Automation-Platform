"""
RecommendationBuilder (Phase D) — deterministically converts matched
PLAYBOOK chunks into RecommendedAction objects. No LLM involvement: every
field is derived from the chunk's own retrieved content/metadata, never
invented.

Non-negotiable platform rule this module exists to enforce in code, not
just in a docstring: RagAgent only ever *recommends* — DecisionAgent/the
SOAR executor is the only thing that can act. `_requires_approval()` is the
single function that decides RecommendedAction.requiresApproval, and it
returns True unconditionally for CONTAINMENT/ERADICATION — every
construction path in build() below routes through it rather than setting
the field inline, so there is exactly one place a future change could
violate the rule, and it's guarded by test_recommendation_builder.py.

Only CONTAINMENT/ERADICATION phase chunks become recommendations
(DETECTION/TRIAGE/RECOVERY/POST_INCIDENT and the phase=None overview chunk
inform relevantPlaybooks/analysis instead — see grounded_context_builder.py
— but aren't in themselves "recommended actions"). When
noRelevantPlaybook is true, build() returns [] unconditionally — never a
generic fallback recommendation invented from thin air.
"""

from __future__ import annotations

from .types import InvestigationContext, RecommendedAction

_ACTIONABLE_PHASES = {"containment", "eradication"}

_PHASE_TO_CATEGORY = {
    "containment": "CONTAINMENT",
    "eradication": "ERADICATION",
}

# Ordered so the first keyword found in the step text wins — order matters
# where a step could plausibly mention more than one (e.g. "isolate and
# collect forensic evidence from the endpoint" should read as isolation,
# the more urgent/definitive containment action, not evidence collection).
_ACTION_KEYWORDS: list[tuple[str, str]] = [
    ("isolate", "isolate_endpoint"),
    ("quarantine", "quarantine_file"),
    ("block", "block_indicator"),
    ("disable", "disable_account"),
    ("revoke", "revoke_access"),
    ("reset", "reset_credentials"),
    ("kill", "terminate_process"),
    ("terminate", "terminate_process"),
    ("snapshot", "snapshot_volume"),
    ("collect", "collect_forensic_evidence"),
    ("preserve", "collect_forensic_evidence"),
    ("patch", "apply_patch"),
    ("restore", "restore_from_backup"),
    ("notify", "notify_stakeholders"),
    ("escalate", "escalate_to_analyst"),
]

_DEFAULT_ACTION = "review_manually"

_REASON_LENGTH = 400


def _derive_action_verb(step_text: str) -> str:
    lowered = step_text.lower()
    for keyword, action in _ACTION_KEYWORDS:
        if keyword in lowered:
            return action
    return _DEFAULT_ACTION


def _requires_approval(category: str) -> bool:
    """
    Single source of truth for RecommendedAction.requiresApproval.
    CONTAINMENT/ERADICATION are always True — never settable to False for
    those two categories by any caller, any heuristic, any confidence
    score. Anything else (a DETECTION/TRIAGE-phase step, if this builder
    is ever extended to cover those) defaults to still requiring approval,
    since RagAgent recommending *anything* actionable is not itself
    authorization to skip human/DecisionAgent review — only an explicit,
    reviewed allowlist should ever be able to loosen that, and this module
    makes no such claim today.
    """
    return True


class RecommendationBuilder:
    def build(
        self,
        playbook_documents: list[dict],
        investigation_context: InvestigationContext,
        no_relevant_playbook: bool,
    ) -> list[RecommendedAction]:
        if no_relevant_playbook:
            return []

        actions: list[RecommendedAction] = []
        for rank, document in enumerate(playbook_documents, start=1):
            metadata = document.get("metadata") or {}
            phase = metadata.get("phase")
            if phase not in _ACTIONABLE_PHASES:
                continue

            step_text = (document.get("content") or "").strip()
            if not step_text:
                continue

            category = _PHASE_TO_CATEGORY[phase]
            doc_mitre_techniques = metadata.get("mitreTechniques") or []

            actions.append(
                RecommendedAction(
                    action=_derive_action_verb(step_text),
                    category=category,
                    reason=step_text[:_REASON_LENGTH],
                    # The alert's own supporting evidence (never the
                    # playbook's own claims) — grounds *why this alert*
                    # warrants the action, distinct from `reason`, which is
                    # the playbook's own guidance text.
                    evidence=list(investigation_context.evidence),
                    sourcePlaybook=document.get("title") or document.get("documentId", ""),
                    # Taken from THIS chunk's own metadata, not the
                    # investigation context — grounds the technique
                    # reference in what this specific playbook chunk is
                    # actually tagged with, rather than assuming every
                    # technique observed on the alert applies to this step.
                    mitreTechnique=doc_mitre_techniques[0] if doc_mitre_techniques else None,
                    priority=rank,
                    requiresApproval=_requires_approval(category),
                    confidence=float(document.get("score") or 0.0),
                    chunkId=document.get("chunkId"),
                )
            )

        return actions
