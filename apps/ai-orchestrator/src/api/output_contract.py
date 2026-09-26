"""
BuildOutputContract — assembles the final structured Output Contract (spec
sections 12-13) from the completed graph's final AgentState. Deliberately
keeps observed facts, provider evidence, MITRE mapping, retrieved
knowledge, LLM analysis, and classification as separate top-level keys —
never flattened into one blob, never letting the LLM's prose stand in as
the "source" of any of the other sections.

The "classification" section is produced by the real Incident
Classification Agent (agents/classification_agent/classification_rules.py)
— a deterministic, multi-signal, evidence-grounded scorer over a small
fixed taxonomy (contracts/classification.py), reading only the already-
built Evidence[] list. classify_incident() below is an older, narrower,
single-technique-label helper kept only for its own direct tests — it is
no longer this module's source of truth for that section (see its own
docstring).
"""

from __future__ import annotations

import re

from src.agents.classification_agent.classification_rules import classify
from src.contracts.error_builder import build_errors
from src.contracts.evidence import build_evidence

_NON_ALNUM = re.compile(r"[^A-Z0-9]+")


def classify_incident(state: dict) -> dict:
    """
    Returns {"label": str, "basis": "mitre_mapping" | "unclassified", "techniqueId": str | None}.

    Superseded as the source of AnalysisResult's "classification" section by
    the real Incident Classification Agent (agents/classification_agent/
    classification_rules.py::classify) — that engine scores evidence
    against a small, fixed taxonomy (contracts/classification.py) rather
    than free-form-labeling whichever technique happens to have the highest
    confidence, so it cannot be reduced to a thin wrapper around this
    function without changing its behavior (e.g. this function can return
    a label like "OS_CREDENTIAL_DUMPING_LSASS_MEMORY" that isn't a member
    of that taxonomy at all). Left in place, unmodified, only because
    nothing else in this codebase depends on it and its own tests exercise
    it directly — see api/output_contract.py's own audit note in the
    Incident Classification Agent task report for the reasoning.
    """
    report = state.get("mitre_mapping_report") or {}
    techniques = report.get("techniques") or []
    if not techniques:
        return {"label": "UNCLASSIFIED", "basis": "unclassified", "techniqueId": None}

    top = max(techniques, key=lambda t: t.get("confidence", 0))
    # "Brute Force" -> "BRUTE_FORCE"; "OS Credential Dumping: LSASS Memory" -> "OS_CREDENTIAL_DUMPING_LSASS_MEMORY"
    label = _NON_ALNUM.sub("_", top.get("techniqueName", "").upper()).strip("_") or "UNCLASSIFIED"
    return {"label": label, "basis": "mitre_mapping", "techniqueId": top.get("techniqueId")}


# The graph's real, fixed node order (build_graph.py) — used only to report
# which agents ran, not to re-derive any of their output.
PIPELINE_AGENT_ORDER = [
    "threat_intel",
    "mitre",
    "rag",
    "llm_analyst",
    "validation",
    "decision",
    "business_analytics",
    "feedback",
]


def _agents_section(state: dict) -> list[dict]:
    """Per-agent PENDING/SUCCESS/SKIPPED reporting — mirrors the backend's
    GetExecutionStatusUseCase logic (Phase 4), computed here from the same
    real state the agents actually wrote rather than guessed."""
    ran = {
        "threat_intel": "threat_intel_report" in state,
        "mitre": "mitre_mapping_report" in state,
        "rag": "rag_result" in state,
        "llm_analyst": bool(state.get("llm_summary")),
        "validation": "validation_passed" in state,
        "decision": bool(state.get("decision")),
        "business_analytics": "kpi_snapshot" in state,
        "feedback": "feedback_logged" in state,
    }
    return [{"name": name, "status": "SUCCESS" if ran.get(name) else "SKIPPED"} for name in PIPELINE_AGENT_ORDER]


def _compute_status(legacy_errors: list, structured_errors: list) -> str:
    """
    Minimal adaptation to the Universal Error Contract (section 9) — not a
    new state machine, one more branch on the same shape this function
    already had: any CRITICAL structured error means the pipeline could not
    safely continue (FAILED, a status this function previously never
    produced at all); any other error (structured or legacy) is the
    existing PARTIAL_SUCCESS behavior; no errors at all is SUCCESS,
    unchanged.
    """
    if any(e.get("severity") == "CRITICAL" for e in structured_errors):
        return "FAILED"
    if legacy_errors or structured_errors:
        return "PARTIAL_SUCCESS"
    return "SUCCESS"


def build_output_contract(execution_id: str, alert: dict, incident_id: str, final_state: dict) -> dict:
    errors = final_state.get("errors") or []
    validation_passed = final_state.get("validation_passed")
    evidence_items = build_evidence(final_state)
    structured_errors = [item.model_dump(by_alias=True, mode="json") for item in build_errors(final_state)]
    # Incident Classification Agent (contracts/classification.py) — the ONE
    # source of truth for "what type of incident is this". Computed from
    # the same Evidence[] list as the "evidence" section below, not from
    # classify_incident() above (see that function's own docstring for why
    # it could not become a compatibility wrapper instead).
    classification = final_state.get("classification") or classify(evidence_items).model_dump(by_alias=True, mode="json")

    return {
        "executionId": execution_id,
        "status": _compute_status(errors, structured_errors),
        # Universal Error Contract (contracts/error.py) — every item traces
        # back to an agent's own already-existing structured output (see
        # error_builder.py). Additive top-level section, sibling to
        # "evidence" below; the legacy raw-string list is preserved
        # unchanged at execution.errors (see below) for backward
        # compatibility — nothing reading that field today needs to change.
        "errors": structured_errors,
        "input": {
            "alertId": alert["id"],
            "externalAlertId": alert["external_alert_id"],
            "type": "alert",
        },
        # 1. Provider evidence (Phase 2) — never the LLM's own claim.
        "threatIntel": final_state.get("threat_intel_report", {}),
        # 2. MITRE mapping (Phase 3) — catalog-validated, evidence-backed only.
        "mitreMapping": final_state.get("mitre_mapping_report", {}),
        # 3. Retrieved knowledge (RagAgent) — real Qdrant hits, never fabricated.
        "ragContext": final_state.get("rag_result", {}),
        # 4. LLM analysis — reasoning ABOUT the sections above, never itself
        # treated as evidence for them.
        "analysis": {
            # "LLM" = summary is a real LLM answer (model below); "FAILED" = the LLM call failed, summary is empty
            # and the pipeline status is FAILED. Never a fallback template presented as an LLM result.
            "source": final_state.get("analysis_source"),
            "model": (final_state.get("analyst_report") or {}).get("model"),
            "summary": final_state.get("llm_summary"),
            "recommendation": final_state.get("llm_recommendation"),
            # LLM Analyst Stage task: structured, evidence-traceable findings
            # (llm_analyst_agent/findings.py) — additive sibling to summary/
            # recommendation above; [] when llm_analyst never ran.
            "keyFindings": final_state.get("llm_key_findings", []),
        },
        # 5. Classification — Incident Classification Agent (section 18):
        # deterministic, multi-signal, evidence-grounded (see `classification`
        # above). No longer classify_incident()'s single-technique label.
        "classification": classification,
        # 5a. Investigation Recommendation — RecommendationAgent's full
        # InvestigationRecommendationReport (Investigation -> Recommendation
        # capability, agents/recommendation_agent/): NIST SP 800-61
        # Rev.3-aligned, MITRE-contextualized, evidence-traceable
        # recommendations, sitting between classification and the decision
        # below. None when recommendation_agent never ran in this pipeline
        # (e.g. a bare test state) — reads the SAME `investigation_recommendation_report`
        # key recommendation_agent.run() already writes, never a second
        # recommendation format. Never a command to execute; see
        # agents/recommendation_agent/models.py's own docstring.
        "investigationRecommendation": final_state.get("investigation_recommendation_report"),
        # 5b. Decision — DecisionAgent's full DecisionResult (Decision Agent
        # + Policy Engine task): decision/outcome, priority, recommended
        # actions, approval requirement, execution mode, policy provenance,
        # reasons, conditions, audit/traceability. None when decision_agent
        # never ran in this pipeline (e.g. a bare test state) — reads the
        # SAME `decision_result` key decision_agent.run() already writes,
        # not a second decision format. Never a command to execute; see
        # decision_agent/models.py::DecisionResult's own docstring.
        "decision": final_state.get("decision_result"),
        # 6. Universal Evidence Contract (contracts/evidence.py) — every
        # item traces back to one of the sections above (threatIntel/
        # mitreMapping/ragContext) or to llm_analyst's own
        # AgentState keys; never a new fact invented here. Additive: any
        # existing caller of build_output_contract() that doesn't look at
        # "evidence" is unaffected. Same evidence_items the classification
        # above was computed from — built once, reused for both sections.
        "evidence": [item.model_dump(by_alias=True, mode="json") for item in evidence_items],
        "validation": {
            "passed": validation_passed,
            "notes": final_state.get("validation_notes", []),
            # Validation Stage task: additive richer status alongside the
            # legacy passed/notes above — status defaults to None (not
            # computed) rather than a guessed VALID/INVALID when
            # ValidationAgent never ran in this pipeline.
            "status": final_state.get("validation_status"),
            "checks": final_state.get("validation_checks", []),
        },
        "execution": {
            "executionId": execution_id,
            "incidentId": incident_id,
            "errors": errors,
            "agents": _agents_section(final_state),
        },
    }
