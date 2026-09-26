"""
Deterministic, evidence-grounded checks of LLM Analyst's free-text output
(llm_summary/llm_recommendation) against real upstream structured state —
Validation Stage task's sections 3.A/C/D/E/G.

No LLM call here — per this task's own "do NOT add another LLM call merely
to validate an LLM" instruction, every check below is regex/set-membership/
keyword matching against real state, same "weak by design, deterministic
amplifier" convention classification_agent/classification_rules.py already
established for its own llm_summary/llm_recommendation substring matching.

Every check degrades to PASS when there's nothing to check (no LLM text,
no upstream evidence to compare against) — this module never invents a
finding, and a missing optional input is never treated as a fabrication.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

CheckStatus = Literal["PASS", "WARNING", "FAIL"]


@dataclass(frozen=True)
class CheckResult:
    check: str
    status: CheckStatus
    details: str


_MITRE_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
# The real local-playbook id convention (resources/mappings/playbook-index.yaml
# ::local_playbook_id, e.g. "PB-RANSOMWARE-001") — a specific, low-false-
# -positive fabrication signal distinct from the generic knowledge-claim
# phrases below: naming one of these while RAG retrieved nothing at all is
# a concrete invented citation, not just vague "playbook-flavored" wording.
_SPECIFIC_PLAYBOOK_ID_PATTERN = re.compile(r"\bPB-[A-Z]+-\d+\b")

# Section 3.G / task's own "GOOD vs BAD" example from the LLM Analyst task
# ("Execute NET-001 immediately" is BAD): an LLM recommendation claiming an
# action was already carried out or authorized is never advisory — it is
# either a hallucination (nothing executes this early in the pipeline) or a
# recommendation Validation must never let through as if it were a report
# of a real, already-decided outcome.
_EXECUTION_OR_APPROVAL_CLAIM_PHRASES = (
    "has been executed",
    "already executed",
    "was executed",
    "successfully executed",
    "has been approved",
    "already approved",
    "approval has been granted",
    "has already been approved",
    "action has been taken",
    "has been automatically approved",
    "automatically executed",
    "i have blocked",
    "i have executed",
    "i have disabled",
)

_KNOWLEDGE_CLAIM_PHRASES = (
    "playbook",
    "according to nist",
    "standard operating procedure",
    "based on the retrieved",
    "knowledge base indicates",
    "per the incident response playbook",
)

_LOW_RISK_PHRASES = ("low risk", "minimal risk", "not a significant threat", "benign activity", "no significant risk")
_CRITICAL_RISK_PHRASES = ("critical risk", "extremely high risk", "severe imminent threat")


def _llm_text(state: dict) -> str:
    return " ".join(filter(None, [state.get("llm_summary"), state.get("llm_recommendation")]))


def _real_mitre_ids(state: dict) -> set[str]:
    report = state.get("mitre_mapping_report") or {}
    ids = {t.get("techniqueId") for t in (report.get("techniques") or []) if t.get("techniqueId")}
    ids |= {t.get("technique_id") for t in (state.get("mitre_techniques") or []) if t.get("technique_id")}
    return ids


def _real_ipv4s(state: dict) -> set[str]:
    ips: set[str] = set()
    for ioc in state.get("iocs") or []:
        value = ioc.get("ioc_value")
        if value and _IPV4_PATTERN.fullmatch(value):
            ips.add(value)
    report = state.get("threat_intel_report") or {}
    for indicator in report.get("indicators") or []:
        ioc = indicator.get("ioc")
        if ioc and _IPV4_PATTERN.fullmatch(ioc):
            ips.add(ioc)
    # IPs already present in the raw alert text are not an LLM fabrication —
    # the LLM legitimately quoting the alert it was given is expected
    # behavior, not an invented fact.
    ips |= set(_IPV4_PATTERN.findall(state.get("alert_text") or ""))
    # The same holds for the structured raw alert: llm_analyst passes it to the
    # LLM verbatim (_build_context "alert"), so e.g. the host's own agent.ip is
    # evidence the LLM was given, not an invented IP. (Before this, quoting the
    # host IP failed ioc_consistency and re-ran the whole enrichment + LLM.)
    ips |= set(_IPV4_PATTERN.findall(json.dumps(state.get("raw_alert") or {}, default=str)))
    return ips


def check_evidence_support(state: dict) -> CheckResult:
    """Section 3.A: flags a real (non-empty) LLM analysis that has
    absolutely no upstream structured evidence behind it — WARNING only,
    never FAIL, since a real LLM response grounded solely in alert_text is
    still a legitimate (if thin) analysis, not a fabrication by itself."""
    llm_text = _llm_text(state)
    if not llm_text:
        return CheckResult("evidence_support", "PASS", "No LLM analysis present to check")

    has_any_evidence = bool(
        state.get("iocs")
        or state.get("mitre_techniques")
        or (state.get("mitre_mapping_report") or {}).get("techniques")
        or (state.get("threat_intel_report") or {}).get("indicators")
        or (state.get("rag_result") or {}).get("knowledge")
        or (state.get("rag_result") or {}).get("playbooks")
    )
    if not has_any_evidence:
        return CheckResult(
            "evidence_support",
            "WARNING",
            "LLM analysis is present but no upstream IOC/MITRE/threat-intel/RAG evidence exists to support it",
        )
    return CheckResult("evidence_support", "PASS", "LLM analysis has real upstream evidence to draw on")


def check_risk_text_consistency(state: dict) -> CheckResult:
    """Section 3.B / 4: the LLM's own prose must not contradict the Wazuh rule-level severity (the only severity
    VIGIX has) — never recalculates or overrides it, only flags a textual contradiction."""
    llm_text = _llm_text(state).lower()
    severity = str(state.get("severity") or "").lower()
    if not llm_text or not severity:
        return CheckResult("risk_text_consistency", "PASS", "Nothing to cross-check (no LLM text or no Wazuh severity)")

    if severity in ("high", "critical") and any(p in llm_text for p in _LOW_RISK_PHRASES):
        return CheckResult(
            "risk_text_consistency",
            "FAIL",
            f"LLM narrative describes low/minimal risk, but the Wazuh severity is '{severity}'",
        )
    if severity == "low" and any(p in llm_text for p in _CRITICAL_RISK_PHRASES):
        return CheckResult(
            "risk_text_consistency",
            "FAIL",
            f"LLM narrative describes critical/extreme risk, but the Wazuh severity is '{severity}'",
        )
    return CheckResult("risk_text_consistency", "PASS", "LLM narrative does not contradict the Wazuh severity")


def check_mitre_consistency(state: dict) -> CheckResult:
    """Section 3.C: every MITRE technique id mentioned in the LLM's own
    prose must exist in the real upstream MITRE result — never fabricated."""
    llm_text = _llm_text(state)
    mentioned = set(_MITRE_ID_PATTERN.findall(llm_text))
    if not mentioned:
        return CheckResult("mitre_consistency", "PASS", "No MITRE technique referenced in LLM text")

    real_ids = _real_mitre_ids(state)
    fabricated = sorted(mentioned - real_ids)
    if fabricated:
        return CheckResult(
            "mitre_consistency",
            "FAIL",
            f"LLM text references MITRE technique(s) {fabricated} not present in the real upstream MITRE result {sorted(real_ids)}",
        )
    return CheckResult("mitre_consistency", "PASS", f"Every MITRE technique referenced by the LLM ({sorted(mentioned)}) is real upstream evidence")


def check_ioc_consistency(state: dict) -> CheckResult:
    """Section 3.D: every IPv4 address mentioned in the LLM's own prose
    must exist in the real incident context (IOCs, threat intel, or the raw
    alert itself) — never fabricated."""
    llm_text = _llm_text(state)
    mentioned = set(_IPV4_PATTERN.findall(llm_text))
    if not mentioned:
        return CheckResult("ioc_consistency", "PASS", "No IP address referenced in LLM text")

    real_ips = _real_ipv4s(state)
    fabricated = sorted(mentioned - real_ips)
    if fabricated:
        return CheckResult(
            "ioc_consistency",
            "FAIL",
            f"LLM text references IP address(es) {fabricated} not present anywhere in the real incident context",
        )
    return CheckResult("ioc_consistency", "PASS", f"Every IP referenced by the LLM ({sorted(mentioned)}) is real incident context")


def check_knowledge_grounding(state: dict) -> CheckResult:
    """Section 3.E: if the LLM's prose implies knowledge/playbook-grounded
    reasoning while RAG genuinely retrieved nothing, flag it. A missing/
    absent RAG result is never itself a finding — only an actual textual
    claim triggers this check.

    Two tiers, by specificity of the claim:
      - A SPECIFIC playbook id (e.g. "PB-RANSOMWARE-001") named while
        nothing was retrieved at all is a concrete invented citation -> FAIL.
      - Vaguer knowledge-flavored language ("per the playbook...") with
        nothing retrieved is a softer signal -> WARNING, never FAIL, to
        avoid over-triggering on generic advisory phrasing.
    """
    llm_text = _llm_text(state)
    llm_text_lower = llm_text.lower()
    specific_playbook_ids = set(_SPECIFIC_PLAYBOOK_ID_PATTERN.findall(llm_text))
    generic_claim = any(p in llm_text_lower for p in _KNOWLEDGE_CLAIM_PHRASES)
    if not specific_playbook_ids and not generic_claim:
        return CheckResult("knowledge_grounding", "PASS", "LLM text makes no explicit knowledge/playbook citation claim")

    rag_result = state.get("rag_result") or {}
    grounded = rag_result.get("groundedContext") or {}
    knowledge_matched = grounded.get("knowledgeStatus") == "MATCHED"
    playbook_matched = grounded.get("playbookStatus") == "MATCHED"
    nothing_retrieved = not knowledge_matched and not playbook_matched

    if specific_playbook_ids and nothing_retrieved:
        return CheckResult(
            "knowledge_grounding",
            "FAIL",
            f"LLM text cites specific playbook id(s) {sorted(specific_playbook_ids)} but RAG retrieved no knowledge or playbooks for this incident",
        )
    if generic_claim and nothing_retrieved:
        return CheckResult(
            "knowledge_grounding",
            "WARNING",
            "LLM text implies knowledge/playbook-grounded reasoning but RAG retrieved no matching knowledge or playbooks",
        )
    return CheckResult("knowledge_grounding", "PASS", "LLM's knowledge/playbook claim is backed by a real RAG match")


def check_recommendation_safety(state: dict) -> CheckResult:
    """Section 3.G: the LLM recommendation must remain advisory — it must
    never claim an action was already executed or approved (that would
    imply bypassing Validation/RecommendationAgent/DecisionAgent/Approval,
    none of which have run yet at this point in the pipeline)."""
    llm_text = _llm_text(state).lower()
    if not llm_text:
        return CheckResult("recommendation_safety", "PASS", "No LLM recommendation text to check")

    matched = [p for p in _EXECUTION_OR_APPROVAL_CLAIM_PHRASES if p in llm_text]
    if matched:
        return CheckResult(
            "recommendation_safety",
            "FAIL",
            f"LLM text claims an action was already executed/approved ({matched!r}) — recommendations must stay advisory only",
        )
    return CheckResult("recommendation_safety", "PASS", "LLM recommendation stays advisory — no execution/approval claim detected")


def run_llm_consistency_checks(state: dict) -> list[CheckResult]:
    return [
        check_evidence_support(state),
        check_risk_text_consistency(state),
        check_mitre_consistency(state),
        check_ioc_consistency(state),
        check_knowledge_grounding(state),
        check_recommendation_safety(state),
    ]
