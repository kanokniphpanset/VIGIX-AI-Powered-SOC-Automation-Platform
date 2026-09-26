"""
build_key_findings() — LlmAnalystAgent's structured "what evidence indicates
this is security-relevant" output (task: LLM Analyst Stage, section 4/5).

Deliberately NOT an LLM call: LlamaProvider (llm/llama_provider.py) has no
JSON-mode/function-calling contract, so asking the model to freeform-emit a
structured findings array would be a new, unvalidated hallucination surface
this codebase doesn't currently support (see agent.py's own module comment:
"this architecture has no JSON schema for the LLM's response today"). This
mirrors the same choice recommendation_agent already made for its own
structured output (see recommendation_agent/agent.py's module docstring:
"Ask the LLM for ONE grounded investigation summary — never for individual
recommendation reasons") and reuses the exact same real, already-computed
AgentState sources contracts/evidence.py reshapes — never a second,
diverging read of "what evidence exists".

Each finding is only emitted when the backing data genuinely exists —
a category with nothing to report simply contributes no finding, never a
fabricated placeholder. `confidence` is always a real value already produced
by the source agent (or None), never invented here.
"""

from __future__ import annotations


def _mitre_findings(state: dict) -> list[dict]:
    report = state.get("mitre_mapping_report") or {}
    techniques = report.get("techniques") or []

    if not techniques:
        # Legacy flat shape fallback — same tolerance contracts/evidence.py's
        # mitre_evidence() applies for a partial/unit-test state.
        techniques = [
            {
                "techniqueId": m.get("technique_id"),
                "techniqueName": m.get("name"),
                "tactic": m.get("tactic"),
                "confidence": m.get("confidence"),
            }
            for m in (state.get("mitre_techniques") or [])
            if m.get("technique_id")
        ]

    findings = []
    for t in techniques:
        technique_id = t.get("techniqueId")
        if not technique_id:
            continue
        tactic = t.get("tactic")
        name = t.get("techniqueName") or ""
        tactic_clause = f" under the {tactic} tactic" if tactic else ""
        findings.append(
            {
                "finding": f"Observed behavior maps to MITRE ATT&CK technique {technique_id}"
                f"{f' ({name})' if name else ''}{tactic_clause}.",
                "evidence": [f"MITRE ATT&CK {technique_id}" + (f" — {name}" if name else "")],
                "confidence": t.get("confidence"),
            }
        )
    return findings


def _threat_intel_findings(state: dict) -> list[dict]:
    report = state.get("threat_intel_report") or {}
    indicators = report.get("indicators") or []

    findings = []
    for indicator in indicators:
        verdict = indicator.get("verdict")
        ioc = indicator.get("ioc")
        if not verdict or verdict.lower() in ("unknown", "none") or not ioc:
            continue
        ioc_type = indicator.get("iocType") or "indicator"
        evidence_refs = [
            f"{ev.get('provider', 'unknown provider')} — {ev.get('evidenceType', 'evidence')}"
            for ev in (indicator.get("evidence") or [])
        ]
        findings.append(
            {
                "finding": f"Indicator {ioc} ({ioc_type}) was assessed as {verdict} by threat intelligence.",
                "evidence": evidence_refs or [f"threat intelligence verdict: {verdict}"],
                "confidence": indicator.get("confidence"),
            }
        )
    return findings


def _rag_grounding_finding(state: dict) -> dict | None:
    rag_result = state.get("rag_result") or {}
    grounded = rag_result.get("groundedContext") or {}
    knowledge_matched = grounded.get("knowledgeStatus") == "MATCHED"
    playbook_matched = grounded.get("playbookStatus") == "MATCHED"
    if not knowledge_matched and not playbook_matched:
        return None

    titles = [k.get("title") for k in (rag_result.get("knowledge") or []) if k.get("title")]
    titles += [p.get("title") for p in (rag_result.get("playbooks") or []) if p.get("title")]
    if not titles:
        return None

    return {
        "finding": "Relevant security knowledge/playbook guidance was retrieved to ground this analysis.",
        "evidence": [f"Retrieved: {title}" for title in titles],
        "confidence": grounded.get("confidence"),
    }


def build_key_findings(state: dict) -> list[dict]:
    """Returns [] when no upstream agent produced anything to report on —
    an honest empty list, never a fabricated finding. Order: MITRE, threat
    intel, ML risk, RAG grounding (evidence-strength-first, matching
    contracts/evidence.py's own build_evidence() ordering convention)."""
    findings: list[dict] = []
    findings.extend(_mitre_findings(state))
    findings.extend(_threat_intel_findings(state))


    rag_finding = _rag_grounding_finding(state)
    if rag_finding:
        findings.append(rag_finding)

    return findings
