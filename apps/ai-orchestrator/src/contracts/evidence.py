"""
EvidenceItem — the Universal Evidence Contract.

Answers "why did VIGIX reach this analysis?" as one flat, UI-renderable
list, built ENTIRELY from data individual agents already produce. This
module never computes anything new — every converter function below is a
pure `(state: dict) -> list[EvidenceItem]` reshape of an existing
AgentState key (`threat_intel_report`, `mitre_mapping_report`, `rag_result`,
`severity` (Wazuh), `llm_summary`/
`llm_recommendation`). None of threat_intel_agent, mitre_agent, rag_agent,
or llm_analyst_agent is imported or modified by this module.

Naming note: this codebase already has TWO other, narrower "Evidence"
dataclasses (threat_intel_agent/types.py::Evidence — one provider-attributed
fact about an IOC; mitre_agent/types.py::Evidence — one field-level fact
supporting a technique mapping) plus decision_agent/models.py::EvidenceSummary
(condensed counts/IDs only, DecisionAgent-internal). This module's
`EvidenceItem` is a different, broader concept — a cross-agent, UI-facing
record — named distinctly so it never collides with or is mistaken for
either existing type. The threat_intel Evidence dataclass in particular is
exactly what `ioc_and_threat_intel_evidence()` below reads FROM (it doesn't
reimplement or replace it).
"""

from __future__ import annotations

from enum import Enum
from itertools import count

from ._base import CamelModel


class EvidenceCategory(str, Enum):
    IOC = "IOC"
    MITRE_TECHNIQUE = "MITRE_TECHNIQUE"
    KNOWLEDGE = "KNOWLEDGE"
    PLAYBOOK = "PLAYBOOK"
    RISK = "RISK"  # LEGACY (no longer produced): ML risk-score evidence was retired
    SEVERITY = "SEVERITY"
    LLM_ANALYSIS = "LLM_ANALYSIS"


class EvidenceKind(str, Enum):
    """
    Phase 8's required distinction: an LLM's prose is an interpretation OF
    evidence, never evidence itself. Every converter function below sets
    this by construction — FACTUAL_EVIDENCE for IOC/MITRE_TECHNIQUE/
    KNOWLEDGE/PLAYBOOK/RISK (all deterministic, observed, or computed by a
    fixed formula), ANALYST_INTERPRETATION for LLM_ANALYSIS only. No code
    path can set LLM_ANALYSIS items to FACTUAL_EVIDENCE — there is exactly
    one place (`llm_analysis_evidence()`) that constructs them, mirroring
    how recommendation_builder.py::_requires_approval() is the single place
    that can ever set requiresApproval.
    """

    FACTUAL_EVIDENCE = "FACTUAL_EVIDENCE"
    ANALYST_INTERPRETATION = "ANALYST_INTERPRETATION"


class EvidenceItem(CamelModel):
    id: str
    type: EvidenceCategory
    kind: EvidenceKind
    agent: str
    source: str | None = None
    title: str
    value: str | None = None
    description: str | None = None
    confidence: float | None = None
    timestamp: str | None = None
    traceability: dict = {}
    metadata: dict = {}


def _next_id(agent: str, category: EvidenceCategory, counter: count) -> str:
    return f"{agent}-{category.value.lower()}-{next(counter)}"


def ioc_and_threat_intel_evidence(state: dict) -> list[EvidenceItem]:
    """
    Reads threat_intel_report.indicators[].evidence[] — the flattened,
    indicator-level union of every provider's real Evidence records
    (threat_intel_agent/result_contract.py::build_result_contract, spec
    section 10 — confirmed against a REAL live run, not just that module's
    own unit tests; see the bug this replaced, below). One EvidenceItem per
    real evidence entry: a provider that returned NOT_CONFIGURED/FAILED/
    TIMEOUT/RATE_LIMITED never contributes one (that dataclass's own
    contract already guarantees this), so nothing here can fabricate a
    finding a provider didn't actually report.

    BUG FIX (LangGraph Integration task, found via live smoke test against
    real VirusTotal/AbuseIPDB/MISP/OTX responses, not a redesign): this
    function previously read `indicator.get("indicator")`/`.get("type")`/
    `.get("riskLevel")` and a per-provider `.get("confidence")` — a shape
    that matches `ThreatIntelData.to_dict()` (types.py) but NOT the actual
    contract `_service.analyze_alert()` really produces
    (`build_result_contract()`, which uses `ioc`/`iocType`, has no
    `riskLevel` key, and has no per-provider `confidence` at all — only one
    overall `confidence` per indicator). The mismatch silently produced
    `confidence=None`/`iocType=None` for every single IOC EvidenceItem in
    every real run — never caught by unit tests because their own fixture
    encoded the same wrong shape. Iterating the indicator's own flattened
    `evidence` list (rather than nesting through `providers[].evidence[]`)
    both fixes this and is simpler — each evidence dict already carries its
    own `provider` key (Evidence.to_dict()), so no information is lost.
    """
    report = state.get("threat_intel_report") or {}
    indicators = report.get("indicators") or []
    counter = count()
    items: list[EvidenceItem] = []

    for indicator in indicators:
        indicator_confidence = indicator.get("confidence")
        for ev in indicator.get("evidence") or []:
            items.append(
                EvidenceItem(
                    id=_next_id("threat_intel", EvidenceCategory.IOC, counter),
                    type=EvidenceCategory.IOC,
                    kind=EvidenceKind.FACTUAL_EVIDENCE,
                    agent="threat_intel",
                    source=ev.get("provider"),
                    title=f"{ev.get('provider', 'unknown provider')} — {ev.get('evidenceType', 'evidence')}",
                    value=ev.get("ioc"),
                    description=ev.get("summary") or None,
                    confidence=indicator_confidence,
                    timestamp=ev.get("fetchedAt") or ev.get("observedAt"),
                    traceability={
                        "reference": ev.get("reference"),
                        "providerObjectId": ev.get("providerObjectId"),
                    },
                    metadata={
                        "iocType": indicator.get("iocType"),
                        "verdict": indicator.get("verdict"),
                    },
                )
            )
    return items


def mitre_evidence(state: dict) -> list[EvidenceItem]:
    """
    Reads mitre_mapping_report.techniques[] (mitre_agent/types.py::MappedTechnique.to_dict())
    — one EvidenceItem per matched technique, never per sub-field (the
    field-level facts in each technique's own `evidence` list are kept as
    `metadata.supportingEvidence`, not exploded into separate top-level
    items, matching Phase 5's one-item-per-technique example). Falls back
    to the legacy flat `mitre_techniques` list only if the richer report is
    absent — mirrors rag_agent/types.py::extract_investigation_context's
    own documented fallback for the same reason (a partial/unit-test state
    that only set the legacy shape should still produce sensible evidence).
    """
    report = state.get("mitre_mapping_report") or {}
    techniques = report.get("techniques") or []
    counter = count()
    items: list[EvidenceItem] = []

    if techniques:
        for t in techniques:
            items.append(
                EvidenceItem(
                    id=_next_id("mitre", EvidenceCategory.MITRE_TECHNIQUE, counter),
                    type=EvidenceCategory.MITRE_TECHNIQUE,
                    kind=EvidenceKind.FACTUAL_EVIDENCE,
                    agent="mitre",
                    source="MITRE ATT&CK",
                    title=t.get("techniqueName", ""),
                    value=t.get("techniqueId"),
                    confidence=t.get("confidence"),
                    metadata={
                        "tactic": t.get("tactic"),
                        "mappingStatus": t.get("mappingStatus"),
                        "isSubTechnique": t.get("isSubTechnique"),
                        "parentTechniqueId": t.get("parentTechniqueId"),
                        "evidenceSource": t.get("evidenceSource"),
                        "supportingEvidence": t.get("evidence") or [],
                    },
                )
            )
        return items

    # Legacy fallback — same shape query_builder/rag_agent already tolerate.
    for m in state.get("mitre_techniques") or []:
        if not m.get("technique_id"):
            continue
        items.append(
            EvidenceItem(
                id=_next_id("mitre", EvidenceCategory.MITRE_TECHNIQUE, counter),
                type=EvidenceCategory.MITRE_TECHNIQUE,
                kind=EvidenceKind.FACTUAL_EVIDENCE,
                agent="mitre",
                source="MITRE ATT&CK",
                title=m.get("name", ""),
                value=m.get("technique_id"),
                confidence=m.get("confidence"),
                metadata={"tactic": m.get("tactic")},
            )
        )
    return items


_KNOWLEDGE_CAVEAT = (
    "Retrieved knowledge used to ground the analysis — this documents what "
    "was consulted, not proof that the incident matches it."
)
_PLAYBOOK_CAVEAT = (
    "Retrieved playbook used to ground recommendations — this documents "
    "what guidance was consulted, not confirmation that the attack occurred."
)


def rag_evidence(state: dict) -> list[EvidenceItem]:
    """
    Reads rag_result.knowledge[]/playbooks[] (rag_agent/types.py::KnowledgeReference/
    PlaybookReference.to_dict()) — never rag_result.analysis (that's
    LLM-synthesized prose about this evidence, not the evidence itself; see
    llm_analysis_evidence() and the module docstring's FACTUAL_EVIDENCE/
    ANALYST_INTERPRETATION split). Explicitly notes in `description` that a
    retrieved document is evidence of *what knowledge was used*, never
    evidence that the attack definitely occurred (Phase 6's required
    distinction) — kept in the description precisely so it survives even if
    a consumer only renders that one field.

    Does not attempt to split `documentReference` into a separate
    repository/path pair: KnowledgeReference/PlaybookReference (rag_agent/
    types.py) only carry the combined `documentReference` URL and
    `sourceProvider` — `sourcePath`/`sourceRepository` are real Postgres
    columns on KnowledgeDocument but are not currently threaded through
    RagAgentOutput, and exposing them would require editing
    grounded_context_builder.py, which this task's "do not touch RAG"
    boundary rules out. `documentReference` already resolves to the exact
    source location, so traceability is not lost — just less granular than
    the task's illustrative example.
    """
    rag_result = state.get("rag_result") or {}
    counter_k = count()
    counter_p = count()
    items: list[EvidenceItem] = []

    for k in rag_result.get("knowledge") or []:
        items.append(
            EvidenceItem(
                id=_next_id("rag", EvidenceCategory.KNOWLEDGE, counter_k),
                type=EvidenceCategory.KNOWLEDGE,
                kind=EvidenceKind.FACTUAL_EVIDENCE,
                agent="rag",
                source=k.get("sourceProvider") or k.get("source"),
                title=k.get("title", ""),
                value=k.get("documentId"),
                description=f"{_KNOWLEDGE_CAVEAT} {k.get('excerpt', '')}".strip(),
                confidence=k.get("score"),
                traceability={"reference": k.get("documentReference")},
                metadata={},
            )
        )

    for p in rag_result.get("playbooks") or []:
        items.append(
            EvidenceItem(
                id=_next_id("rag", EvidenceCategory.PLAYBOOK, counter_p),
                type=EvidenceCategory.PLAYBOOK,
                kind=EvidenceKind.FACTUAL_EVIDENCE,
                agent="rag",
                source=p.get("sourceProvider"),
                title=p.get("title", ""),
                value=p.get("documentId"),
                description=f"{_PLAYBOOK_CAVEAT} {p.get('excerpt', '')}".strip(),
                confidence=p.get("score"),
                traceability={"reference": p.get("documentReference")},
                metadata={"scenario": p.get("scenario"), "phase": p.get("phase")},
            )
        )
    return items


def wazuh_severity_evidence(state: dict) -> list[EvidenceItem]:
    """
    The authoritative severity: derived deterministically from the Wazuh rule level at ingestion (backend), passed
    in as state["severity"]. FACTUAL_EVIDENCE — it comes from the SIEM, never from a model. VIGIX has no AI severity.
    """
    severity = str(state.get("severity") or "").strip().upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return []
    return [
        EvidenceItem(
            id="wazuh-severity-0",
            type=EvidenceCategory.SEVERITY,
            kind=EvidenceKind.FACTUAL_EVIDENCE,
            agent="wazuh",
            source="Wazuh rule.level -> VIGIX severity mapping",
            title="Wazuh severity",
            value=severity,
        )
    ]


def llm_analysis_evidence(state: dict) -> list[EvidenceItem]:
    """
    Reads llm_summary/llm_recommendation (llm_analyst_agent/agent.py) as
    ANALYST_INTERPRETATION, never FACTUAL_EVIDENCE — this is the one
    category in this module that is prose, not an observed/computed fact.
    `confidence` is deliberately left unset: LlmAnalystAgent's plain-text
    response carries no numeric confidence today (see its own module
    docstring — "this architecture has no JSON schema for the LLM's
    response"), and inventing one here would violate the same rule Phase 8
    exists to enforce. `metadata.availableContext` lists which upstream
    sections actually had data when the LLM ran — a real, derivable fact
    about the run, not a claim about what the LLM specifically cited.
    """
    summary = state.get("llm_summary")
    recommendation = state.get("llm_recommendation")
    if not summary and not recommendation:
        return []

    available_context = [
        key
        for key, state_key in (
            ("threat_intel", "threat_intel_report"),
            ("mitre", "mitre_mapping_report"),
            ("rag", "rag_result"),
        )
        if state.get(state_key)
    ]

    items: list[EvidenceItem] = []
    counter = count()
    if summary:
        items.append(
            EvidenceItem(
                id=_next_id("llm_analyst", EvidenceCategory.LLM_ANALYSIS, counter),
                type=EvidenceCategory.LLM_ANALYSIS,
                kind=EvidenceKind.ANALYST_INTERPRETATION,
                agent="llm_analyst",
                title="LLM Summary",
                value=summary,
                metadata={"availableContext": available_context},
            )
        )
    if recommendation:
        items.append(
            EvidenceItem(
                id=_next_id("llm_analyst", EvidenceCategory.LLM_ANALYSIS, counter),
                type=EvidenceCategory.LLM_ANALYSIS,
                kind=EvidenceKind.ANALYST_INTERPRETATION,
                agent="llm_analyst",
                title="LLM Recommendation",
                value=recommendation,
                metadata={"availableContext": available_context},
            )
        )
    return items


def build_evidence(state: dict) -> list[EvidenceItem]:
    """
    Concatenates every category, in a fixed order, from whatever the
    upstream agents actually produced. Any missing/absent source
    (no threat intel, no MITRE mapping, no RAG result, no Wazuh severity,
    LLM didn't run) contributes an empty list rather than raising — this
    function never crashes just because one optional evidence source is
    unavailable (see tests/contracts/test_evidence.py).
    """
    return [
        *ioc_and_threat_intel_evidence(state),
        *mitre_evidence(state),
        *rag_evidence(state),
        *wazuh_severity_evidence(state),
        *llm_analysis_evidence(state),
    ]
