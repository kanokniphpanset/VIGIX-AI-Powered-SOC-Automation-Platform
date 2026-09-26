"""
Plain dataclasses for RagAgent's own working data — mirrors the style
threat_intel_agent/types.py and mitre_agent/types.py already established
(cheap to construct, trivial to test, no second modeling framework
introduced). Every dataclass that can end up inside AgentState (which must
stay JSON-safe for src/api/database.py's json.dumps) carries its own
to_dict() — never stored as a raw dataclass instance, same convention as
mitre_agent/types.py::MappedTechnique.to_dict().
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

SourceType = Literal["KNOWLEDGE", "PLAYBOOK"]

_NON_ALNUM = re.compile(r"[^A-Z0-9]+")


@dataclass
class MitreTechniqueRef:
    technique_id: str
    technique_name: str = ""


@dataclass
class RagQueryInput:
    """
    Normalized input the query builder and re-ranker read from. Every field
    is optional — RagAgent runs sequentially after ThreatIntelAgent and
    MitreAgent (see build_graph.py), so on a normal first pass it already
    has mitre/malware_family/threat_categories from their completed output;
    fields stay optional mainly to degrade gracefully if either upstream
    agent found nothing for this alert, not because their output is racing
    RagAgent's. See query_builder.extract_query_input for exactly how much
    is actually derivable from AgentState at call time.

    `scenario` (Phase D) is set separately by agent.py from
    InvestigationContext.scenario (extract_query_input has no reason to
    know about it — it's a Phase D re-ranking signal, not a Phase C query
    term) and is read by reranker.py's scenario_match scoring term.
    """

    incident_type: str | None = None
    malware_family: str | None = None
    threat_categories: list[str] = field(default_factory=list)
    mitre: list[MitreTechniqueRef] = field(default_factory=list)
    alert_text: str = ""
    scenario: str | None = None
    # Explainable Retrieval task — three more Phase E re-ranking signals,
    # all set by agent.py from InvestigationContext (same pattern as
    # `scenario` above), never derived here: platform/service/
    # response_phase are retrieval-context facts, not query-construction
    # concerns.
    platform: str | None = None
    service: str | None = None
    response_phase: str | None = None


# RAG Transparency/Ranking task: `scenario` previously came ONLY from a
# threat-intel provider's own malwareFamily/categories tags (below) — for
# an indicator a provider doesn't categorize as a specific malware family
# (e.g. a generic malicious-IP/Tor-exit verdict, confirmed live: a real
# ransomware alert's own C2 IP had no VirusTotal/AbuseIPDB category tag at
# all), `scenario` silently stayed None, so reranker.py's scenario_match
# term (0.05 weight) never engaged even though the alert's real MITRE
# techniques already unambiguously identified the scenario. This is a
# small, LOCAL technique -> scenario-keyword fallback (deliberately not
# imported from classification_agent.classification_rules — same
# "agents in this package never import from a different agent's internals"
# convention _classify_from_mitre_report's own docstring above states;
# classification_agent also runs AFTER rag in the graph, so it has no
# output yet for rag to depend on regardless). Intentionally small — a
# handful of the most common scenarios, matching resources/response-
# actions and this package's own playbook scenario vocabulary
# (playbooks/*.md frontmatter's own `incidentTypes`/tags) — not
# exhaustive, since this is only ever a tie-breaking nudge, never the
# sole signal (vector_similarity still carries 10x the weight).
_SCENARIO_FROM_MITRE_TECHNIQUE: dict[str, str] = {
    "T1486": "ransomware",
    "T1490": "ransomware",
    "T1489": "ransomware",
    "T1566": "phishing",
    "T1598": "phishing",
    "T1110": "credential_compromise",
    "T1003": "credential_compromise",
    "T1078": "account_compromised",
    "T1098": "account_compromised",
    "T1041": "data_loss",
    "T1048": "data_loss",
    "T1567": "data_loss",
}


def _scenario_from_mitre(mitre_refs: list[MitreTechniqueRef]) -> str | None:
    for ref in mitre_refs:
        scenario = _SCENARIO_FROM_MITRE_TECHNIQUE.get(ref.technique_id)
        if scenario:
            return scenario
    return None


def _classify_from_mitre_report(mitre_mapping_report: dict) -> str:
    """
    Deterministic, evidence-only classification label — deliberately a
    *local* re-implementation of api/output_contract.py::classify_incident's
    exact logic (highest-confidence mapped technique's own real name upper-
    snake-cased; "UNCLASSIFIED" with no mapping) rather than an import from
    it: agents in this package never import from src/api/** (that layer
    depends on agents, not the other way around — see build_graph.py), and
    the logic itself is 5 lines, cheap enough to keep in lockstep rather
    than introduce a layering violation to share it.
    """
    techniques = mitre_mapping_report.get("techniques") or []
    if not techniques:
        return "UNCLASSIFIED"
    top = max(techniques, key=lambda t: t.get("confidence", 0))
    label = _NON_ALNUM.sub("_", (top.get("techniqueName") or "").upper()).strip("_")
    return label or "UNCLASSIFIED"


def _extract_platform(raw_alert: dict) -> str | None:
    """
    Best-effort only — the raw SIEM payload has no normalized platform
    field (see AgentState.severity's own comment on this exact problem for
    severity). Checks the handful of shapes real adapters in this codebase
    produce (Wazuh's agent.os.platform, a generic top-level "platform", a
    generic host.os.name) and returns None rather than guessing if none of
    them are present — a missing platform must never block retrieval, it
    just means the platform filter/signal goes unused for this alert.
    """
    if not isinstance(raw_alert, dict):
        return None

    agent = raw_alert.get("agent")
    if isinstance(agent, dict):
        os_info = agent.get("os")
        if isinstance(os_info, dict) and isinstance(os_info.get("platform"), str) and os_info["platform"].strip():
            return os_info["platform"].strip()

    top_level = raw_alert.get("platform")
    if isinstance(top_level, str) and top_level.strip():
        return top_level.strip()

    host = raw_alert.get("host")
    if isinstance(host, dict):
        os_info = host.get("os")
        if isinstance(os_info, dict) and isinstance(os_info.get("name"), str) and os_info["name"].strip():
            return os_info["name"].strip()

    return None


# Best-effort decoder-name -> service label, for the small set of decoders
# a real UnifiedAlert/Wazuh alert commonly carries. Deliberately narrow —
# an unrecognized decoder name contributes no service signal rather than a
# guessed one. Values match the controlled, human-readable form knowledge
# authors already use in tags (see credential-access-incident-response.md's
# own `tags: [..., authentication, ...]` convention) — uppercase protocol/
# service acronym, consistent with the task's own "SSH" example.
_SERVICE_FROM_DECODER_NAME: dict[str, str] = {
    "sshd": "SSH",
    "ssh": "SSH",
    "rdp": "RDP",
    "smb": "SMB",
    "win_rdp": "RDP",
    "web-accesslog": "HTTP",
    "apache": "HTTP",
    "nginx": "HTTP",
    "ftpd": "FTP",
    "vsftpd": "FTP",
}


def _extract_service(raw_alert: dict) -> str | None:
    """
    Real, structural extraction only — never inferred from free text. Reads
    UnifiedAlert's own `decoder.name` field (see apps/backend's
    WazuhAlertNormalizer — a Wazuh alert always carries this for a matched
    event, e.g. "sshd" for the Golden E2E SSH brute-force scenario) through
    the small, explicit mapping above. Returns None — never a guess — for a
    decoder this mapping doesn't recognize, or a non-Wazuh source with no
    `decoder` field at all.
    """
    if not isinstance(raw_alert, dict):
        return None
    decoder = raw_alert.get("decoder")
    name = decoder.get("name") if isinstance(decoder, dict) else None
    if not isinstance(name, str) or not name.strip():
        return None
    return _SERVICE_FROM_DECODER_NAME.get(name.strip().lower())


@dataclass
class InvestigationContext:
    """
    Broader-than-RagQueryInput working shape for the Phase D pipeline
    (query construction, re-ranking signals, grounded-context building, and
    recommendation building all read from this one object) — see
    extract_investigation_context() for exactly how much of it is
    derivable from AgentState at RagAgent's point in the graph
    (threat_intel -> mitre -> rag -> llm_analyst -> ... ), and why some fields
    (incidentRisk, decisionReliability) intentionally read from an
    upstream/legacy signal or stay unset rather than a field that hasn't
    been computed yet at this point in the run.
    """

    alertId: str = ""
    alertClassification: str = "UNCLASSIFIED"
    # VIGIX has no AI severity: incidentRisk reads the backend's own pre-computed
    # alert severity (AgentState.severity, see its own docstring), the one
    # risk-flavored signal that genuinely IS available this early.
    incidentRisk: str | None = None
    iocs: list[str] = field(default_factory=list)
    behaviors: list[str] = field(default_factory=list)
    mitreTechniques: list[MitreTechniqueRef] = field(default_factory=list)
    assetContext: dict = field(default_factory=dict)
    platform: str | None = None
    # Explainable Retrieval task — best-effort service label (see
    # _extract_service above), same "structural fact or None" contract as
    # `platform`.
    service: str | None = None
    scenario: str | None = None
    evidence: list[dict] = field(default_factory=list)
    # DecisionAgent (which computes this) also runs after rag — always
    # None on the normal path today; kept as a real field (rather than
    # omitted) so the shape is forward-compatible if a future retry loop
    # ever re-runs RagAgent after a decision exists.
    decisionReliability: float | None = None
    # Explainable Retrieval task — the pipeline's own real position in the
    # incident lifecycle at the moment RagAgent runs. Always "INVESTIGATION"
    # today: decision/approval/execution (the only events that could move
    # an incident into CONTAINMENT/ERADICATION/RECOVERY) all happen strictly
    # AFTER rag in both build_graph() and build_analysis_graph() (see
    # build_graph.py's fixed node order) — no state key exists yet that
    # would let a later phase be observed from within a single graph run.
    # This is a real fact about where this pipeline stands today, not a
    # fabricated default; a genuinely later phase (e.g. RagAgent invoked
    # again after containment actions were already taken) would need
    # incident-lifecycle state threaded into AgentState first — see this
    # task's own report for this limitation.
    responsePhase: str = "INVESTIGATION"


def extract_investigation_context(state) -> InvestigationContext:  # state: AgentState
    """
    Best-effort extraction from whatever AgentState already holds — mirrors
    query_builder.extract_query_input's own degrade-gracefully contract
    (state.get with defaults throughout, never raises on a partial/empty
    state). Prefers the structured, evidence-grounded
    mitre_mapping_report/threat_intel_report shapes when present, falling
    back to the legacy flat mitre_techniques/iocs shapes otherwise (both
    are always present together in a normal run — see graph/state.py — the
    fallback exists mainly so a unit test constructing a partial state
    still gets a sensible InvestigationContext).
    """
    mitre_report = state.get("mitre_mapping_report") or {}
    reported_techniques = mitre_report.get("techniques") or []

    mitre_refs = [
        MitreTechniqueRef(technique_id=t["techniqueId"], technique_name=t.get("techniqueName", ""))
        for t in reported_techniques
        if t.get("techniqueId")
    ]
    if not mitre_refs:
        mitre_refs = [
            MitreTechniqueRef(technique_id=m["technique_id"], technique_name=m.get("name", ""))
            for m in state.get("mitre_techniques", [])
            if m.get("technique_id")
        ]

    behaviors: list[str] = []
    seen_behaviors: set[str] = set()
    for technique in reported_techniques:
        name = technique.get("techniqueName")
        key = (name or "").strip().lower()
        if name and key not in seen_behaviors:
            seen_behaviors.add(key)
            behaviors.append(name)

    evidence: list[dict] = []
    for technique in reported_techniques:
        evidence.extend(technique.get("evidence") or [])

    malware_family: str | None = None
    categories: list[str] = []
    for ioc in state.get("iocs", []):
        raw_response = ioc.get("raw_response") or {}
        for provider_result in raw_response.values():
            if not isinstance(provider_result, dict):
                continue
            if not malware_family and provider_result.get("malwareFamily"):
                malware_family = provider_result["malwareFamily"]
            categories.extend(provider_result.get("categories") or [])

    # scenario is the one term RagQueryConstructor/reranker use to narrow
    # toward a specific attack scenario rather than a bare technique ID —
    # malware family (most specific, e.g. "LockBit") wins over a bare
    # threat category (e.g. "ransomware") when both are present, matching
    # query_builder.build_semantic_query's own incident_type-before-
    # threat_categories priority ordering.
    # RAG Transparency/Ranking task: fall back to a MITRE-technique-derived
    # scenario only when threat intel gave us nothing more specific — the
    # provider's own malware-family/category tag stays authoritative when
    # present (it's a more specific, externally-corroborated signal than a
    # technique-to-scenario guess).
    scenario = malware_family or (categories[0] if categories else None) or _scenario_from_mitre(mitre_refs)

    ioc_values = [ioc.get("ioc_value") for ioc in state.get("iocs", []) if ioc.get("ioc_value")]

    asset_context = {
        "assetId": state.get("asset_id"),
        "assetCriticality": state.get("asset_criticality"),
        "businessPolicyTags": state.get("business_policy_tags", []),
        "organizationRegulated": state.get("organization_regulated"),
    }

    return InvestigationContext(
        alertId=state.get("alert_id", ""),
        alertClassification=_classify_from_mitre_report(mitre_report),
        incidentRisk=state.get("severity"),
        iocs=ioc_values,
        behaviors=behaviors,
        mitreTechniques=mitre_refs,
        assetContext=asset_context,
        platform=_extract_platform(state.get("raw_alert") or {}),
        service=_extract_service(state.get("raw_alert") or {}),
        scenario=scenario,
        evidence=evidence,
        decisionReliability=None,
    )


@dataclass
class RecommendedAction:
    """
    Spec step 7's exact output contract for one deterministically-derived
    recommended action. `requiresApproval` is computed exclusively by
    recommendation_builder.py's `_requires_approval()` — a single source of
    truth so no other code path can ever construct one of these with
    requiresApproval=False for a CONTAINMENT/ERADICATION category (the
    platform's non-negotiable "RAG only ever recommends, never executes"
    rule — see recommendation_builder.py's module docstring).
    """

    action: str
    category: str
    reason: str
    evidence: list[dict]
    sourcePlaybook: str
    mitreTechnique: str | None
    priority: int
    requiresApproval: bool
    confidence: float
    # Explainable Retrieval task — the exact chunk this recommendation was
    # derived from (`${documentId}:${chunkIndex}`, already unique/stable —
    # see apps/backend's DocumentChunk.chunkId), for provenance/audit.
    chunkId: str | None = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "category": self.category,
            "reason": self.reason,
            "evidence": self.evidence,
            "sourcePlaybook": self.sourcePlaybook,
            "mitreTechnique": self.mitreTechnique,
            "priority": self.priority,
            "requiresApproval": self.requiresApproval,
            "confidence": self.confidence,
            "chunkId": self.chunkId,
        }


@dataclass
class KnowledgeReference:
    """One re-ranked KNOWLEDGE chunk, trimmed to what a consumer of the final output contract needs — never a raw dataclass, always to_dict()'d before it reaches AgentState.

    Explainable Retrieval task — chunkId/sourceRepository/sourcePath/
    rerankBreakdown added for full provenance/explainability (section 14):
    every value here is copied straight from the real candidate dict
    VectorSearchClient already returned (see grounded_context_builder.py's
    construction site) — never recomputed or guessed.
    """

    documentId: str
    title: str
    source: str
    sourceProvider: str | None
    score: float
    excerpt: str
    documentReference: str = ""
    chunkId: str | None = None
    sourceRepository: str | None = None
    sourcePath: str | None = None
    # Full per-signal score breakdown from reranker.py — vectorSimilarity,
    # mitreMatch, incidentTypeMatch, platformMatch, responsePhaseMatch, etc.
    # "Why was this retrieved" made concrete, not just the final `score`.
    rerankBreakdown: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "documentId": self.documentId,
            "title": self.title,
            "source": self.source,
            "sourceProvider": self.sourceProvider,
            "score": self.score,
            "excerpt": self.excerpt,
            "documentReference": self.documentReference,
            "chunkId": self.chunkId,
            "sourceRepository": self.sourceRepository,
            "sourcePath": self.sourcePath,
            "rerankBreakdown": self.rerankBreakdown,
        }


@dataclass
class PlaybookReference:
    """One re-ranked PLAYBOOK chunk. `phase` is copied straight from the backend's chunk metadata (detection|triage|containment|eradication|recovery|postIncident, or None for an overview/additional-guidance chunk) — never inferred here.

    Explainable Retrieval task — same provenance additions as
    KnowledgeReference above, plus `responsePhase`: `phase` mapped through
    the controlled ResponsePhase vocabulary (contracts/response_phase.py),
    None when `phase` doesn't map to one of the five controlled values.
    """

    documentId: str
    title: str
    sourceProvider: str | None
    scenario: str | None
    phase: str | None
    score: float
    excerpt: str
    documentReference: str = ""
    chunkId: str | None = None
    sourceRepository: str | None = None
    sourcePath: str | None = None
    responsePhase: str | None = None
    rerankBreakdown: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "documentId": self.documentId,
            "title": self.title,
            "sourceProvider": self.sourceProvider,
            "scenario": self.scenario,
            "phase": self.phase,
            "score": self.score,
            "excerpt": self.excerpt,
            "documentReference": self.documentReference,
            "chunkId": self.chunkId,
            "sourceRepository": self.sourceRepository,
            "sourcePath": self.sourcePath,
            "responsePhase": self.responsePhase,
            "rerankBreakdown": self.rerankBreakdown,
        }
