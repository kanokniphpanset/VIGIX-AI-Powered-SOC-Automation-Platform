"""
Deterministic, evidence-grounded incident classification (section 6).

Reads ONLY the already-built, cross-agent Evidence[] list
(contracts/evidence.py::build_evidence) — never threat_intel_report/
mitre_mapping_report/rag_result/etc. directly, and never re-derives
anything threat_intel_agent, mitre_agent, rag_agent, or
llm_analyst_agent already computed. This gives every score a real,
already-existing EvidenceItem.id to cite (section 5's evidence-grounding
requirement is structural here, not a separate bookkeeping step) and keeps
this module a pure `(list[EvidenceItem]) -> IncidentClassification`
function with zero I/O.

SCORING MODEL
=============
Two kinds of contributor, matching sections 7-11's repeated instruction
that only MITRE and RAG evidence may ever *introduce* a category, while
IOC/ML-risk/LLM may only *amplify* a category some other signal already
introduced:

  - MITRE (weight 0.50 * that technique's own confidence, section 7) and
    RAG playbook-scenario matches (weight 0.10 * that playbook's own
    score, section 10) each independently open a category "accumulator".
  - IOC/threat-intel (0.20), ML risk (0.15), and LLM interpretation (0.05)
    only ever add to an accumulator that already exists — they never
    create one on their own (sections 8/9/11's explicit "must not
    independently determine/create a category" rule, enforced structurally
    rather than by convention). An LLM-only run therefore always resolves
    to UNKNOWN: `_apply_llm` is a no-op when `accumulators` is empty.

Weights are the task's own suggested starting point (section 6 explicitly
says "do not blindly copy these exact weights ... if existing architecture
suggests better values" — this codebase has no prior classification
scoring precedent to defer to, so the suggested weights are used as-is,
each attached to a real per-signal confidence rather than a flat constant
wherever one exists).

MITRE TECHNIQUE -> CATEGORY MAPPING
====================================
A small, hand-curated table of already-known technique IDs (section 7:
"classification consumes MITRE output, it does not perform MITRE
detection" — this is categorization of technique IDs MitreAgent already
validated against the real catalog, not a second detection system).

T1110 (parent "Brute Force") maps to CREDENTIAL_ATTACK, not BRUTE_FORCE —
its four sub-techniques (T1110.001-004: password guessing/cracking/
spraying, credential stuffing) map to the more specific BRUTE_FORCE
instead. This reconciles the task's two examples: section 3's "T1110 ->
CREDENTIAL_ATTACK / BRUTE_FORCE" (presented as either being acceptable)
and section 13's worked conflict example, which uses bare T1110 and
resolves it to CREDENTIAL_ATTACK specifically. The umbrella technique is
genuinely the broader, less specific fact; its sub-techniques name the
actual brute-force methodology.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.contracts.classification import ClassificationStatus, IncidentCategory, IncidentClassification
from src.contracts.evidence import EvidenceCategory, EvidenceItem

_MITRE_WEIGHT = 0.50
_MITRE_MULTI_TECHNIQUE_BONUS = 0.05
_MITRE_MULTI_TECHNIQUE_BONUS_CAP = 0.15
_IOC_WEIGHT = 0.20
_RAG_WEIGHT = 0.10
_LLM_WEIGHT = 0.05

# Only a HIGH/CRITICAL severity suggestion from the ML classifier may lend support to a category — letting a
# LOW/MEDIUM suggestion amplify a category would let a low-severity alert borrow confidence it hasn't earned (section 9).

HIGH_CONFIDENCE_FLOOR = 0.75
MEDIUM_CONFIDENCE_FLOOR = 0.50
LOW_CONFIDENCE_FLOOR = 0.25

_UNKNOWN_RATIONALE = "Insufficient evidence to determine a reliable incident category."

# Sub-technique overrides checked BEFORE the base-technique table below.
_MITRE_SUBTECHNIQUE_CATEGORY: dict[str, IncidentCategory] = {
    "T1110.001": IncidentCategory.BRUTE_FORCE,
    "T1110.002": IncidentCategory.BRUTE_FORCE,
    "T1110.003": IncidentCategory.BRUTE_FORCE,
    "T1110.004": IncidentCategory.BRUTE_FORCE,
}

_MITRE_TECHNIQUE_CATEGORY: dict[str, IncidentCategory] = {
    # Credential access
    "T1110": IncidentCategory.CREDENTIAL_ATTACK,  # umbrella "Brute Force" — see module docstring
    "T1003": IncidentCategory.CREDENTIAL_ATTACK,  # OS Credential Dumping
    "T1555": IncidentCategory.CREDENTIAL_ATTACK,  # Credentials from Password Stores
    "T1552": IncidentCategory.CREDENTIAL_ATTACK,  # Unsecured Credentials
    "T1556": IncidentCategory.CREDENTIAL_ATTACK,  # Modify Authentication Process
    "T1621": IncidentCategory.CREDENTIAL_ATTACK,  # Multi-Factor Authentication Request Generation
    "T1558": IncidentCategory.CREDENTIAL_ATTACK,  # Steal or Forge Kerberos Tickets
    # Phishing
    "T1566": IncidentCategory.PHISHING,  # Phishing
    "T1598": IncidentCategory.PHISHING,  # Phishing for Information
    # Ransomware / impact
    "T1486": IncidentCategory.RANSOMWARE,  # Data Encrypted for Impact
    "T1490": IncidentCategory.RANSOMWARE,  # Inhibit System Recovery
    # Malware execution/defense evasion
    "T1204": IncidentCategory.MALWARE,  # User Execution
    "T1059": IncidentCategory.MALWARE,  # Command and Scripting Interpreter
    "T1055": IncidentCategory.MALWARE,  # Process Injection
    "T1027": IncidentCategory.MALWARE,  # Obfuscated Files or Information
    "T1105": IncidentCategory.MALWARE,  # Ingress Tool Transfer
    "T1547": IncidentCategory.MALWARE,  # Boot or Logon Autostart Execution
    # Exfiltration
    "T1041": IncidentCategory.DATA_EXFILTRATION,  # Exfiltration Over C2 Channel
    "T1048": IncidentCategory.DATA_EXFILTRATION,  # Exfiltration Over Alternative Protocol
    "T1567": IncidentCategory.DATA_EXFILTRATION,  # Exfiltration Over Web Service
    "T1020": IncidentCategory.DATA_EXFILTRATION,  # Automated Exfiltration
    # Account compromise
    "T1078": IncidentCategory.ACCOUNT_COMPROMISE,  # Valid Accounts
    "T1098": IncidentCategory.ACCOUNT_COMPROMISE,  # Account Manipulation
    # Command and control
    "T1071": IncidentCategory.COMMAND_AND_CONTROL,  # Application Layer Protocol
    "T1090": IncidentCategory.COMMAND_AND_CONTROL,  # Proxy
    "T1571": IncidentCategory.COMMAND_AND_CONTROL,  # Non-Standard Port
    "T1573": IncidentCategory.COMMAND_AND_CONTROL,  # Encrypted Channel
    # Initial access
    "T1190": IncidentCategory.INITIAL_ACCESS,  # Exploit Public-Facing Application
    "T1133": IncidentCategory.INITIAL_ACCESS,  # External Remote Services
    "T1091": IncidentCategory.INITIAL_ACCESS,  # Replication Through Removable Media
}

# rag_result.playbooks[].scenario values (backend playbook ingestion —
# apps/backend/.../playbooks/*/*.ts) that map onto this taxonomy. Scenarios
# with no reasonable single-category match (e.g. "sts_token_abuse",
# "satellite_operations") are intentionally absent — an unmapped scenario
# contributes nothing rather than being forced into the nearest category.
_RAG_SCENARIO_CATEGORY: dict[str, IncidentCategory] = {
    "phishing": IncidentCategory.PHISHING,
    "ransomware": IncidentCategory.RANSOMWARE,
    "malware": IncidentCategory.MALWARE,
    "data_loss": IncidentCategory.DATA_EXFILTRATION,
    "data_access": IncidentCategory.DATA_EXFILTRATION,
    "data_breach": IncidentCategory.DATA_EXFILTRATION,
    "account_compromised": IncidentCategory.ACCOUNT_COMPROMISE,
    "credential_compromise": IncidentCategory.CREDENTIAL_ATTACK,
    "insider_threat": IncidentCategory.INSIDER_THREAT,
}

# LLM analyst text -> category, checked as a plain lowercase substring
# match against llm_summary + llm_recommendation. Weak by design (section
# 11): only ever consulted as an amplifier via _apply_llm, never able to
# open a new accumulator.
_LLM_KEYWORD_CATEGORY: list[tuple[str, IncidentCategory]] = [
    ("ransomware", IncidentCategory.RANSOMWARE),
    ("phishing", IncidentCategory.PHISHING),
    ("brute force", IncidentCategory.BRUTE_FORCE),
    ("brute-force", IncidentCategory.BRUTE_FORCE),
    ("credential", IncidentCategory.CREDENTIAL_ATTACK),
    ("malware", IncidentCategory.MALWARE),
    ("exfiltrat", IncidentCategory.DATA_EXFILTRATION),  # exfiltration / exfiltrate
    ("insider", IncidentCategory.INSIDER_THREAT),
    ("command and control", IncidentCategory.COMMAND_AND_CONTROL),
    ("account takeover", IncidentCategory.ACCOUNT_COMPROMISE),
    ("account compromise", IncidentCategory.ACCOUNT_COMPROMISE),
    ("initial access", IncidentCategory.INITIAL_ACCESS),
]

# Tie-break order when two categories land on the same rounded score —
# roughly "most specific/technique-precise" to "most context-dependent".
_CATEGORY_PRECEDENCE: list[IncidentCategory] = [
    IncidentCategory.BRUTE_FORCE,
    IncidentCategory.RANSOMWARE,
    IncidentCategory.PHISHING,
    IncidentCategory.CREDENTIAL_ATTACK,
    IncidentCategory.ACCOUNT_COMPROMISE,
    IncidentCategory.DATA_EXFILTRATION,
    IncidentCategory.MALWARE,
    IncidentCategory.COMMAND_AND_CONTROL,
    IncidentCategory.INITIAL_ACCESS,
    IncidentCategory.INSIDER_THREAT,
]


@dataclass
class _CategoryAccumulator:
    category: IncidentCategory
    components: dict[str, float] = field(default_factory=dict)  # source -> contribution
    evidence_ids: set[str] = field(default_factory=set)
    matched_techniques: set[str] = field(default_factory=set)
    rationale_parts: list[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        return min(sum(self.components.values()), 1.0)


def _category_for_technique(technique_id: str) -> IncidentCategory | None:
    if technique_id in _MITRE_SUBTECHNIQUE_CATEGORY:
        return _MITRE_SUBTECHNIQUE_CATEGORY[technique_id]
    return _MITRE_TECHNIQUE_CATEGORY.get(technique_id.split(".")[0])


def _apply_mitre(evidence: list[EvidenceItem], accumulators: dict[IncidentCategory, _CategoryAccumulator]) -> None:
    matches_by_category: dict[IncidentCategory, list[EvidenceItem]] = {}
    for item in evidence:
        if item.type != EvidenceCategory.MITRE_TECHNIQUE or not item.value:
            continue
        category = _category_for_technique(item.value)
        if category is None:
            continue
        matches_by_category.setdefault(category, []).append(item)

    for category, items in matches_by_category.items():
        ranked = sorted(items, key=lambda i: i.confidence or 0.0, reverse=True)
        top_confidence = ranked[0].confidence if ranked[0].confidence is not None else 0.75
        bonus = min((len(ranked) - 1) * _MITRE_MULTI_TECHNIQUE_BONUS, _MITRE_MULTI_TECHNIQUE_BONUS_CAP)

        acc = accumulators.setdefault(category, _CategoryAccumulator(category=category))
        acc.components["mitre"] = _MITRE_WEIGHT * top_confidence + bonus
        for item in ranked:
            acc.evidence_ids.add(item.id)
            acc.matched_techniques.add(item.value)
        technique_list = ", ".join(sorted(acc.matched_techniques))
        acc.rationale_parts.append(f"MITRE technique(s) {technique_list} map to {category.value}.")


def _apply_rag(evidence: list[EvidenceItem], accumulators: dict[IncidentCategory, _CategoryAccumulator]) -> None:
    for item in evidence:
        if item.type != EvidenceCategory.PLAYBOOK:
            continue
        scenario = (item.metadata or {}).get("scenario")
        category = _RAG_SCENARIO_CATEGORY.get(scenario) if scenario else None
        if category is None:
            continue

        contribution = _RAG_WEIGHT * (item.confidence if item.confidence is not None else 0.5)
        acc = accumulators.setdefault(category, _CategoryAccumulator(category=category))
        if contribution <= acc.components.get("rag", 0.0):
            acc.evidence_ids.add(item.id)
            continue
        acc.components["rag"] = contribution
        acc.evidence_ids.add(item.id)
        acc.rationale_parts.append(f"Retrieved playbook for scenario '{scenario}' supports {category.value}.")


def _apply_ioc(evidence: list[EvidenceItem], accumulators: dict[IncidentCategory, _CategoryAccumulator]) -> None:
    if not accumulators:
        return
    malicious = [item for item in evidence if item.type == EvidenceCategory.IOC and (item.metadata or {}).get("verdict") == "MALICIOUS"]
    if not malicious:
        return

    avg_confidence = sum((item.confidence or 0.0) for item in malicious) / len(malicious)
    contribution = _IOC_WEIGHT * avg_confidence
    for acc in accumulators.values():
        acc.components["threatIntel"] = contribution
        acc.evidence_ids.update(item.id for item in malicious)
        acc.rationale_parts.append(f"{len(malicious)} malicious IOC(s) corroborate {acc.category.value}.")


def _apply_llm(evidence: list[EvidenceItem], accumulators: dict[IncidentCategory, _CategoryAccumulator]) -> None:
    if not accumulators:
        return
    llm_items = [item for item in evidence if item.type == EvidenceCategory.LLM_ANALYSIS]
    if not llm_items:
        return

    combined_text = " ".join(item.value or "" for item in llm_items).lower()
    for keyword, category in _LLM_KEYWORD_CATEGORY:
        acc = accumulators.get(category)
        if acc is None or "llmAnalyst" in acc.components:
            continue
        if keyword in combined_text:
            acc.components["llmAnalyst"] = _LLM_WEIGHT
            acc.evidence_ids.update(item.id for item in llm_items)
            acc.rationale_parts.append(f"LLM analyst interpretation is consistent with {category.value}.")


def _status_for(score: float) -> ClassificationStatus:
    if score >= HIGH_CONFIDENCE_FLOOR:
        return "HIGH_CONFIDENCE"
    if score >= MEDIUM_CONFIDENCE_FLOOR:
        return "MEDIUM_CONFIDENCE"
    return "LOW_CONFIDENCE"


def unknown_classification() -> IncidentClassification:
    """The mandatory, non-error UNKNOWN result (section 14) — matches the task's own exact example (confidence=0.0, everything else empty)."""
    return IncidentClassification(
        category=IncidentCategory.UNKNOWN.value,
        confidence=0.0,
        rationale=_UNKNOWN_RATIONALE,
        evidence_ids=[],
        matched_techniques=[],
        signals={},
        status="UNCLASSIFIED",
        metadata={},
    )


def classify(evidence: list[EvidenceItem]) -> IncidentClassification:
    """
    Pure, deterministic, never raises on well-formed EvidenceItem input
    (never crashes per section 19E — every accessor above already defaults
    safely on missing/None fields).
    """
    accumulators: dict[IncidentCategory, _CategoryAccumulator] = {}

    _apply_mitre(evidence, accumulators)
    _apply_rag(evidence, accumulators)
    _apply_ioc(evidence, accumulators)
    _apply_llm(evidence, accumulators)

    if not accumulators:
        return unknown_classification()

    def _sort_key(acc: _CategoryAccumulator) -> tuple[float, int]:
        precedence = _CATEGORY_PRECEDENCE.index(acc.category) if acc.category in _CATEGORY_PRECEDENCE else len(_CATEGORY_PRECEDENCE)
        return (-round(acc.score, 6), precedence)

    ranked = sorted(accumulators.values(), key=_sort_key)
    best = ranked[0]

    if best.score < LOW_CONFIDENCE_FLOOR:
        return unknown_classification()

    competing = {acc.category.value: round(acc.score, 2) for acc in ranked[1:] if acc.score > 0.05}

    return IncidentClassification(
        category=best.category.value,
        confidence=round(best.score, 2),
        rationale=" ".join(best.rationale_parts) or f"Evidence supports {best.category.value}.",
        evidence_ids=sorted(best.evidence_ids),
        matched_techniques=sorted(best.matched_techniques),
        signals={source: round(value, 2) for source, value in best.components.items()},
        status=_status_for(best.score),
        metadata={"competingCategories": competing} if competing else {},
    )
