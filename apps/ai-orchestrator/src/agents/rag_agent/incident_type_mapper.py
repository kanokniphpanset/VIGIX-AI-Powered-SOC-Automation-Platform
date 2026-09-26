"""
Deterministic MITRE technique -> controlled incident_type mapping, scoped
specifically to RAG's retrieval-context signal (RagQueryInput.incident_type,
consumed by reranker.py's incident_type_match term) — NOT a replacement for
or a change to classification_agent/classification_rules.py's own (separate,
unrelated) incident-category scoring model.

Reuses the existing, real IncidentCategory enum (contracts/classification.py)
rather than inventing a parallel vocabulary — "BRUTE_FORCE"/"MALWARE"/
"RANSOMWARE" are exactly its own values.

Deliberately covers only the three Golden E2E-prioritized incident types
(BRUTE_FORCE, MALWARE, RANSOMWARE) — extensible by adding more entries to
_MITRE_TECHNIQUE_INCIDENT_TYPE, never by guessing an unmapped technique into
the nearest category. A technique with no entry here contributes no
incident_type signal (None), not a wrong one.

WHY THIS DIFFERS FROM classification_rules.py FOR BARE T1110:
classification_agent/classification_rules.py maps bare T1110 ("Brute
Force", the umbrella technique) to CREDENTIAL_ATTACK, reserving BRUTE_FORCE
for its sub-techniques only (T1110.001-004) — a deliberate governance/
decision-policy design choice documented in that module's own docstring.
This module serves a different purpose: matching a live alert's MITRE
technique against KNOWLEDGE/PLAYBOOK metadata that content authors tag
using the technique's own plain-English name ("Brute Force"). A real Wazuh
SSH brute-force alert (rule 5712) carries bare T1110 with native
rule.mitre.technique=["Brute Force"] — for retrieval purposes, mapping
that to BRUTE_FORCE is the factually correct, evidence-grounded choice
(it's literally the technique's own name), and this task's own worked
examples (SSH Brute Force -> incident_type=BRUTE_FORCE, MITRE=T1110)
confirm this is the intended behavior for retrieval. The two modules are
allowed to disagree on this one umbrella technique because they answer two
different questions ("what governance category is this" vs "what knowledge
is this about") — this is intentional, not a bug, and not something this
change alters classification_rules.py to "fix".
"""

from __future__ import annotations

from src.contracts.classification import IncidentCategory

from .types import MitreTechniqueRef

# Sub-technique overrides checked BEFORE the base-technique table below —
# same two-tier lookup structure as classification_rules.py's own table,
# independently maintained per this module's docstring.
_MITRE_SUBTECHNIQUE_INCIDENT_TYPE: dict[str, IncidentCategory] = {
    "T1110.001": IncidentCategory.BRUTE_FORCE,
    "T1110.002": IncidentCategory.BRUTE_FORCE,
    "T1110.003": IncidentCategory.BRUTE_FORCE,
    "T1110.004": IncidentCategory.BRUTE_FORCE,
}

_MITRE_TECHNIQUE_INCIDENT_TYPE: dict[str, IncidentCategory] = {
    # Brute Force — bare T1110 included (see module docstring for why this
    # intentionally differs from classification_rules.py's CREDENTIAL_ATTACK).
    "T1110": IncidentCategory.BRUTE_FORCE,
    # Malware — same technique set classification_rules.py's own
    # _MITRE_TECHNIQUE_CATEGORY already associates with MALWARE (no
    # conflict for this category; independently maintained per this
    # module's own docstring, not imported).
    "T1204": IncidentCategory.MALWARE,  # User Execution
    "T1059": IncidentCategory.MALWARE,  # Command and Scripting Interpreter
    "T1055": IncidentCategory.MALWARE,  # Process Injection
    "T1027": IncidentCategory.MALWARE,  # Obfuscated Files or Information
    "T1105": IncidentCategory.MALWARE,  # Ingress Tool Transfer
    "T1547": IncidentCategory.MALWARE,  # Boot or Logon Autostart Execution
    # Ransomware — same technique set classification_rules.py associates
    # with RANSOMWARE, plus T1489 (Service Stop), which the real, ingested
    # ransomware-incident-response.md playbook's own frontmatter already
    # lists (mitreTechniques: [T1486, T1490, T1489, ...]) — real evidence,
    # not invented.
    "T1486": IncidentCategory.RANSOMWARE,  # Data Encrypted for Impact
    "T1490": IncidentCategory.RANSOMWARE,  # Inhibit System Recovery
    "T1489": IncidentCategory.RANSOMWARE,  # Service Stop
}


def derive_incident_type(mitre_refs: list[MitreTechniqueRef]) -> str | None:
    """
    Highest-precedence match wins when multiple MITRE techniques are
    present: checked in the order given (mirrors how MitreAgent/
    InvestigationContext already orders mitreTechniques by confidence —
    see types.extract_investigation_context). Returns None (never a
    guess) when no technique in the list maps to one of the three
    prioritized incident types.
    """
    for ref in mitre_refs:
        if not ref.technique_id:
            continue
        if ref.technique_id in _MITRE_SUBTECHNIQUE_INCIDENT_TYPE:
            return _MITRE_SUBTECHNIQUE_INCIDENT_TYPE[ref.technique_id].value
        base_id = ref.technique_id.split(".")[0]
        category = _MITRE_TECHNIQUE_INCIDENT_TYPE.get(base_id)
        if category is not None:
            return category.value
    return None
