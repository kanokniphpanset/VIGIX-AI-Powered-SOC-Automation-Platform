"""
BehaviorExtractor — turns a raw alert (+ threat intel) into a list of
ObservedSignal objects: named behavior categories, each carrying the actual
Evidence that justifies it. No signal is ever produced without at least one
piece of concrete evidence — an empty match means the category simply
doesn't fire, never a placeholder/guessed signal.

Threat intel is used only as *corroborating* evidence attached to a signal
that already fired on its own — never as the sole trigger for a category.
This is the direct enforcement of spec section 4: "IOC reputation alone is
not sufficient evidence for arbitrary MITRE technique assignment." A
malicious IP mentioned in an alert with no matching behavioral keyword
produces zero signals, by design (see test_no_iocs_alone.py-equivalent
coverage in test_behavior_extractor.py).

Detection is regex/keyword matching against the flattened alert text (the
same `alert_text` every other agent in this pipeline already receives —
see graph/state.py) plus a best-effort scan of structured raw_alert fields
where SIEMs commonly carry a numeric signal (failed attempt counts, event
IDs). Deterministic, no LLM involved in signal extraction itself (spec
section 4: IOC type detection and — by the same principle — behavior
detection here are not something an LLM decides).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import behavior_signals as sig
from .types import Evidence

_FAILED_AUTH_COUNT_PATTERN = re.compile(r"(\d+)\s+failed\s+(?:password|login|authentication)", re.IGNORECASE)


@dataclass
class ObservedSignal:
    category: str
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def strength(self) -> str:
        """More independent corroborating evidence -> stronger signal — same
        principle threat_intel_agent/scoring.py already uses for provider
        agreement (Phase 2), applied here to evidence-item count."""
        count = len(self.evidence)
        if count >= 3:
            return "HIGH"
        if count >= 2:
            return "MEDIUM"
        return "LOW"


def _contains_any(text: str, keywords: tuple[str, ...]) -> str | None:
    for kw in keywords:
        if kw in text:
            return kw
    return None


def _threat_intel_malicious_iocs(threat_intel_report: dict | None) -> list[dict]:
    if not threat_intel_report:
        return []
    return [i for i in threat_intel_report.get("indicators", []) if i.get("verdict") == "MALICIOUS"]


class BehaviorExtractor:
    def extract(self, alert_text: str, raw_alert: dict | None, threat_intel_report: dict | None = None) -> list[ObservedSignal]:
        text = (alert_text or "").lower()
        raw_alert = raw_alert if isinstance(raw_alert, dict) else {}
        signals: list[ObservedSignal] = []

        for extractor in (
            self._brute_force,
            self._credential_dumping,
            self._encoded_powershell,
            self._powershell_cradle,
            self._persistence_schtasks,
            self._persistence_registry,
            self._lateral_movement,
            self._discovery,
            self._command_and_control,
            self._exfiltration_archive,
            self._exfiltration_transfer,
            self._impact_shadow_copy,
            self._impact_ransom_extension,
        ):
            result = extractor(text, raw_alert, threat_intel_report)
            if result is not None:
                signals.append(result)

        signals.extend(self._siem_native_mitre(raw_alert))

        return signals

    def _siem_native_mitre(self, raw_alert: dict) -> list[ObservedSignal]:
        """Some SIEMs (Wazuh's own ruleset is the real, verified example —
        e.g. rule 5712 "sshd: brute force..." carries
        `rule.mitre.id: ["T1110"]` on the raw alert itself) already tag a
        rule with a MITRE technique ID as part of their own curated rule
        metadata — a fact, not an inference. Previously this agent only
        ever *guessed* techniques from regex/keyword matches against free
        text, which real Wazuh SSH brute-force alerts don't satisfy (their
        rendered description is "sshd: brute force trying to get access to
        the system. Non existent user." — no "N failed password" phrase,
        no Windows event ID), so a real, correctly-tagged brute-force alert
        produced NO_SUPPORTED_MAPPING despite Wazuh itself already knowing
        the technique. This reads that native tag as its own evidence
        source ("siem_native") — TechniqueMapper still validates every ID
        against the real catalog before it can ever reach the output, so a
        SIEM asserting a nonexistent/renamed ID is dropped exactly like any
        other candidate, never trusted blindly."""
        rule = raw_alert.get("rule")
        if not isinstance(rule, dict):
            return []
        mitre = rule.get("mitre")
        if not isinstance(mitre, dict):
            return []
        technique_ids = mitre.get("id")
        if not isinstance(technique_ids, list):
            return []

        signals: list[ObservedSignal] = []
        for technique_id in technique_ids:
            if not isinstance(technique_id, str) or not technique_id:
                continue
            evidence = [Evidence(source="siem_native", field="mitreTechniqueId", value=technique_id)]
            rule_id = rule.get("id")
            if rule_id:
                evidence.append(Evidence(source="siem_native", field="ruleId", value=rule_id))
            signals.append(ObservedSignal(f"NATIVE_MITRE:{technique_id}", evidence))
        return signals

    def _brute_force(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        evidence: list[Evidence] = []
        match = _FAILED_AUTH_COUNT_PATTERN.search(text)
        if match:
            count = int(match.group(1))
            if count >= sig.BRUTE_FORCE_MIN_FAILED_ATTEMPTS:
                evidence.append(Evidence(source="alert", field="failedAttempts", value=count))
        event_id = _contains_any(text, sig.BRUTE_FORCE_FAILED_LOGON_EVENT_IDS)
        if event_id:
            evidence.append(Evidence(source="alert", field="windowsEventId", value=event_id))
        return ObservedSignal("BRUTE_FORCE", evidence) if evidence else None

    def _credential_dumping(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        evidence: list[Evidence] = []
        proc = _contains_any(text, sig.CREDENTIAL_DUMPING_PROCESS_NAMES)
        if proc:
            evidence.append(Evidence(source="alert", field="processName", value=proc))
        target = _contains_any(text, sig.CREDENTIAL_DUMPING_TARGET_PROCESSES)
        if target:
            evidence.append(Evidence(source="alert", field="targetProcess", value=target))
        keyword = _contains_any(text, sig.CREDENTIAL_DUMPING_KEYWORDS)
        if keyword:
            evidence.append(Evidence(source="alert", field="commandLine", value=keyword))
        return ObservedSignal("CREDENTIAL_DUMPING", evidence) if evidence else None

    def _encoded_powershell(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        match = sig.ENCODED_POWERSHELL_PATTERN.search(text)
        if not match:
            return None
        return ObservedSignal("ENCODED_POWERSHELL", [Evidence(source="alert", field="commandLine", value=match.group(0)[:120])])

    def _powershell_cradle(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        proc = _contains_any(text, sig.POWERSHELL_PROCESS_NAMES)
        cradle = sig.POWERSHELL_DOWNLOAD_CRADLE_PATTERN.search(text)
        if not (proc and cradle):
            return None
        return ObservedSignal(
            "POWERSHELL_CRADLE",
            [
                Evidence(source="alert", field="processName", value=proc),
                Evidence(source="alert", field="commandLine", value=cradle.group(0)),
            ],
        )

    def _persistence_schtasks(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        keyword = _contains_any(text, sig.PERSISTENCE_KEYWORDS)
        if not keyword:
            return None
        return ObservedSignal("PERSISTENCE_SCHTASKS", [Evidence(source="alert", field="commandLine", value=keyword)])

    def _persistence_registry(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        for pattern in sig.PERSISTENCE_REGISTRY_PATTERNS:
            match = pattern.search(text)
            if match:
                return ObservedSignal("PERSISTENCE_REGISTRY", [Evidence(source="alert", field="registryKeyPath", value=match.group(0))])
        return None

    def _lateral_movement(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        evidence: list[Evidence] = []
        proc = _contains_any(text, sig.LATERAL_MOVEMENT_PROCESS_NAMES)
        if proc:
            evidence.append(Evidence(source="alert", field="processName", value=proc))
        keyword = _contains_any(text, sig.LATERAL_MOVEMENT_KEYWORDS)
        if keyword:
            evidence.append(Evidence(source="alert", field="commandLine", value=keyword))
        return ObservedSignal("LATERAL_MOVEMENT", evidence) if evidence else None

    def _discovery(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        evidence: list[Evidence] = []
        proc = _contains_any(text, sig.DISCOVERY_PROCESS_NAMES)
        if proc:
            evidence.append(Evidence(source="alert", field="processName", value=proc))
        acct_kw = _contains_any(text, sig.DISCOVERY_ACCOUNT_KEYWORDS)
        if acct_kw:
            evidence.append(Evidence(source="alert", field="commandLine", value=acct_kw))
        sys_kw = _contains_any(text, sig.DISCOVERY_SYSTEM_KEYWORDS)
        if sys_kw:
            evidence.append(Evidence(source="alert", field="commandLine", value=sys_kw))
        return ObservedSignal("DISCOVERY", evidence) if evidence else None

    def _command_and_control(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        # Behavioral trigger required — a malicious IOC alone never fires this.
        evidence: list[Evidence] = []
        keyword = _contains_any(text, sig.C2_KEYWORDS)
        if keyword:
            evidence.append(Evidence(source="alert", field="commandLine", value=keyword))
        for port in sig.C2_SUSPICIOUS_PORTS:
            if f":{port}" in text or f"port {port}" in text:
                evidence.append(Evidence(source="alert", field="port", value=port))
                break
        if not evidence:
            return None
        # Threat intel only ever *corroborates* an already-fired signal.
        for ioc in _threat_intel_malicious_iocs(threat_intel_report):
            evidence.append(Evidence(source="threat_intel", field="ioc", value=ioc.get("ioc")))
            break
        return ObservedSignal("COMMAND_AND_CONTROL", evidence)

    def _exfiltration_archive(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        keyword = _contains_any(text, sig.EXFILTRATION_ARCHIVE_KEYWORDS)
        if not keyword:
            return None
        return ObservedSignal("EXFILTRATION_ARCHIVE", [Evidence(source="alert", field="commandLine", value=keyword)])

    def _exfiltration_transfer(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        evidence: list[Evidence] = []
        keyword = _contains_any(text, sig.EXFILTRATION_TRANSFER_KEYWORDS)
        if keyword:
            evidence.append(Evidence(source="alert", field="commandLine", value=keyword))
        domain = _contains_any(text, sig.EXFILTRATION_KNOWN_SERVICE_DOMAINS)
        if domain:
            evidence.append(Evidence(source="alert", field="destinationDomain", value=domain))
        return ObservedSignal("EXFILTRATION_TRANSFER", evidence) if evidence else None

    def _impact_shadow_copy(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        keyword = _contains_any(text, sig.IMPACT_SHADOW_COPY_KEYWORDS)
        if not keyword:
            return None
        return ObservedSignal("IMPACT_SHADOW_COPY", [Evidence(source="alert", field="commandLine", value=keyword)])

    def _impact_ransom_extension(self, text, raw_alert, threat_intel_report) -> ObservedSignal | None:
        ext = _contains_any(text, sig.IMPACT_RANSOM_FILE_EXTENSIONS)
        if not ext:
            return None
        return ObservedSignal("IMPACT_RANSOM_EXTENSION", [Evidence(source="alert", field="filePath", value=ext)])
