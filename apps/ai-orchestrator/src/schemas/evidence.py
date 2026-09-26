"""Evidence items. Agents may only cite evidence by `evidence_id`."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

WAZUH_EVENT = "WAZUH_EVENT"
WAZUH_ALERT = "WAZUH_ALERT"
THREAT_INTEL = "THREAT_INTEL"
IOC = "IOC"

# The original investigation/hunt query, kept so verification can re-run the *same* query later.
# `data` shape for this type is defined by HuntQueryData (see src/schemas/hunt_query.py):
#   {"query": str, "time_range": {"from": iso, "to": iso}, "scope": "AFFECTED_AGENTS" | "ALL_AGENTS",
#    "agents": [str, ...], "ioc": Optional[str]}
WAZUH_HUNT = "WAZUH_HUNT"

# Summary of a re-hunt run (before/after counts, new hosts). Created when verification finds
# NOT_RESOLVED, so the next plan cycle has fresh evidence to work from.
REHUNT_RESULT = "REHUNT_RESULT"


@dataclass
class Evidence:
    evidence_id: str          # e.g. "EV-001"
    incident_id: str
    type: str                 # WAZUH_EVENT | WAZUH_ALERT | THREAT_INTEL | IOC | WAZUH_HUNT | REHUNT_RESULT ...
    source: str                # "wazuh", "virustotal", ...
    timestamp: str
    data: dict[str, Any] = field(default_factory=dict)
