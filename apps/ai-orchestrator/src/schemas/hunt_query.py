"""Hunt query data: the original investigation query, kept as the single source of truth so
verification re-runs the *same* query it was investigated with, never a new one derived from
a response plan.

Stored as a WAZUH_HUNT Evidence record (see src/schemas/evidence.py). This module is the one
place that knows the shape of `Evidence.data` for that type - services should go through
`HuntQueryData.from_evidence` rather than reading `evidence.data[...]` directly, so a future
change to the stored shape only touches this file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

AFFECTED_AGENTS = "AFFECTED_AGENTS"   # hunt is scoped to specific agents (host-specific incident)
ALL_AGENTS = "ALL_AGENTS"             # hunt covers every agent (environment-wide IOC sweep)


class HuntQueryDataError(ValueError):
    """Raised when an Evidence record claims type WAZUH_HUNT but its `data` is malformed."""


@dataclass
class HuntQueryData:
    query: str
    time_range: dict[str, str]                 # {"from": iso, "to": iso}
    scope: str = AFFECTED_AGENTS               # AFFECTED_AGENTS | ALL_AGENTS
    agents: list[str] = field(default_factory=list)  # ignored by rehunt_tool when scope == ALL_AGENTS
    ioc: Optional[str] = None

    @classmethod
    def from_evidence(cls, evidence: dict[str, Any]) -> "HuntQueryData":
        if evidence.get("type") != "WAZUH_HUNT":
            raise HuntQueryDataError(
                f"expected evidence type WAZUH_HUNT, got {evidence.get('type')!r}"
            )
        data = evidence.get("data") or {}
        query = data.get("query")
        time_range = data.get("time_range")
        if not query or not isinstance(time_range, dict):
            raise HuntQueryDataError(
                f"WAZUH_HUNT evidence {evidence.get('evidence_id')!r} is missing query/time_range"
            )
        scope = data.get("scope", AFFECTED_AGENTS)
        if scope not in (AFFECTED_AGENTS, ALL_AGENTS):
            raise HuntQueryDataError(f"unknown hunt scope: {scope!r}")
        return cls(
            query=query,
            time_range=time_range,
            scope=scope,
            agents=list(data.get("agents") or []),
            ioc=data.get("ioc"),
        )

    def agents_for_rehunt(self) -> Optional[list[str]]:
        """None means "query every agent" - what rehunt_tool expects for ALL_AGENTS scope."""
        return None if self.scope == ALL_AGENTS else (self.agents or None)
