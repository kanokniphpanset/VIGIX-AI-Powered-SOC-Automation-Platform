"""MITRE ATT&CK lookup.

Maps a technique id (T1110) or a keyword to technique / tactic / mitigation / detection.
Prefer an offline ATT&CK STIX bundle: stable and needs no network.
"""
from __future__ import annotations

from typing import Optional

from src.contracts.tool_result import ToolResult

SOURCE = "mitre"


def lookup_technique(technique_id: Optional[str] = None, keyword: Optional[str] = None) -> ToolResult:
    """data = {"technique_id", "technique", "tactic": [...], "mitigation": [...], "detection": [...]}"""
    raise NotImplementedError("TODO: load ATT&CK data and look up")
