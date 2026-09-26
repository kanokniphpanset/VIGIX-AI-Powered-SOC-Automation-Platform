"""VirusTotal lookup.

Returns a normalized result. A timeout / error must come back as status "timeout" / "error",
never as "benign".
"""
from __future__ import annotations

from typing import Optional

from src.contracts.tool_result import ToolResult

SOURCE = "virustotal"


def lookup_ioc(ioc: str, ioc_type: Optional[str] = None) -> ToolResult:
    """data = {"ioc", "verdict", "score", "tags", "last_seen", "link"}"""
    raise NotImplementedError("TODO: call the VirusTotal API")
