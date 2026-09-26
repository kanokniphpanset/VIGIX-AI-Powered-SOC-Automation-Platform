"""MISP lookup.

Same normalized shape as virustotal_tool.
"""
from __future__ import annotations

from typing import Optional

from src.contracts.tool_result import ToolResult

SOURCE = "misp"


def lookup_ioc(ioc: str, ioc_type: Optional[str] = None) -> ToolResult:
    """data = {"ioc", "verdict", "score", "tags", "last_seen", "link"}"""
    raise NotImplementedError("TODO: call MISP")
