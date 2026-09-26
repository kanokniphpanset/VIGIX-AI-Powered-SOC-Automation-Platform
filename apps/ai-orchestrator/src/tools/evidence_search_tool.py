"""Evidence search tool.

The one standard way to fetch evidence. Agents cite evidence only by the `evidence_id` returned here.
"""
from __future__ import annotations

from typing import Any, Optional

from src.contracts.tool_result import ToolResult

SOURCE = "evidence_search"


def search_evidence(
    incident_id: str,
    *,
    evidence_type: Optional[str] = None,
    filters: Optional[dict[str, Any]] = None,
) -> ToolResult:
    """data = {"evidence": [{"evidence_id", "type", "source", "timestamp", "data"}]}"""
    raise NotImplementedError("TODO: read from evidence_repository")
