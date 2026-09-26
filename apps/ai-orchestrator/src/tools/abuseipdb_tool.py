"""AbuseIPDB lookup.

Same normalized shape as virustotal_tool. IPs only.
"""
from __future__ import annotations


from src.contracts.tool_result import ToolResult

SOURCE = "abuseipdb"


def lookup_ip(ip: str) -> ToolResult:
    """data = {"ioc", "verdict", "score", "tags", "last_seen", "link"}"""
    raise NotImplementedError("TODO: call the AbuseIPDB API")
