"""Re-hunt tool.

Executes the *original* hunt query again over a before / after window so verification can compare them.
Must cover all agents, not just the one that was attacked, or spread cannot be detected.

Host identity is `agent.id` (stable across agent renames, unlike `agent.name`).
`new_hosts` are hosts seen in the after-window that were NOT seen in the before-window for the
same query. This is spread *of this specific query's hits*, not overall event-volume growth on
hosts already affected.

If `agents` is given, the hunt is narrowed to just those agents (one wazuh_query_tool call per
agent, merged). If omitted, the query runs unfiltered by agent, exactly as required by the "must
cover all agents" rule above.
"""
from __future__ import annotations

from typing import Any, Optional

from src.contracts.tool_result import ToolResult
from src.tools import wazuh_query_tool

SOURCE = "rehunt"

# Hard ceiling per underlying wazuh_query_tool call. This tool cares about total_hits and the
# set of distinct hosts, not full pagination through every event, so a generous page is enough.
_PAGE_SIZE = 1000


def _extract_hosts(events: list[dict[str, Any]]) -> dict[str, str]:
    """host agent.id -> agent.name, from raw Wazuh Indexer hits."""
    hosts: dict[str, str] = {}
    for ev in events:
        source = ev.get("_source", ev)
        agent = source.get("agent") or {}
        agent_id = agent.get("id")
        if agent_id:
            hosts[agent_id] = agent.get("name", hosts.get(agent_id, ""))
    return hosts


def _run_window(
    *,
    original_query: str,
    time_range: dict[str, str],
    agents: Optional[list[str]],
    ioc: Optional[str],
) -> ToolResult:
    """Run one window's hunt, merged across `agents` if given. Returns a ToolResult whose
    data (on success) is {"total_hits", "events"}; failure short-circuits the caller."""
    call_query = {
        "original_query": original_query, "time_range": time_range, "agents": agents, "ioc": ioc,
    }

    agent_list = agents or [None]  # None = no agent filter, i.e. all agents
    total_hits = 0
    all_events: list[dict[str, Any]] = []

    for agent in agent_list:
        result = wazuh_query_tool.query_events(
            agent=agent,
            ioc=ioc,
            time_range=time_range,
            query=original_query,
            limit=_PAGE_SIZE,
        )
        if not result.ok:
            # Any failed leg means we cannot trust the count/host-set for this window.
            return ToolResult.failure(
                result.status if result.status != "ok" else "error",
                SOURCE,
                f"wazuh_query_tool failed for agent={agent!r}: {result.error}",
                call_query,
            )
        total_hits += result.data["total_hits"]
        all_events.extend(result.data["events"])

    return ToolResult.success(SOURCE, {"total_hits": total_hits, "events": all_events}, call_query)


def run_rehunt(
    *,
    original_query: str,
    before_range: dict[str, str],
    after_range: dict[str, str],
    agents: Optional[list[str]] = None,
    ioc: Optional[str] = None,
) -> ToolResult:
    """data = {"before_count": int, "after_count": int, "new_hosts": [...], "spread_detected": bool}"""
    call_args = {
        "original_query": original_query, "before_range": before_range, "after_range": after_range,
        "agents": agents, "ioc": ioc,
    }

    before = _run_window(original_query=original_query, time_range=before_range, agents=agents, ioc=ioc)
    if not before.ok:
        return ToolResult.failure(before.status, SOURCE, f"before-window hunt failed: {before.error}", call_args)

    after = _run_window(original_query=original_query, time_range=after_range, agents=agents, ioc=ioc)
    if not after.ok:
        return ToolResult.failure(after.status, SOURCE, f"after-window hunt failed: {after.error}", call_args)

    before_hosts = _extract_hosts(before.data["events"])
    after_hosts = _extract_hosts(after.data["events"])

    new_host_ids = set(after_hosts) - set(before_hosts)
    new_hosts = [{"id": hid, "name": after_hosts[hid]} for hid in sorted(new_host_ids)]

    data = {
        "before_count": before.data["total_hits"],
        "after_count": after.data["total_hits"],
        "new_hosts": new_hosts,
        "spread_detected": len(new_hosts) > 0,
    }
    return ToolResult.success(SOURCE, data, call_args)