"""Wazuh Indexer query tool.

Talks to the Wazuh Indexer. It only queries; it never decides whether something is an attack.
Read-only. Paginate, and always return the real `total_hits` (not len(events)).

Connection config comes from environment variables (see `_load_config`). No credentials
are hardcoded here on purpose.

Environment variables
    WAZUH_INDEXER_HOST           default "localhost"
    WAZUH_INDEXER_PORT           default "9200"
    WAZUH_INDEXER_USER           default "admin"
    WAZUH_INDEXER_PASSWORD       required, no default
    WAZUH_INDEXER_USE_SSL        default "true"
    WAZUH_INDEXER_VERIFY_CERTS   default "false"  (wazuh-docker single-node ships a self-signed cert)
    WAZUH_INDEXER_CA_CERTS       optional path to a CA bundle; used only if VERIFY_CERTS=true
    WAZUH_ALERTS_INDEX_PATTERN   default "wazuh-alerts-*"
    WAZUH_INDEXER_TIMEOUT        default "10" (seconds)

Requires the `opensearch-py` package (the Wazuh Indexer is OpenSearch under the hood):
    pip install opensearch-py
"""
from __future__ import annotations

import os
from typing import Any, Optional

from opensearchpy import OpenSearch
from opensearchpy.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConnectionError as OSConnectionError,
    ConnectionTimeout,
    NotFoundError,
    RequestError,
)

from src.contracts.tool_result import ToolResult

SOURCE = "wazuh_query"

# Fields IOC values are matched against. Adjust/extend as your alert schema grows
# (e.g. add "data.win.eventdata.hashes" once Sysmon/Windows alerts are ingested).
_IOC_FIELDS = [
    "data.srcip",
    "data.dstip",
    "data.url",
    "data.hash",
    "syscheck.sha256_after",
    "syscheck.md5_after",
    "full_log",
]

_client: Optional[OpenSearch] = None  # lazy singleton, one per process


class WazuhQueryConfigError(RuntimeError):
    """Raised when required connection settings are missing."""


def _load_config() -> dict[str, Any]:
    password = os.environ.get("WAZUH_INDEXER_PASSWORD")
    if not password:
        raise WazuhQueryConfigError(
            "WAZUH_INDEXER_PASSWORD is not set. Set it to the Wazuh Indexer admin "
            "password configured for your wazuh-docker stack."
        )
    return {
        "host": os.environ.get("WAZUH_INDEXER_HOST", "localhost"),
        "port": int(os.environ.get("WAZUH_INDEXER_PORT", "9200")),
        "user": os.environ.get("WAZUH_INDEXER_USER", "admin"),
        "password": password,
        "use_ssl": os.environ.get("WAZUH_INDEXER_USE_SSL", "true").lower() != "false",
        "verify_certs": os.environ.get("WAZUH_INDEXER_VERIFY_CERTS", "false").lower() == "true",
        "ca_certs": os.environ.get("WAZUH_INDEXER_CA_CERTS") or None,
        "index_pattern": os.environ.get("WAZUH_ALERTS_INDEX_PATTERN", "wazuh-alerts-*"),
        "timeout": int(os.environ.get("WAZUH_INDEXER_TIMEOUT", "10")),
    }


def _get_client(cfg: dict[str, Any]) -> OpenSearch:
    global _client
    if _client is not None:
        return _client
    _client = OpenSearch(
        hosts=[{"host": cfg["host"], "port": cfg["port"]}],
        http_auth=(cfg["user"], cfg["password"]),
        use_ssl=cfg["use_ssl"],
        verify_certs=cfg["verify_certs"],
        ca_certs=cfg["ca_certs"],
        ssl_show_warn=False,
        timeout=cfg["timeout"],
    )
    return _client


def reset_client() -> None:
    """Drop the cached client so the next call reconnects (e.g. after config changes, in tests)."""
    global _client
    _client = None


def _build_query_body(
    *,
    agent: Optional[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    rule: Optional[str],
    user: Optional[str],
    ioc: Optional[str],
    time_range: Optional[dict[str, str]],
) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    filter_: list[dict[str, Any]] = []

    if agent:
        # Matches either the agent name or its numeric id.
        must.append({
            "bool": {
                "should": [
                    {"term": {"agent.id": agent}},
                    {"match": {"agent.name": agent}},
                ],
                "minimum_should_match": 1,
            }
        })
    if source_ip:
        must.append({"term": {"data.srcip": source_ip}})
    if destination_ip:
        must.append({"term": {"data.dstip": destination_ip}})
    if rule:
        must.append({
            "bool": {
                "should": [
                    {"term": {"rule.id": rule}},
                    {"match": {"rule.description": rule}},
                ],
                "minimum_should_match": 1,
            }
        })
    if user:
        must.append({
            "bool": {
                "should": [
                    {"match": {"data.srcuser": user}},
                    {"match": {"data.dstuser": user}},
                ],
                "minimum_should_match": 1,
            }
        })
    if ioc:
        must.append({
            "bool": {
                "should": [{"term": {f: ioc}} for f in _IOC_FIELDS[:-1]]
                + [{"match_phrase": {"full_log": ioc}}],
                "minimum_should_match": 1,
            }
        })
    if time_range and (time_range.get("from") or time_range.get("to")):
        range_clause: dict[str, str] = {}
        if time_range.get("from"):
            range_clause["gte"] = time_range["from"]
        if time_range.get("to"):
            range_clause["lte"] = time_range["to"]
        filter_.append({"range": {"timestamp": range_clause}})

    if not must and not filter_:
        query: dict[str, Any] = {"match_all": {}}
    else:
        query = {"bool": {"must": must, "filter": filter_}}

    return {"query": query, "sort": [{"timestamp": {"order": "desc"}}]}


def query_events(
    *,
    agent: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    rule: Optional[str] = None,
    user: Optional[str] = None,
    ioc: Optional[str] = None,
    time_range: Optional[dict[str, str]] = None,   # {"from": iso, "to": iso}
    query: Optional[str] = None,                   # raw Lucene/DSL string, stored for re-hunt
    limit: int = 100,
) -> ToolResult:
    """data = {"total_hits": int, "events": [...], "query": str, "time_range": {...}}"""
    call_args = {
        "agent": agent, "source_ip": source_ip, "destination_ip": destination_ip,
        "rule": rule, "user": user, "ioc": ioc, "time_range": time_range,
        "query": query, "limit": limit,
    }

    try:
        cfg = _load_config()
    except WazuhQueryConfigError as exc:
        return ToolResult.failure("error", SOURCE, str(exc), call_args)

    try:
        client = _get_client(cfg)

        if query:
            # Raw query string wins when given; stored as-is so re-hunt can replay it verbatim.
            body: dict[str, Any] = {
                "query": {"query_string": {"query": query}},
                "sort": [{"timestamp": {"order": "desc"}}],
            }
            effective_query = query
        else:
            body = _build_query_body(
                agent=agent, source_ip=source_ip, destination_ip=destination_ip,
                rule=rule, user=user, ioc=ioc, time_range=time_range,
            )
            effective_query = body["query"]

        response = client.search(
            index=cfg["index_pattern"],
            body=body,
            size=limit,
            track_total_hits=True,
        )
    except (AuthenticationException, AuthorizationException) as exc:
        return ToolResult.failure("error", SOURCE, f"authentication failed: {exc}", call_args)
    except ConnectionTimeout as exc:
        return ToolResult.failure("timeout", SOURCE, f"indexer did not respond in time: {exc}", call_args)
    except OSConnectionError as exc:
        return ToolResult.failure("error", SOURCE, f"could not reach the Wazuh Indexer: {exc}", call_args)
    except NotFoundError as exc:
        # The index pattern matched nothing existing yet (e.g. fresh install, no alerts ingested).
        return ToolResult.success(
            SOURCE,
            {"total_hits": 0, "events": [], "query": str(effective_query), "time_range": time_range or {}},
            query=call_args,
        )
    except RequestError as exc:
        return ToolResult.failure("error", SOURCE, f"malformed query rejected by indexer: {exc}", call_args)
    except Exception as exc:  # noqa: BLE001 - last-resort guard, never surface as a clean result
        return ToolResult.failure("error", SOURCE, f"unexpected error querying Wazuh Indexer: {exc}", call_args)

    hits = response.get("hits", {})
    total = hits.get("total", {})
    total_hits = total.get("value", 0) if isinstance(total, dict) else total
    events = hits.get("hits", [])

    data = {
        "total_hits": total_hits,
        "events": events,
        "query": str(effective_query),
        "time_range": time_range or {},
    }
    return ToolResult.success(SOURCE, data, query=call_args)