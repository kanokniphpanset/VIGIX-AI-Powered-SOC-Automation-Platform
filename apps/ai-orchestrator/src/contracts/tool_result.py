"""Common envelope returned by every tool.

`status` is the important part: a failed lookup must never look like a clean result.
  ok            the tool ran and `data` is valid (an empty result is still "ok")
  not_found     the source answered that it has no record of the query
  error         the tool or the remote service failed
  timeout       the remote service did not answer in time
  rate_limited  the remote service refused because of quota
Only "ok" and "not_found" are answers. The other three mean "we do not know".
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_ERROR = "error"
STATUS_TIMEOUT = "timeout"
STATUS_RATE_LIMITED = "rate_limited"

ANSWER_STATUSES = frozenset({STATUS_OK, STATUS_NOT_FOUND})
FAILURE_STATUSES = frozenset({STATUS_ERROR, STATUS_TIMEOUT, STATUS_RATE_LIMITED})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ToolResult:
    status: str
    source: str
    query: dict[str, Any] = field(default_factory=dict)  # the real query, kept for audit
    data: dict[str, Any] = field(default_factory=dict)
    queried_at: datetime = field(default_factory=_utcnow)
    raw_ref: Optional[str] = None  # id of the stored raw response, if any
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    @property
    def is_answer(self) -> bool:
        """True only when the tool actually answered (ok / not_found)."""
        return self.status in ANSWER_STATUSES

    @classmethod
    def success(cls, source: str, data: dict[str, Any], query: Optional[dict[str, Any]] = None,
                raw_ref: Optional[str] = None) -> "ToolResult":
        return cls(status=STATUS_OK, source=source, data=data, query=query or {}, raw_ref=raw_ref)

    @classmethod
    def failure(cls, status: str, source: str, error: str, query: Optional[dict[str, Any]] = None) -> "ToolResult":
        if status not in FAILURE_STATUSES | {STATUS_NOT_FOUND}:
            raise ValueError(f"not a failure status: {status}")
        return cls(status=status, source=source, error=error, query=query or {})

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["queried_at"] = self.queried_at.isoformat()
        return d
