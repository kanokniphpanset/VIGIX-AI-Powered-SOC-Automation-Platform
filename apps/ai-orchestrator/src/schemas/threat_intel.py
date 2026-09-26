"""Threat-intel output: per-source verdicts plus the merged view."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SourceVerdict:
    source: str                     # virustotal | abuseipdb | otx | misp
    status: str                     # ToolResult.status - keep errors visible
    verdict: Optional[str] = None   # malicious | suspicious | benign | unknown (None if the call failed)
    score: Optional[float] = None
    tags: list[str] = field(default_factory=list)
    last_seen: Optional[str] = None
    link: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ThreatIntelResult:
    ioc: str
    ioc_type: str
    sources: list[SourceVerdict] = field(default_factory=list)
    verdict: str = "unknown"        # never "benign" when a source failed and nothing else says so
    confidence: float = 0.0
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    incomplete: bool = False        # True when at least one source failed / timed out
