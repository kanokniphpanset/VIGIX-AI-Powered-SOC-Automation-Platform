"""
Core types for the Threat Intelligence Agent.

Kept as plain dataclasses (not pydantic) so they're cheap to construct in
tight loops and trivially convert to JSON-safe dicts via `to_dict()` for
storage in AgentState / Postgres — mirrors the TypedDict style already used
in graph/state.py rather than introducing a second modeling framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IocType(str, Enum):
    """
    Supported IOC types. Deliberately an open set at the *extraction* layer
    (ioc_extractor.py can tag anything), but only these are wired through to
    provider `supports()` checks and scoring today. Add a new member here to
    support another indicator type end-to-end.
    """

    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    EMAIL = "EMAIL"
    UNKNOWN = "UNKNOWN"


HASH_TYPES = (IocType.MD5, IocType.SHA1, IocType.SHA256)
IP_TYPES = (IocType.IPV4, IocType.IPV6)


class Verdict(str, Enum):
    """
    MALICIOUS/SUSPICIOUS/CLEAN require evidence from at least one provider.
    UNKNOWN means no provider could be queried (all disabled/failed) or none
    returned data — this is NOT the same as CLEAN and must never be conflated
    with it (see scoring.py).
    """

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    # Distinct from LOW: no evidence was available to assess risk at all
    # (every provider disabled/failed), vs. LOW meaning evidence was
    # gathered and indicates minimal risk. Mirrors the Verdict.UNKNOWN /
    # Verdict.CLEAN distinction for the same reason.
    UNKNOWN = "UNKNOWN"


class ProviderStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    DISABLED = "DISABLED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INVALID_INDICATOR = "INVALID_INDICATOR"


@dataclass
class ExtractedIoc:
    """Output of IOCExtractor, before normalization/validation."""

    value: str
    type: IocType
    field: str = "unknown"  # source alert field the IOC was pulled from


@dataclass
class ThreatIntelProviderResult:
    """Normalized result of a single provider's analysis of a single IOC."""

    name: str
    status: ProviderStatus
    malicious: bool = False
    suspicious: bool = False
    confidence: float = 0.0
    reputation: float | None = None
    categories: list[str] = field(default_factory=list)
    malware_family: str | None = None
    threat_actors: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    detections: int = 0
    total_checks: int = 0
    raw_summary: dict = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0
    from_cache: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "confidence": self.confidence,
            "reputation": self.reputation,
            "categories": self.categories,
            "malwareFamily": self.malware_family,
            "threatActors": self.threat_actors,
            "campaigns": self.campaigns,
            "detections": self.detections,
            "totalChecks": self.total_checks,
            "error": self.error,
            "durationMs": self.duration_ms,
            "fromCache": self.from_cache,
        }


@dataclass
class ThreatIntelData:
    """Final, explainable result for a single IOC — see threat-score.service / scoring.py."""

    indicator: str
    type: IocType
    verdict: Verdict
    risk_level: RiskLevel
    confidence: float
    threat_score: float
    malicious: bool
    suspicious: bool
    providers: list[ThreatIntelProviderResult]
    categories: list[str] = field(default_factory=list)
    malware_family: str | None = None
    threat_actors: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    analyzed_at: str = ""
    duration_ms: int = 0
    valid: bool = True
    invalid_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.type.value,
            "verdict": self.verdict.value,
            "riskLevel": self.risk_level.value,
            "confidence": self.confidence,
            "threatScore": self.threat_score,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "providers": [p.to_dict() for p in self.providers],
            "categories": self.categories,
            "malwareFamily": self.malware_family,
            "threatActors": self.threat_actors,
            "campaigns": self.campaigns,
            "sources": self.sources,
            "explanation": self.explanation,
            "analyzedAt": self.analyzed_at,
            "durationMs": self.duration_ms,
            "valid": self.valid,
            "invalidReason": self.invalid_reason,
        }

    def to_legacy_ioc(self, field_name: str = "unknown") -> dict:
        """
        Shape expected by graph/state.py::Ioc — kept so existing consumers
        (ml_risk_agent/feature_engineering.py, api/database.py) that only read
        ioc_type/ioc_value/source/reputation_score/raw_response keep working
        unmodified, while newer consumers can read the richer fields added
        alongside them.
        """
        return {
            "ioc_type": self.type.value.lower(),
            "ioc_value": self.indicator,
            "source": ",".join(self.sources) if self.sources else "none",
            "reputation_score": self.threat_score if self.sources else None,
            "raw_response": {p.name: p.to_dict() for p in self.providers},
            "verdict": self.verdict.value,
            "risk_level": self.risk_level.value,
            "threat_score": self.threat_score,
            "confidence": self.confidence,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "categories": self.categories,
            "sources": self.sources,
            "explanation": self.explanation,
            "analyzed_at": self.analyzed_at,
            "providers": [p.to_dict() for p in self.providers],
        }


@dataclass
class ThreatIntelReport:
    """Aggregate report across every IOC extracted from a single alert."""

    indicators: list[ThreatIntelData]
    summary: dict
    overall_risk_level: RiskLevel
    overall_confidence: float
    key_findings: list[str]
    analyzed_at: str
    duration_ms: int
    highest_risk_indicator: ThreatIntelData | None = None

    def to_dict(self) -> dict:
        return {
            "indicators": [i.to_dict() for i in self.indicators],
            "summary": self.summary,
            "highestRiskIndicator": self.highest_risk_indicator.to_dict()
            if self.highest_risk_indicator
            else None,
            "overallRiskLevel": self.overall_risk_level.value,
            "overallConfidence": self.overall_confidence,
            "keyFindings": self.key_findings,
            "analyzedAt": self.analyzed_at,
            "durationMs": self.duration_ms,
        }
