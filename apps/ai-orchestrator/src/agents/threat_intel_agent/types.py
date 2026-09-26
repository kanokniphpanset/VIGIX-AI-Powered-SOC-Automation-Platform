"""
Core types for the Threat Intelligence Agent (Phase 2).

Plain dataclasses (not pydantic) so they're cheap to construct in tight
loops and trivially convert to JSON-safe dicts via `to_dict()` for storage
in AgentState / Postgres — mirrors the TypedDict style already used in
graph/state.py rather than introducing a second modeling framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IocType(str, Enum):
    """
    Supported IOC types. Deliberately an open set at the *extraction* layer
    (ioc_extractor.py can tag anything), but only these are wired through to
    provider `supports()` checks and scoring today.
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
    MALICIOUS/SUSPICIOUS/BENIGN require evidence from at least one provider.
    UNKNOWN means no provider could be queried at all (all NOT_CONFIGURED/
    FAILED/TIMEOUT/RATE_LIMITED) — this is NOT the same as BENIGN and must
    never be conflated with it (see scoring.py). A NO_MATCH from every
    configured provider is also UNKNOWN, not BENIGN: "nobody has ever seen
    this indicator" is not proof it's safe.
    """

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    # Distinct from LOW: no evidence was available to assess risk at all, vs.
    # LOW meaning evidence was gathered and indicates minimal risk.
    UNKNOWN = "UNKNOWN"


class ProviderStatus(str, Enum):
    """
    Per-provider outcome of querying one IOC. SUCCESS means the provider was
    reached and answered — it says nothing about whether the answer was a
    hit. A hit-less answer is NO_MATCH, never folded into SUCCESS silently
    and never reported as BENIGN.
    """

    SUCCESS = "SUCCESS"
    NO_MATCH = "NO_MATCH"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INVALID_INDICATOR = "INVALID_INDICATOR"


class PipelineStatus(str, Enum):
    """
    Overall status of one IOC's analysis across every provider — distinct
    from Verdict (which is about maliciousness) and from any single
    provider's ProviderStatus. See scoring.py::pipeline_status_for.
    """

    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


class EvidenceType(str, Enum):
    DETECTION_STATS = "DETECTION_STATS"
    REPUTATION_SCORE = "REPUTATION_SCORE"
    MISP_ATTRIBUTE = "MISP_ATTRIBUTE"
    OTX_PULSE = "OTX_PULSE"
    NO_RECORD = "NO_RECORD"


@dataclass
class Evidence:
    """
    One traceable, provider-attributed fact — see spec section 11. Never
    constructed for a NOT_CONFIGURED/FAILED/TIMEOUT/RATE_LIMITED provider
    (nothing was actually observed), and never invented when a provider's
    response has nothing evidentiary in it — an empty evidence list is
    always a legitimate outcome, never backfilled with a guess.
    """

    provider: str
    ioc: str
    evidence_type: EvidenceType
    provider_object_id: str | None = None
    reference: str | None = None
    observed_at: str | None = None
    fetched_at: str = ""
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "ioc": self.ioc,
            "evidenceType": self.evidence_type.value,
            "providerObjectId": self.provider_object_id,
            "reference": self.reference,
            "observedAt": self.observed_at,
            "fetchedAt": self.fetched_at,
            "summary": self.summary,
        }


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
    source: str = "LIVE"  # "LIVE" or "CACHE" — see cache.py
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
    evidence: list[Evidence] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0
    retry_count: int = 0

    def to_dict(self) -> dict:
        return {
            "provider": self.name,
            "status": self.status.value,
            "source": self.source,
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
            "evidence": [e.to_dict() for e in self.evidence],
            "error": self.error,
            "durationMs": self.duration_ms,
            "retryCount": self.retry_count,
        }


@dataclass
class ThreatIntelData:
    """Final, explainable result for a single IOC — see scoring.py."""

    indicator: str
    type: IocType
    status: PipelineStatus
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
    execution_id: str | None = None
    valid: bool = True
    invalid_reason: str | None = None

    @property
    def evidence(self) -> list[Evidence]:
        return [e for p in self.providers for e in p.evidence]

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "type": self.type.value,
            "status": self.status.value,
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
            "executionId": self.execution_id,
            "valid": self.valid,
            "invalidReason": self.invalid_reason,
        }

    def to_result_contract(self) -> dict:
        """Spec section 10's exact shape — see result_contract.py."""
        from .result_contract import build_result_contract

        return build_result_contract(self)

    def to_legacy_ioc(self, field_name: str = "unknown") -> dict:
        """
        Shape expected by graph/state.py::Ioc — kept so existing consumers
        (api/database.py) that only
        read ioc_type/ioc_value/source/reputation_score/raw_response keep
        working unmodified, while newer consumers can read the richer
        fields added alongside them.
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
    execution_id: str | None = None
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
            "executionId": self.execution_id,
        }
