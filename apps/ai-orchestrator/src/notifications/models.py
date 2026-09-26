from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action_name: str


class NotificationMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")

    incident_id: str
    incident_type: str
    # Severity (LOW..CRITICAL) suggested for the incident; the backend analyst-validated severity is authoritative.
    priority: str = "MEDIUM"

    confidence: float = 0.0
    asset_criticality: str = "unknown"

    decision: str = "unknown"
    approval_required: bool = False
    approval_tier: str | None = None

    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    mitre_techniques: list[dict] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)

    jira_reference: str | None = None


class NotificationResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    success: bool
    channel: str
    detail: dict | None = None
    error: str | None = None


class IncidentContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    incident_id: str = ""
    incident_type: str = "Security Incident"
    asset_criticality: str = "unknown"
    severity: str = "unknown"

    iocs: list = Field(default_factory=list)
    mitre_techniques: list[dict] = Field(default_factory=list)

    confidence: float = 0.0

    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
