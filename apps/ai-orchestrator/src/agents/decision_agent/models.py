from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DecisionResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    escalate: bool = False
    responsible_role: str = ""
    approval_required: bool = False
    approval_role: str | None = None
    severity: str = ""
    policy_id: str = ""
    policy_version: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
