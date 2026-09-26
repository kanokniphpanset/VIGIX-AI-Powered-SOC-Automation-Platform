"""
policy_loader.py — restores a missing, previously-documented module (see
prompt_loader.py's own docstring for the full context). Reconstructed
against resources/policies/incident-response-policy.yaml's own header
comments, resources/README.md, and PolicyEngine's PolicyConfig/
PolicyConfigProvider Protocol in
src/agents/decision_agent/policy_engine.py — every YAML field name below
matches a PolicyConfig field name exactly, by that file's own design.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from src.agents.decision_agent.models import AssetCriticality, BusinessPolicyTag, DecisionOutcome
from src.agents.decision_agent.policy_engine import PolicyConfig

_REPO_ROOT = Path(__file__).resolve().parents[3]
_POLICY_PATH = _REPO_ROOT / "resources" / "policies" / "incident-response-policy.yaml"


class ResourcePolicyConfigProvider:
    def __init__(self, policy_path: Path | None = None):
        self._policy_path = policy_path or _POLICY_PATH
        self._config: PolicyConfig | None = None
        self.reload()

    def reload(self) -> None:
        data = yaml.safe_load(self._policy_path.read_text(encoding="utf-8"))
        self._config = PolicyConfig(
            risk_auto_response_threshold=float(data["risk_auto_response_threshold"]),
            risk_human_approval_threshold=float(data["risk_human_approval_threshold"]),
            confidence_floor=float(data["confidence_floor"]),
            emergency_override_active=bool(data["emergency_override_active"]),
            emergency_override_outcome=DecisionOutcome(data["emergency_override_outcome"]),
            change_freeze_active=bool(data["change_freeze_active"]),
            policy_registry_version=str(data["policy_registry_version"]),
            asset_criticality_floor={
                AssetCriticality(tier): DecisionOutcome(outcome) for tier, outcome in data["asset_criticality_floor"].items()
            },
            business_floor_tags=frozenset(BusinessPolicyTag(tag) for tag in data["business_floor_tags"]),
        )

    def get_config(self, tenant_id: str = "", incident_category: str = "") -> PolicyConfig:
        # No per-tenant/per-category concept at this layer — a plain global
        # YAML file, same as SettingsPolicyConfigProvider's own precedent.
        assert self._config is not None
        return self._config
