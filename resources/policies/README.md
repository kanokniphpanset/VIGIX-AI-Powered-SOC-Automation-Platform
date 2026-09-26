# Policies

Incident-response policy configuration, read by DecisionAgent's
PolicyEngine (`apps/ai-orchestrator/src/agents/decision_agent/policy_engine.py`).
See the top-level `resources/README.md` for the "how to change a policy"
walkthrough.

## `incident-response-policy.yaml`

Fully migrated (Phase 3). Previously two things were hardcoded in
`policy_engine.py` itself:

- The tunable thresholds (`risk_auto_response_threshold`,
  `risk_human_approval_threshold`, `confidence_floor`, etc.) — these were
  already reading from `.env`-backed Settings via `SettingsPolicyConfigProvider`,
  which still exists as a fallback/legacy option but is no longer the default.
- `_ASSET_CRITICALITY_FLOOR` and `_BUSINESS_FLOOR_TAGS` — module-level
  Python dict/set literals used directly inside the Tier 3 (Asset
  Criticality) and Tier 7 (Business) policy evaluators.

All of the above now live in this one YAML file, loaded by
`apps/ai-orchestrator/resources/policy_loader.py::ResourcePolicyConfigProvider`,
which is `PolicyEngine`'s default provider as of this phase.

The policy's `id` (`incident-response-policy`) is how
`ResourcePolicyConfigProvider` finds it — if you add a second policy file
for a different scenario, give it a different `id` and pass that id to
`ResourcePolicyConfigProvider(policy_id=...)` wherever you want it used.
