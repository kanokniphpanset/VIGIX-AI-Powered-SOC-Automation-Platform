# Assets

Real host → business-criticality mapping, read by MlRiskAgent's weighted
risk score (`apps/ai-orchestrator/src/ml_models/weighted_risk_model.py`)
and DecisionAgent's PolicyEngine Tier 3 (Asset Criticality) evaluator
(`apps/ai-orchestrator/src/agents/decision_agent/policy_engine.py`). See the
top-level `resources/README.md` for the "how to change a resource"
walkthrough.

## `asset-criticality-catalog.yaml`

Resolves a real alert's `agent.name`/`agent.ip` (or Wazuh's `data.srcip`) to
one of the four `AssetCriticality` tiers (`tier1_critical` | `tier2_high` |
`tier3_medium` | `tier4_low`), via
`apps/ai-orchestrator/resources/asset_criticality_loader.py::ResourceAssetCriticalityProvider`,
called from `run_pipeline.py::_resolve_asset_criticality()`.

There is no live asset-inventory system in this repo (`OBS-002`'s
description in `resources/response-actions/OBS-002.yaml` describes one
aspirationally; nothing implements it) — this file is the authoritative,
hand-maintained source until one exists. Match by IP is tried first, then
hostname (case-insensitive), then the catalog's own `default_tier` for
anything uncatalogued.

**This directly changes real automation behavior.** Before this file
existed, `asset_criticality` was never populated anywhere in the pipeline,
so every incident silently defaulted to `tier1_critical` — which, under
`resources/policies/incident-response-policy.yaml`'s
`asset_criticality_floor`, forces a `human_approval` floor on *every*
incident regardless of what it targets. With this catalog wired in, hosts
tagged `tier3_medium`/`tier4_low` (e.g. dev/test workstations) become
eligible for `auto_response`/`dismiss` outcomes for the first time. Review
the tiers below before relying on them in a live environment — they were
assigned from hostname naming convention, not a verified asset-ownership
process.

The resource's `id` (`asset-criticality-catalog`) is how
`ResourceAssetCriticalityProvider` finds it — same one-resource-per-id
convention as `resources/policies/incident-response-policy.yaml`.
