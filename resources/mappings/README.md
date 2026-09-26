# Mappings

Backs the Investigation Recommendation capability
(`apps/ai-orchestrator/src/agents/recommendation_agent/`) — loaded at
runtime via `apps/ai-orchestrator/resources/mapping_loader.py`.

- `recommendation-catalog.yaml` — incident type -> candidate recommendation
  entries (category, evidence conditions, default priority, MITRE
  techniques, automation hint). Selection is deterministic and
  evidence-gated — see `RecommendationSelector`.
- `nist-800-61-r3-mapping.yaml` — VIGIX recommendation category -> verified
  NIST SP 800-61 Rev.3 / CSF 2.0 function-level traceability. Fine-grained
  section citations are `reference_required` by design, never fabricated.
- `playbook-index.yaml` — incident type -> local playbook
  (`apps/backend/data/knowledge/playbooks/*.md`) plus non-authoritative
  external structural references (msraju/Incident-Response-Playbooks,
  austinsonger/Incident-Playbook).

Edit any file here and restart the AI orchestrator (or call the relevant
loader's `reload()`/`start_watching()`) to change the catalog without
touching Python — same convention as `resources/policies/`.
