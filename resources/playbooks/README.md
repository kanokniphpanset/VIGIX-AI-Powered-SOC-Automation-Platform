# Playbooks

**Status: placeholder only (Phase 3). Not populated, no loader.**

Not a migration target this phase — the Phase 1 Repository Analysis found
no hardcoded playbook *content* in code to migrate. The closest existing
concept is the n8n workflow JSON files at `automation/n8n/workflows/`
(playbook-runner.json, teams-notification.json, ticket-creation.json),
which are already file-based/git-versioned — see that folder's own README.
Whether this folder becomes something distinct (e.g. a higher-level
playbook definition that *references* an n8n workflow by id) is a decision
for a later phase, not this one.
