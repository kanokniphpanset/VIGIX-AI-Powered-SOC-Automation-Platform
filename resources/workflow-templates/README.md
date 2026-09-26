# Workflow Templates

**Status: placeholder only (Phase 3). Not populated, no loader.**

The real n8n workflow template files already exist at
`automation/n8n/workflows/*.json` (`playbook-runner.json`,
`teams-notification.json`, `ticket-creation.json`) and are already
file-based and git-versioned — exactly the pattern this resource system is
trying to establish everywhere else. They are not hardcoded in application
code (confirmed in the Phase 1 audit: the backend's
`N8nWorkflowEngineAdapter.ts` calls out to n8n by webhook path, it doesn't
embed workflow definitions).

Consolidating those files into this folder instead of
`automation/n8n/workflows/` is a naming/location decision for a later
phase — moving them isn't an urgent gap, since they're already externalized
correctly, just in a different directory than this new system's layout
would otherwise suggest.
