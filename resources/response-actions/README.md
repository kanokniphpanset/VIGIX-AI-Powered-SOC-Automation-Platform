# Response Actions

**Status: real, loaded at runtime (Phase 8; extended Phase 5.7; fully
reconciled against the AI orchestrator's catalog in Phase 5.8.2).**
Scaffolded (folder + README only) in Phase 3; migrated for real in Phase 8,
since the Response module that consumes it now exists.

21 actions ship here: 16 reconcile 1:1 against
`apps/ai-orchestrator/src/agents/decision_agent/action_catalog.py`'s 16
entries (see the reconciliation table below), plus 5 pre-Phase-5.7 generic
notify/ticket actions that have no AI-catalog counterpart at all (they back
the orchestrator callback's unconditional notify+ticket playbook, not a
`Decision.recommendedActionIds` entry):

| Action id | Executor | Real integration used |
|---|---|---|
| `notify-soc-teams` | `n8n` | `automation/n8n/workflows/teams-notification.json` (webhook `soar/notify-teams`) |
| `create-investigation-ticket` | `n8n` | `automation/n8n/workflows/ticket-creation.json` (webhook `soar/create-ticket`) |
| `notify-external-webhook` | `webhook` | Generic outbound HTTP POST, URL from `RESPONSE_WEBHOOK_URL` env var — real, not stubbed |
| `notify-oncall-email` | `email` | **Not implemented** — no backend-reachable SMTP integration exists (Python's `notifications/email_notification_service.py` lives in a different process) |
| `notify-oncall-line` | `line` | **Not implemented** — same gap, LINE Messaging API client only exists on the Python side |

## Relationship to `apps/ai-orchestrator`'s own action catalog

`apps/ai-orchestrator/src/agents/decision_agent/action_catalog.py` is a
**separate, still-hardcoded** catalog — it exists for DecisionAgent's own
policy purposes (which actions to *recommend*, at what approval tier),
computed at pipeline-run time. This resource folder is about *execution* —
given a decision's recommended action id(s)
(`Decision.recommendedActionIds`/`recommendedActions`, Phase 5.6/5.7), which
real system call does running it actually make.

**Phase 5.8.2 reconciliation table** — every id below has an identical
`riskLevel`/`automationSupported`/`approvalRequired`/`rollbackAvailable` on
both sides (verified by hand against `action_catalog.py` when this table was
built; drift after this point is caught at runtime, see below):

| Action id | Category | Risk | Automation | Approval tier | Rollback |
|---|---|---|---|---|---|
| `OBS-001` | observation | low | yes | no_approval | n/a |
| `OBS-002` | observation | low | yes | no_approval | n/a |
| `NOTIF-001` | notification | low | yes | no_approval | n/a |
| `NOTIF-003` | notification | low | yes | no_approval | n/a |
| `INV-001` | investigation | low | conditional | no_approval | n/a |
| `INV-002` | investigation | low | yes | no_approval | n/a |
| `CONT-001` | containment | high | yes | soc_analyst_approval | yes |
| `CONT-004` | containment | medium | yes | no_approval | yes |
| `CRED-001` | credential_response | medium | yes | no_approval | partial |
| `CRED-003` | credential_response | high | yes | soc_analyst_approval | yes |
| `NET-001` | network_response | medium | yes | no_approval | yes |
| `NET-002` | network_response | low | yes | no_approval | yes |
| `EP-002` | endpoint_response | medium | yes | soc_analyst_approval | partial |
| `EP-006` | endpoint_response | medium | conditional | soc_analyst_approval | n/a |
| `REC-004` | recovery | medium | conditional | manager_approval | yes |
| `REC-005` | recovery | low | conditional | soc_analyst_approval | n/a |

15 of these 16 route through the same deliberately safe n8n dry-run
workflow (`automation/n8n/workflows/action-executor-dryrun.json`, webhook
`soar/execute-action-dryrun`) that `CRED-003`/`CONT-001` (among others)
used since Phase 5.7 — none of those 15 have a real firewall/EDR/IAM/
SIEM/ticketing API wired up in this environment. See Phase 5.7/5.8's final
reports for the explicit scope of what was and wasn't verified against a
live security tool.

`NET-001` is the one exception (Phase 5.9, explicit user authorization):
its `executor` is `ssh_firewall`, not `n8n` — approving a Decision that
recommends it really SSHes into `FIREWALL_SSH_HOST` and runs a real
`iptables ... -j DROP` against the target IP, no dry-run, no further
confirmation. See `SshFirewallExecutor`'s own docstring for the security
notes (strict IP validation, idempotent rule insertion, key-based auth
only).

### Catalog drift after reconciliation — runtime `CATALOG_CONFLICT` check

This table is a point-in-time hand reconciliation, not a shared source of
truth — the two catalogs can still drift apart if either file changes
without the other. `AutomationPolicyEvaluator`
(`src/domain/automation/services/AutomationPolicyEvaluator.ts`) guards
against exactly that at evaluation time: for every recommended action, it
compares the AI-persisted `requiredApprovalTier`
(`Decision.recommendedActions[].requiredApprovalTier`, written by the
orchestrator) against this catalog's own `approvalRequired` for the same
action id. A disagreement is a `catalogConflict` — the action is marked
non-auto-executable regardless of what either side claims, the whole
Decision falls back to `HUMAN_APPROVAL`, and `AutomationPolicyService`
records a distinct `catalog_validation_failed` audit event (never silently
prefers one catalog over the other). An action id missing from this catalog
entirely (not yet reconciled) fails the same way via `foundInCatalog: false`.

## How to add a new response action

Same as any other resource (see the top-level `resources/README.md`): add
a `.yaml` file here with `id`, `name`, `description`, `category`,
`riskLevel`, `automationSupported`, `approvalRequired`,
`rollbackAvailable`, `executor` (`n8n` | `webhook` | `email` | `line`), and
`executorConfig` (shape depends on `executor` — `n8n` needs `webhookPath`,
`webhook` needs `urlEnvVar`). No code change required for a new `n8n` or
`webhook` action. If the new id also exists in
`action_catalog.py`, add it to the reconciliation table above with matching
values — a mismatch is safe (falls back to `HUMAN_APPROVAL`) but defeats the
point of adding automation-eligible actions.
