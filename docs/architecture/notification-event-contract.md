# VIGIX Notification Event Contract & Template Specification (Phase N1)

> **Update 2026-09-25 — Severity is the primary classification; Risk Score is retired from decisions.**
> Policy now evaluates the incident **severity** (analyst-validated) plus asset criticality and action impact.
> The risk-score rules (RULE-R01..R04, RULE-P08, RULE-P10) are disabled (rows kept for history), the engine never
> matches a `riskScore` condition, and no risk score is produced, sent or displayed. Canonical rules:
> `apps/backend/prisma/seeds/policy.seed.ts`. Statements about risk score / risk level below are historical.

Status: **specification only — no backend/n8n code written yet.** This is the
artifact Phase N2 (Backend Notification Event/Dispatcher) and Phase N4
(n8n webhook) both build against, so backend, n8n, and frontend agree on one
shape instead of drifting apart.

Every field below is checked against the **real, currently-persisted**
entities in `apps/backend` (Incident, Recommendation, Approval, ResponsePlan,
Verification — see the audit that preceded this doc). Where the earlier
example JSON assumed a field that doesn't actually exist, that's called out
explicitly rather than silently "fixed" — these are decisions for you to
confirm, not facts to take on faith.

---

## 1. Design principles (unchanged from your brief)

```
Backend  = Source of Truth + Event Generator   (decides WHAT happened and WHO should hear about it)
Contract = this document                        (the shape backend and n8n both agree to)
n8n      = Template fill + delivery only         (never decides approval, never queries Postgres)
Human    = Approval / Response decision
```

n8n receives a fully-assembled JSON payload and a `recipient.roles` list — it
never joins tables, never infers who approves, never decides anything.

---

## 2. Two real structural corrections to your example

Before the per-event spec, two places where the real schema doesn't match
the example JSON in your message — flagging these now avoids rebuilding
templates later.

### 2.1 `incident.severity` doesn't exist — use `incident.priority`

`Incident` has no `severity` column. The closest real field is
`Incident.priority` (`"low"|"medium"|"high"|"critical"`, already what the
Ticket Dashboard displays). `Alert.severity` also exists (one hop away via
`Incident.alertId`) but Policy evaluation itself already reads and acts on
`priority`, so the contract uses `priority` too — it's the value that's
actually driving the system's own decisions, not a second, possibly-divergent number.

There is also no `incident.type` field (no persisted "BRUTE_FORCE" style
category) — that string exists today only as a runtime heuristic inside
`FakeRecommendationAgent.inferAttackSignal()`, never written to the
database. **Left out of the contract** rather than re-derived with a second
heuristic that could disagree with the first. `incident.riskScore` *is*
available, but only via `RecommendationContextRepository.getLatestRiskScore()`
— already documented in that file as "arbitrary row if more than one exists,
no timestamp to order by." Included as `riskScore: number | null` with that
caveat carried into the field description below.

### 2.2 `recommendation.actionCode` (singular) doesn't match reality for `APPROVAL_REQUIRED`

`RequestApprovalUseCase` requests approval for an entire **Recommendation**
(which can have multiple steps, only some of which have `requiresApproval:
true` and a concrete `actionId`) — not for one single action. A
Recommendation → single-action assumption only becomes true later, at
`CreateResponsePlanUseCase` (one step → one ResponsePlan).

So `APPROVAL_REQUIRED`'s payload carries `recommendation.stepsRequiringApproval: [...]`
(an array — usually length 1 in today's seeded data, but the contract
doesn't assume that), while `RESPONSE_ASSIGNED`/`RESPONSE_COMPLETED` (which
fire per-ResponsePlan, i.e. per-step) correctly carry a single flattened
`ticket.action`/`ticket.target`.

---

## 3. Base envelope

```ts
interface NotificationEvent {
  eventType:
    | "APPROVAL_REQUIRED"
    | "APPROVAL_APPROVED"
    | "APPROVAL_REJECTED"
    | "RESPONSE_ASSIGNED"
    | "RESPONSE_COMPLETED"
    | "VERIFICATION_NOT_RESOLVED"
    | "INVESTIGATION_REOPENED";
  eventId: string;       // crypto.randomUUID(), generated once at emit time — MUST be unique per emit call. Not persisted in N1/N2 (no notification table, per your instruction not to fake DELIVERED), but n8n should still treat it as the idempotency key from day one: if a future retry (backend timeout → resend) delivers the same eventId twice, the receiving workflow should be able to dedupe on it rather than double-send. N2 does not implement retry itself (see §8/reliability) — this field just makes that possible later without a payload shape change.
  timestamp: string;     // ISO 8601, emit time
  tenantId: string;

  recipient: {
    roles: ("SOC" | "IR_TEAM" | "MANAGER")[];  // array — VERIFICATION_NOT_RESOLVED and INVESTIGATION_REOPENED are multi-recipient.
    // Deliberately NO "addresses"/"email" field here, and never will be in
    // this envelope — see §4.1. Role -> actual mailbox (one address, many
    // addresses, a distribution list, whatever) is resolved entirely on
    // the delivery side (n8n or its config), specifically so that "MANAGER
    // now means two people" is a config change, not a backend redeploy.
    channels: ("email" | "discord" | "telegram")[];  // (N3.5) delivery mechanism only, never authorization — see §9. Backend always sends all three today; n8n intersects with whatever's actually configured for that role.
  };

  incident: IncidentSummary;        // always present
  ticket?: TicketSummary;           // present on RESPONSE_ASSIGNED / RESPONSE_COMPLETED; absent on APPROVAL_* (no ResponsePlan exists yet at that point — see 2.2)
  recommendation?: RecommendationSummary;  // present on APPROVAL_REQUIRED / APPROVAL_APPROVED / APPROVAL_REJECTED
  approval?: ApprovalSummary;       // present on all APPROVAL_* events
  verification?: VerificationSummary; // present on VERIFICATION_NOT_RESOLVED / INVESTIGATION_REOPENED

  links: {
    ticket?: string;      // `${VIGIX_BASE_URL}/tickets/{responsePlanId}` — only when ticket is present
    approval?: string;    // `${VIGIX_BASE_URL}/incidents/{incidentId}/approval` — only when approval is present
  };
}

interface IncidentSummary {
  id: string;
  title: string;
  priority: string;           // real field — see 2.1
  riskScore: number | null;   // real, but "latest arbitrary row" caveat — see 2.1
  investigationNumber: number;
}

interface TicketSummary {
  id: string;                 // ResponsePlan.id
  incidentId: string;         // ResponsePlan.incidentId — explicit even though incident.id is also on the envelope, so a template can link a ticket to its incident without cross-referencing two objects
  status: string;
  approvalStatus: string;     // ResponsePlan.approvalStatus — NOT_REQUIRED | PENDING | APPROVED | REJECTED, distinct from ApprovalSummary.status (that's the Approval row's own status, if one exists)
  action: { code: string; name: string } | null;   // resolved via Action lookup by ResponsePlan.actionId — payload builder's job, not n8n's
  target: string | null;
  runbook: { code: string } | null;                 // resolved via Runbook lookup, only if the step had a sourceRunbookId
  assignedRole: string;
}

interface RecommendationSummary {
  id: string;
  recommendationNumber: number;
  summary: string;            // Recommendation.summary — real free-text field, always safe to show
  stepsRequiringApproval: {
    title: string;
    action: { code: string; name: string } | null;
    target: string | null;
    runbook: { code: string } | null;
  }[];
}

interface ApprovalSummary {
  id: string;
  role: string;                // Approval.approvalRole
  status: string;               // pending | approved | rejected | more_evidence_requested
  reason: string;
  decidedBy: string | null;     // a user id (uuid) — see 4.1, no email resolution exists today
  comment: string | null;
}

interface VerificationSummary {
  id: string;
  result: "RESOLVED" | "NOT_RESOLVED";
  threatContained: boolean;
  spreadDetected: boolean;
  iocRecurrence: boolean;
  matchingEvents: number | null;
  notes: string | null;
}
```

### 4.1 `recipient` is role-only, on purpose — and a genuine gap this surfaces

No use-case in the pipeline currently has access to a real email address.
`Approval.requestedTo` exists in the schema but is **never set** (confirmed
dead in the earlier audit); `decidedBy`/`assignedTo`/`verifiedBy` are all
user **ids**, not emails; there is no "get user email by id" call anywhere
in these use-cases. So the contract deliberately stops at `recipient.roles`
— **role → email resolution is a delivery-config concern, not a Policy
decision**, and the natural place for it is a small static map n8n (or a
tiny backend config) owns, e.g.:

```
MANAGER_EMAIL=manager@soar-platform.local
IR_TEAM_EMAIL=irteam@soar-platform.local
SOC_EMAIL=soc@soar-platform.local
```

This keeps "who is authorized" (backend, real, already built) separate from
"what's their email today" (ops config, changes without a deploy) — matches
your own architecture note that n8n must never decide *who* approves; it's
only ever resolving a role the backend already assigned into a mailbox.

### 4.2 New env var needed

`VIGIX_BASE_URL` does not exist yet (checked — no `.env`/`.env.example` has
it). Needed for the `links.*` fields. Proposed default:
`VIGIX_BASE_URL="http://localhost:5173"`.

---

## 5. Per-event specification

For each event: exact trigger point (file + condition), recipient, and
which base-envelope fields are populated (with source noted). Then §6 has
the email template for each.

### `APPROVAL_REQUIRED`

- **Trigger**: `RequestApprovalUseCase.execute()`, right after
  `approvalRepository.create()` succeeds — i.e. `policyResult.approvalRequired === true`.
  ([RequestApproval.usecase.ts:46](../../apps/backend/src/application/approval/use-cases/RequestApproval.usecase.ts))
- **Recipient**: `[approval.approvalRole]` — dynamic, real (currently always
  resolves to `MANAGER` per today's seeded Policy rules, but read from the
  field, not hardcoded).
- **In scope already** (no extra fetch needed): `recommendation` (with
  steps), `incidentContext`, `riskScore`, the just-created `approval`.
- **Needs no extra fetch** — everything for this event's payload is already
  loaded in this use-case.
- **Not populated**: `ticket` (no ResponsePlan exists yet — see §2.2).

### `APPROVAL_APPROVED` / `APPROVAL_REJECTED`

- **Trigger**: `DecideApprovalUseCase.execute()`, branch on `input.status`.
  ([DecideApproval.usecase.ts:42](../../apps/backend/src/application/approval/use-cases/DecideApproval.usecase.ts))
- **Recipient**: `APPROVED → [IR_TEAM]`, `REJECTED → [SOC]`. **Both are
  fixed conventions, not derived from data** — Approval has no
  "who requested this" field to route back to (only the dead
  `requestedTo`), and no "who should execute next" field either. Flag this
  for your sign-off: if you'd rather route differently, it's a one-line
  change in the dispatcher, not a schema change.
- **In scope already**: `approval` only (id, recommendationId, role,
  status, decidedBy, comment).
- **Needs an extra fetch**: this use-case does **not** currently load the
  Recommendation or Incident — the dispatcher will need one extra
  `recommendationRepository.findById(approval.recommendationId)` call (and
  from that, `recommendation.incidentId`) to populate `incident` and
  `recommendation` in the payload. Small, read-only, no behavior change to
  the use-case's own decision logic.
- **Not populated**: `ticket` (same reason as above — still no ResponsePlan
  reference on a recommendation-level Approval in today's flow).

### `RESPONSE_ASSIGNED`

- **Trigger**: `CreateResponsePlanUseCase.execute()`, unconditionally after
  `responsePlanRepository.create()` succeeds (mirrors the existing
  `"RESPONSE_PLAN_CREATED"` audit action 1:1 — fires whether or not approval
  is still pending, since "assigned" and "ready to execute" are different
  moments; a PENDING_APPROVAL ticket is still assigned to IR_TEAM, just not
  actionable yet).
  ([CreateResponsePlan.usecase.ts:59](../../apps/backend/src/application/response/use-cases/CreateResponsePlan.usecase.ts))
- **Recipient**: `[responsePlan.assignedRole]` — real, dynamic (Policy's
  `responsibleRole` output).
- **In scope already**: `recommendation`, the specific `step`, `action`
  (already fetched to build the ResponsePlan), `incidentContext`, the
  just-created `responsePlan`. Everything needed is already loaded — no
  extra fetch.

### `RESPONSE_COMPLETED`

- **Trigger**: `CompleteResponseUseCase.execute()`, after
  `updateStatus(..., status: "COMPLETED")` succeeds.
  ([CompleteResponse.usecase.ts:31](../../apps/backend/src/application/response/use-cases/CompleteResponse.usecase.ts))
- **Recipient**: `[SOC]` (fixed convention — same flag as §APPROVAL_REJECTED).
- **In scope already**: `response` (full ResponsePlan, including
  `executionResult`).
- **Needs an extra fetch**: this use-case doesn't load Incident or the
  Action/Runbook names — dispatcher needs `incidentRepository.findById`,
  `actionRepository.findById(response.actionId)`.

### `VERIFICATION_NOT_RESOLVED`

- **Trigger**: `CreateVerificationUseCase.execute()`, when `result === "NOT_RESOLVED"`.
  ([CreateVerification.usecase.ts:64](../../apps/backend/src/application/verification/use-cases/CreateVerification.usecase.ts))
- **Recipient**: `[SOC, IR_TEAM]`.
- **In scope already**: `incident`, `verification` — both fully loaded.

### `INVESTIGATION_REOPENED`

- **Trigger**: same use-case, inside `if (policyResult.requireNewInvestigation)`
  — a **subset** of `NOT_RESOLVED` (Policy's `RULE-V01-03` decides this, not
  every NOT_RESOLVED reopens an investigation). **Both events can fire from
  the same `CreateVerification` call** when both conditions are true — the
  dispatcher emits up to two `NotificationEvent`s from one use-case
  invocation, not one.
- **Recipient**: `[SOC, IR_TEAM]`.
- **In scope already**: `incident` (now with the freshly-incremented
  `investigationNumber`), `verification`.

---

## 6. Email templates

Plain text, `{{mustache}}` placeholders matching the field names in §3
exactly — n8n fills these directly from the JSON payload with no additional
lookup. Array fields (`stepsRequiringApproval`) are rendered with a
`{{#each}}`-style loop, shown inline below.

### APPROVAL_REQUIRED

```
Subject: [VIGIX][{{incident.priority}}] Approval Required — {{incident.id}}

VIGIX Incident Response Notification

Incident
──────────────
Incident ID:  {{incident.id}}
Title:        {{incident.title}}
Priority:     {{incident.priority}}
Risk Score:   {{incident.riskScore}}

Recommendation
──────────────
Recommendation: {{recommendation.id}} (#{{recommendation.recommendationNumber}})
Summary: {{recommendation.summary}}

Steps requiring approval:
{{#each recommendation.stepsRequiringApproval}}
  - {{this.title}} — {{this.action.name}} ({{this.action.code}}){{#if this.target}} → {{this.target}}{{/if}}{{#if this.runbook}} [{{this.runbook.code}}]{{/if}}
{{/each}}

Approval
──────────────
Required Role: {{approval.role}}
Reason: {{approval.reason}}

Please review and make a decision in VIGIX.

Open Approval:
{{links.approval}}
```
(No "Execute" button — matches your instruction; the only action offered is opening the Approval page.)

### APPROVAL_APPROVED

```
Subject: [VIGIX] Approved — {{incident.id}}

VIGIX Incident Response Notification

Incident: {{incident.id}} — {{incident.title}}
Recommendation: {{recommendation.id}} — {{recommendation.summary}}

Approval
──────────────
Status: APPROVED
Decided By: {{approval.decidedBy}}
Comment: {{approval.comment}}

This recommendation is now approved. A response ticket will be created for IR Team execution.

Open Approval:
{{links.approval}}
```

### APPROVAL_REJECTED

```
Subject: [VIGIX] Rejected — {{incident.id}}

VIGIX Incident Response Notification

Incident: {{incident.id}} — {{incident.title}}
Recommendation: {{recommendation.id}} — {{recommendation.summary}}

Approval
──────────────
Status: REJECTED
Decided By: {{approval.decidedBy}}
Reason for rejection: {{approval.comment}}

Please review the recommendation and evidence, and consider next steps.

Open Approval:
{{links.approval}}
```

### RESPONSE_ASSIGNED

```
Subject: [VIGIX] Response Assigned — {{ticket.id}}

VIGIX Incident Response Notification

Incident
──────────────
Incident ID: {{incident.id}}
Priority: {{incident.priority}}

Ticket
──────────────
Ticket ID: {{ticket.id}}
Action: {{ticket.action.name}} ({{ticket.action.code}})
Target: {{ticket.target}}
{{#if ticket.runbook}}Runbook: {{ticket.runbook.code}}{{/if}}
Assigned Team: {{ticket.assignedRole}}
Status: {{ticket.status}}

Please perform the response manually and record the execution result in VIGIX.

Open Response Ticket:
{{links.ticket}}
```

### RESPONSE_COMPLETED

```
Subject: [VIGIX] Response Completed — {{ticket.id}}

VIGIX Incident Response Notification

Incident: {{incident.id}}
Ticket: {{ticket.id}}
Action: {{ticket.action.name}}
Target: {{ticket.target}}

Status: COMPLETED

Next Step: Verification required before this incident can be considered resolved.

Open Response Ticket:
{{links.ticket}}
```
(Execution result deliberately not inlined verbatim in the email — it's
free-text/JSON the human typed, shown in full on the Ticket Detail page
instead of risking an unformatted dump in an email body. Open the link to see it.)

### VERIFICATION_NOT_RESOLVED

```
Subject: [VIGIX] Verification NOT RESOLVED — {{incident.id}}

VIGIX Incident Response Notification

Incident: {{incident.id}} — {{incident.title}}

Verification Result: NOT RESOLVED
──────────────
Threat Contained: {{verification.threatContained}}
Spread Detected: {{verification.spreadDetected}}
IOC Recurrence: {{verification.iocRecurrence}}
Matching Events: {{verification.matchingEvents}}
Notes: {{verification.notes}}

This incident is not yet resolved. Review the evidence and continue investigation.
```
(No `links.ticket`/`links.approval` guaranteed present for this event — omit the "Open" line if neither link exists in the payload.)

### INVESTIGATION_REOPENED

```
Subject: [VIGIX] Investigation #{{incident.investigationNumber}} Reopened — {{incident.id}}

VIGIX Incident Response Notification

Incident: {{incident.id}} — {{incident.title}}

Investigation #{{incident.investigationNumber}} has been opened for this incident,
based on verification evidence indicating the threat is not fully contained.

A new recommendation will be generated for this investigation cycle.
```

---

## 7. Full real payload — worked example

Using the actual seeded/tested data from this session's live verification
(`INC = aa4ff565-...`, `REC #2 = 35737293-...`, `ResponsePlan =
d30f0ef5-...`), for `RESPONSE_ASSIGNED`:

```json
{
  "eventType": "RESPONSE_ASSIGNED",
  "eventId": "c1a2e3f4-0000-4000-8000-000000000001",
  "timestamp": "2026-09-17T14:49:13.812Z",
  "tenantId": "00000000-0000-0000-0000-000000000001",
  "recipient": { "roles": ["IR_TEAM"], "channels": ["email", "discord", "telegram"] },
  "incident": {
    "id": "aa4ff565-ea23-4d1a-8a18-8c0a1b4a9b43",
    "title": "Suspicious PowerShell execution on WKS-DEMO-01",
    "priority": "high",
    "riskScore": null,
    "investigationNumber": 1
  },
  "ticket": {
    "id": "d30f0ef5-1ee5-40cb-b01b-24b8726ad60e",
    "status": "READY_FOR_EXECUTION",
    "action": { "code": "ACT-BLOCK-SOURCE-IP", "name": "Block Source IP" },
    "target": "203.0.113.55",
    "runbook": { "code": "RB-NETWORK-001" },
    "assignedRole": "IR_TEAM"
  },
  "links": {
    "ticket": "http://localhost:5173/tickets/d30f0ef5-1ee5-40cb-b01b-24b8726ad60e"
  }
}
```
(`riskScore: null` here is honest — no `RiskScore` row exists for this demo
incident, matching what the live system actually returned.)

---

## 8. What Phase N2 needs to build against this contract

Not implemented in this phase (spec only) — listed here so N2's prompt can
reference this document instead of re-deriving it:

1. `NotificationEvent` type + the 7 payload-builder functions (one per
   event, per §5's "in scope already" / "needs extra fetch" notes).
2. `INotificationDispatcher` port + `N8nNotificationDispatcher` — reuses the
   existing `N8nWorkflowEngineAdapter` pattern (same `fetch()` + `X-N8N-API-KEY`
   header shape), new webhook path e.g. `soar/notification`.
3. One `dispatcher.emit(event)` call added next to each use-case's existing
   `auditLogger.record(...)` call (7 call sites — no restructuring, as the
   earlier audit confirmed all 7 use-cases already inject `AuditLogger` the
   same way).
4. `VIGIX_BASE_URL` env var.
5. Failure handling matching the existing `OrchestratorCallbackController`
   precedent: a dead/unreachable n8n must never fail the underlying
   Approval/Response/Verification call — log and continue, exactly like
   that controller already does.

Nothing here touches Policy/Approval/Response/Verification *decision*
logic — every insertion point is "after the real decision already
happened, emit a description of it."

---

## 9. Multi-channel delivery (N3.5)

Extends the envelope (not a redesign) so one event can be delivered over
Email, Discord, and Telegram, while keeping the same separation of
concerns: **backend decides who (`roles`); n8n decides how (`channels`) and
actually delivers.**

```
VIGIX Backend
      ↓
NotificationEvent  (recipient.roles + recipient.channels)
      ↓
n8n Webhook
      ↓
Validate event
      ↓
Render template (per event type)
      ↓
Role → Channel → credential mapping   (n8n-side, config-driven)
      ↓
 ┌────────┬──────────┬───────────┐
 ▼        ▼          ▼
Email   Discord   Telegram
```

### 9.1 Contract addition

```ts
export type NotificationChannel = "email" | "discord" | "telegram";

recipient: {
  roles: NotificationRole[];
  channels: NotificationChannel[];  // NEW — backend always sends all three today (no per-event-type channel preference logic exists yet, so this is honestly "try all three," not a fabricated distinction)
};
```

`channels` is never an authorization signal — a role that has zero channels
configured (e.g. `SOC_DISCORD_WEBHOOK` unset) simply doesn't receive that
channel; it does not change whether SOC is a valid recipient for the event.

### 9.2 Config (n8n-side only — never in backend source or the contract)

Nine env vars total, following the exact `infra/docker/docker-compose.yml`
pattern already used for `N8N_URL`/`JIRA_*`/`TEAMS_WEBHOOK_URL`
(`${VAR:-default}`, empty-by-default, gitignored `infra/docker/.env` for
real overrides):

```
MANAGER_EMAIL             MANAGER_DISCORD_WEBHOOK             MANAGER_TELEGRAM_CHAT_ID
IR_TEAM_EMAIL             IR_TEAM_DISCORD_WEBHOOK             IR_TEAM_TELEGRAM_CHAT_ID
SOC_EMAIL                 SOC_DISCORD_WEBHOOK                 SOC_TELEGRAM_CHAT_ID
```

The 3 `*_EMAIL` vars already existed (N3); the 6 `*_DISCORD_WEBHOOK`/
`*_TELEGRAM_CHAT_ID` vars are new, empty by default. n8n's own "determine
enabled channels" step is: `event.recipient.channels ∩ {channel : that
role's env var for that channel is non-empty}` — so a channel absent from
config is never attempted regardless of what the payload requested.

### 9.3 Per-channel presentation, same underlying event

All three channels read the exact same `NotificationEvent` — only the
rendering differs (Email keeps the box-drawing plain-text style from §6;
Discord/Telegram want shorter, chat-native text). As of N3.5, only
`RESPONSE_ASSIGNED` has hand-written Discord/Telegram-specific renderers;
the other 6 events reuse their existing §6 email body as a plain-text
fallback for all three channels until their own channel-specific templates
are written in a later phase — noted here so nobody assumes all 21
(7 events × 3 channels) presentations already exist.

**RESPONSE_ASSIGNED — Discord** (markdown, `**bold**` headers):
```
**[VIGIX] Response Assigned — {{ticket.id}}**
Incident `{{incident.id}}` · Priority **{{incident.priority}}**
Action: **{{ticket.action.name}}** ({{ticket.action.code}}){{#if ticket.target}} → `{{ticket.target}}`{{/if}}
Assigned: {{ticket.assignedRole}} · Status: {{ticket.status}}
<{{links.ticket}}>
```

**RESPONSE_ASSIGNED — Telegram** (plain, short — Telegram's default parse
mode has no headers):
```
🔔 VIGIX — Response Assigned
Ticket: {{ticket.id}}
Incident: {{incident.id}} ({{incident.priority}})
Action: {{ticket.action.name}}{{#if ticket.target}} → {{ticket.target}}{{/if}}
Team: {{ticket.assignedRole}} | Status: {{ticket.status}}
{{links.ticket}}
```

### 9.4 Still no real send

n8n's workflow renders per-channel output and reports which channels are
actually enabled/configured for the resolved roles — it does not yet call
a real SMTP/Discord/Telegram API. That's N4, deliberately deferred until
real credentials exist to test against.
