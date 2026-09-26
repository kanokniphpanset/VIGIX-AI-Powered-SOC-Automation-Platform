# VIGIX Recommendation → Response → Verification Flow

This document describes the actual, implemented, tested state of the
Recommendation/Response workflow in `apps/backend` as of this writing. It
does not describe aspirational or partially-built behavior — anything
marked "not implemented" below genuinely has zero code behind it.

## 1. Principle: human-in-the-loop

AI never approves, executes, modifies Policy, invents evidence/Action
IDs/Runbook IDs, or declares an incident resolved. The backend is
authoritative for validation, policy evaluation, permission, assignment,
approval requirements, SLA, state transitions, persistence, and audit. IR
Team executes manually and records results. Verification determines
RESOLVED/NOT_RESOLVED from Wazuh re-hunt evidence, never from AI or from a
caller-supplied flag.

## 2. End-to-end flow

```
Alert → Incident (existing, pre-dates this work)
  ↓
Investigation (Incident.investigationNumber; no separate Investigation table)
  ↓
Evidence (ThreatIntelIoc, MitreMapping — existing tables, read-only here)
  ↓
RecommendationContextBuilder assembles RecommendationContextDto
  (Incident+Alert facts, IOCs, MITRE mappings, ENABLED Actions, ACTIVE Runbooks —
   nothing fabricated; missing data is left empty, never invented)
  ↓
RecommendationAgent (FakeRecommendationAgent today — see §4) proposes
  RAW, UNVALIDATED candidate steps referencing action/runbook CODES
  ↓
RecommendationValidator re-resolves every code against the REAL Action/Runbook
  repositories, strips fabricated evidence, downgrades unsupported steps to
  investigation-only (RULE-001..015 — see §5)
  ↓
Recommendation + RecommendationStep rows persisted (VALIDATED or INVALID —
  a rejected candidate is still recorded, never silently discarded)
  ↓
SOC reviews the recommendation and clicks Send to IR (SendRecommendationToIr):
  for every action step, CreateResponsePlan creates the Response Ticket FIRST
  (PENDING_IR_DECISION, assignedRole IR_TEAM, Policy evaluated for the reason
  tags), opens the single IR_TEAM approval, THEN emails / notifies IR with the
  ticket link
  ↓
IR_TEAM decides APPROVE or REJECT — a note is mandatory for both; admin can
  never stand in. REJECT: ticket REJECTED, reason stored + audited, nothing runs
  ↓
StartResponse — IR_TEAM records that manual execution has begun.
  Blocks if approval is still PENDING/REJECTED. No shell/API/n8n call
  exists anywhere in this path — "start" is a status update, not an action.
  ↓
CompleteResponse / FailResponse — IR_TEAM records the real-world result
  ↓
CreateVerification — IR_TEAM records Wazuh re-hunt evidence
  (threatContained, spreadDetected, iocRecurrence, matchingEvents, ...).
  `result` is DERIVED, never accepted as input:
    RESOLVED  iff threatContained AND !spreadDetected AND !iocRecurrence
              AND matchingEvents == 0
    otherwise NOT_RESOLVED
  ↓
Policy re-evaluated with {verificationResult, spreadDetected, threatContained}
  ↓
  requireNewInvestigation=true → Incident.investigationNumber += 1
    (Investigation #2 begins; audited as INVESTIGATION_REOPENED)
  result=RESOLVED → Incident.status = "resolved"
  ↓
Next GenerateRecommendation call automatically reads the bumped
  investigationNumber and builds a FRESH context from whatever evidence
  exists NOW — Recommendation #2 never copies Recommendation #1's rows
  (enforced by RecommendationRepository.supersedePrevious + a fresh
  RecommendationContextBuilder.build() call every time)
```

Verified live end-to-end (see conversation record / test suite) including
the NOT_RESOLVED → Investigation #2 → new-evidence → Recommendation #2 →
RESOLVED loop, and the spreadDetected-forces-NOT_RESOLVED-even-when-contained
case.

## 3. Module boundaries

| Concept | Owns | Never |
|---|---|---|
| **Policy** | priority, assignment, approval requirement, SLA, escalation/verification-failure handling | attack-specific rules, severity mutation |
| **Playbook** (`STC-001`) | the generic 7-stage lifecycle | naming a specific Action or Runbook |
| **Action** | the allowlist of executable actions (code, enabled, impactLevel) | being trusted as the final approval authority (`defaultApprovalRequired` is a catalog hint only) |
| **Runbook** | attack-specific technical procedure (may reference Action codes in prose) | being copied wholesale into a Recommendation |
| **Recommendation** | case-specific candidate steps, evidence-traced, catalog-bound | inventing evidence/action/runbook, approving, executing |
| **Approval** | the one human decision gate, role sourced from Policy | being created when Policy says approval isn't required |
| **Response** | tracking manual execution state | ever executing anything itself |
| **Verification** | deriving RESOLVED/NOT_RESOLVED from evidence | accepting `result` as direct input |

## 4. AI integration boundary (verified, not assumed)

- `IRecommendationAgentPort` — the only interface a "recommendation agent"
  implements. It receives a `RecommendationContextDto` and returns raw,
  unvalidated candidate JSON. Nothing more.
- `FakeRecommendationAgent` — the **currently wired** implementation.
  Fully deterministic, zero LLM/RAG/MITRE/ML-risk logic of its own. Every
  field traces to a value already in the context (an IOC value, a MITRE
  technique id, or the incident title).
- `LlmRecommendationAgent` — an HTTP adapter to `apps/ai-orchestrator`,
  written but **not wired into `container.ts`**. `apps/ai-orchestrator`
  does not yet expose the narrow `POST /recommendations/generate` endpoint
  this class calls. This is honestly incomplete, not a hidden stub —
  `container.ts` binds `FakeRecommendationAgent` today.
- `apps/ai-orchestrator`'s own Python `recommendation_agent` (LangGraph
  node, pre-existing) is untouched and bound to a different, older Action
  Catalog (`decision_agent/action_catalog.py`, ids like `NET-001`) — it is
  architecturally separate from everything in this document.

## 5. RecommendationValidator guardrails (RULE-001–015)

Implemented in `src/infrastructure/recommendation-validation/RecommendationValidator.ts`.
See that file's own docstring for the authoritative, current rule
definitions — this doc does not duplicate them to avoid drift.

## 6. Known gaps (as of this writing)

- `LlmRecommendationAgent` has no real orchestrator endpoint to call yet.
- RBAC is a foundation (JWT + role header check), not a full identity
  system — no refresh tokens, no session revocation, no MFA.
- `Approval` has no `tenantId` column of its own (pre-existing schema
  gap); tenant isolation is enforced via a join to `Recommendation`.
- `RiskScore` has no timestamp column, so "latest risk score" is
  best-effort, not temporally guaranteed.
- The `knowledge/` documentation tree (per-Policy/Playbook/Action/Runbook/
  Recommendation reference docs) has not been written.
