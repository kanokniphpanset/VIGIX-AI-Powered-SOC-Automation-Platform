# Policy Engine module

> **Update 2026-09-25 — Severity is the primary classification; Risk Score is retired from decisions.**
> Policy now evaluates the incident **severity** (analyst-validated) plus asset criticality and action impact.
> The risk-score rules (RULE-R01..R04, RULE-P08, RULE-P10) are disabled (rows kept for history), the engine never
> matches a `riskScore` condition, and no risk score is produced, sent or displayed. Canonical rules:
> `apps/backend/prisma/seeds/policy.seed.ts`. Statements about risk score / risk level below are historical.

Implements the VIGIX Policy Engine design doc as a Clean-Architecture
module: Priority / Assignment rules from Severity + Risk Score, a separate
Approval/Review policy, and Verification override rules that reopen the
investigation loop without ever auto-triggering a Response.

## Layout

```
policy/
├── domain/
│   ├── entities/            Policy, PolicyRule, PolicyCondition, PolicyEvaluationTypes
│   └── repositories/        IPolicyRepository (port)
├── application/
│   ├── dto/                 Create/Update/Evaluate DTOs + validation
│   └── use-cases/           One class per action (CreatePolicy, EvaluatePolicy, ...)
├── infrastructure/
│   ├── repositories/        PrismaPolicyRepository (adapter)
│   └── policy-engine/       PolicyMatcher, PolicyPrecedence, PolicyEvaluator
├── presentation/
│   ├── controllers/, routes/, validators/   HTTP layer
└── seeds/
    └── policy.seed.ts       The 14 rules transcribed from the design doc
```

Domain and application code depend only on `IPolicyRepository`, never on
Prisma directly — same convention as the rest of this codebase
(`IIncidentRepository`, `IAlertRepository`, etc.).

## What the engine actually does

`PolicyEvaluator.evaluate(policies, input)`:
1. Filters to enabled policies, sorted by `precedence` ascending.
2. For each policy's enabled rules, runs `PolicyMatcher.matches(condition, input)`
   — a plain switch over `eq/neq/gte/lte/gt/lt` and `all`/`any` nesting.
   Conditions are pure data (JSON), never executable code.
3. Merges every matched rule's `PolicyResultFragment` via `PolicyPrecedence.merge()`.

The merge strategy (documented in full in `PolicyPrecedence.ts`) is:
- `priority` / `responsibleRole` / `reviewRole` / `approvalRole`: most severe /
  highest-authority match wins (P0 beats P3; IR_TEAM beats SOC).
- Every boolean flag (`approvalRequired`, `reviewRequired`, `highRiskReview`,
  `requireEscalation`, etc.): OR'd — true if *any* matched rule requires it.
- `approvalReason`: deduped union across all matched rules.
- `firstResponseSlaMinutes` / `resolutionSlaMinutes`: **minimum** across
  matched rules (the stricter deadline wins).

None of this is a fixed law — it's the one place a re-tune belongs if your
org's rules should merge differently.

## Design decisions carried over from the doc (deliberately enforced by types)

- **Severity ≠ RiskLevel ≠ Priority.** `PolicyEvaluationInput.severity` is
  read-only input; `riskScore` never overwrites it. A HIGH-severity,
  risk-92 incident stays `Severity=HIGH / RiskLevel=CRITICAL / Priority=P0`
  — three independent fields, never collapsed (see `PolicyEvaluationTypes.ts`).
- **Assignment ≠ Approval.** `responsibleRole` (who owns the case) and
  `approvalRequired`/`approvalRole` (who must sign off) are separate fields,
  set by separate policies (`priority-by-severity` vs `approval-and-review`
  in the seed data) — matching the doc's "2 ตาราง" split.
- **Verification never auto-triggers Response.** The `verification-override`
  policy only ever sets `requireNewInvestigation` / `requireEscalation` /
  `requireAdditionalEvidence` / `incidentStatus` — never `responseRequired`.
  The loop is Verification → Investigation #2 → Recommendation #2 → Decision
  → Approval (if required) → Response, enforced by keeping that decision out
  of the engine's hands entirely.
- **`investigationNumber += 1` is not a PolicyResultFragment field.** It's an
  Incident-level counter; whichever use-case applies a matched
  `requireNewInvestigation` result to an Incident owns incrementing it. The
  Policy Engine only returns the flag, per `policy.seed.ts`'s own comment.

## Seed data coverage

`seeds/policy.seed.ts` implements 15 rules (RULE-001 through RULE-015) drawn
straight from the doc's tables:
- RULE-001–008: the Priority table (severity + risk score → P0–P3).
- RULE-009–011: the Verification override table.
- RULE-012–014: the Approval Policy table (Critical+CriticalAsset →
  IR approval; high-impact action → IR approval; HIGH/CRITICAL → IR review).
- RULE-015: the doc's own worked example in section 9 — HIGH severity
  (not CRITICAL, so RULE-012 alone doesn't cover it) + a critical asset +
  a high-impact action (e.g. isolate-production-server) together require
  IR approval. Three-level nested `all`/`any` condition.

The doc's own scratch comment mentions "POL-001..017" as a placeholder from
an earlier draft; rather than pad the count with invented rules, this seed
only encodes what the doc actually specifies. Extending it (e.g. per-attack
Playbook conditions) is additive — see the doc's own note: *"ยังไม่ต้องสนใจ
ว่า Incident คือ Brute Force, Malware, Ransomware หรือ MITRE อะไรเลย
แล้วค่อยเพิ่มเงื่อนไขพวกนั้นใน Policy Layer ภายหลัง"*.

## Assumptions that need your confirmation

These weren't specified anywhere shared with me, so I made the most
reasonable, easiest-to-swap choice and flagged it inline. Search this
folder for `ASSUMPTION` to find every spot:

1. **HTTP framework: Express.** `presentation/` assumes `Request`/`Response`
   from `express` and `req.tenantId` set by upstream auth middleware. If
   this project uses Fastify/Nest/Koa, only the 4 files under
   `presentation/` need rewriting — nothing else references them.
2. **ORM: Prisma**, with models named `policy` / `policyRule`, a
   `policyId` foreign key, and `condition`/`result` as `Json` columns.
   `PrismaPolicyRepository.ts` is a best-effort scaffold against that
   shape — point it at your actual `schema.prisma` and adjust the four
   `this.prisma.policy.*` calls and the two `toDomain*` mappers.
3. **Precedence semantics**: ascending `precedence` number = evaluated
   first / considered "more authoritative" when policies of the same type
   would otherwise both set a field the merge has to pick a winner for.
