# MITRE Detection Rules

**Status: scaffolded only (Phase 3, item 4). No content migrated yet.**

This is the intended future home of MITRE ATT&CK detection rules —
currently 8 hardcoded TypeScript classes under
`apps/backend/src/domain/mitre/services/rule-engine/mitre-rules/*.ts`,
registered in `defaultMitreRules.ts`.

A `RuleLoader` (`apps/backend/src/shared/resources/RuleLoader.ts`) exists
and is tested, but nothing has been migrated into this folder, and
`RuleLoader` is **not** wired into `MitreRuleEngine`/`RuleRegistry` — see
`defaultMitreRules.ts`'s own `TODO(Phase 3b)` comment.

## Why full migration is deferred, and why it's harder than prompts/policies

Unlike prompts (plain text) or policies (a flat config object), each rule's
`conditions` field is **executable logic**, not data — a composable
predicate tree built from `AllOf`/`AnyOf`/`Not`/`PredicateCondition`
classes (see `IMitreRule.ts`, `IRuleCondition.ts`). For example,
`EncodedPowerShellExecutionRule` evaluates a `PredicateCondition` closure
against the alert context, not a lookup value.

Externalizing that into a YAML/JSON file means designing a **declarative
condition DSL** the loader can parse and turn back into something
`RuleEvaluator` can execute — e.g. `{"anyOf": [{"keyword": "powershell"},
{"regex": "..."}]}` — and building an interpreter for it. That's real
design work, not a data move, which is why it's out of scope for a
scaffolding-only phase.

`RuleLoader`'s current schema (`resources/schema/rule.schema.ts`)
validates a rule's static metadata (`id`, `name`, `description`,
`techniqueId`, `tactic`, `confidenceWeight`) but leaves `conditions` typed
as `unknown` — a placeholder, not a real condition format.

## What Phase 3b will need to do

1. Design the condition DSL and its schema.
2. Build the interpreter that turns parsed condition data into an
   `IRuleCondition<MitreRuleContext>` instance `RuleEvaluator` can run.
3. Confirm nothing outside `defaultMitreRules.ts` imports the 8 rule
   classes directly before removing them (search first).
4. Move the 8 rules into `resources/rules/mitre/*.yaml`, wire
   `RuleLoader` into `createDefaultMitreRuleEngine()`, delete the 8 files
   and the hardcoded array in `defaultMitreRules.ts`.
