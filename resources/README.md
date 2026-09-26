# VIGIX Resource System

This folder is the **single source of truth** for content that used to be
hardcoded inside TypeScript/Python source files — prompts, policies, and
(eventually) response actions, rules, templates, and knowledge assets. It's
shared by both `apps/backend` (TypeScript) and `apps/ai-orchestrator`
(Python); each app has its own loader that reads from here, so there is
never a second copy of the same content to keep in sync.

## Why this exists

Before this system, things like "what risk score triggers auto-response?"
or "what does the LLM say when summarizing an alert?" lived inside `.py`/
`.ts` files. Changing them meant editing code, reviewing a code diff, and
redeploying the app. Now they're files right here — YAML, Markdown, or
JSON, whichever fits the content — that get loaded when the app starts
(and can be hot-reloaded without a restart, see below). Changing a policy
threshold or a prompt's wording is a pull request against a data file, not
a code change.

## How to add a new prompt (no code required)

1. Go to `resources/prompts/<agent-name>/`.
2. Create a new `.md` file. Every prompt file looks like this:

   ```
   ---
   id: my-agent.my-prompt
   version: "1"
   variables: [alert_text, risk_score]
   description: One line explaining what this prompt is for.
   ---
   Everything below the second `---` is the actual prompt text. Use
   {alert_text} and {risk_score} anywhere you want those values inserted.
   ```

3. `id` must be unique across every prompt file in the whole `resources/prompts/` tree.
4. `variables` lists every `{placeholder}` your prompt text uses — the loader
   will refuse to render the prompt if a caller forgets to supply one of them.
5. Save the file. If the app is running with hot-reload enabled, it picks up
   the new prompt within a few seconds — otherwise, restart the app.
6. Open a pull request like you would for any other change. A teammate can
   read the prompt text directly in the diff — no code review needed to
   understand what changed.

## How to add or change a policy (no code required)

1. Go to `resources/policies/`.
2. Open `incident-response-policy.yaml` (or create a new one — see below)
   and edit the values. Every field is commented with what it controls and
   what values are valid.
3. To add a *second* policy (e.g. a stricter one for a specific tenant),
   copy the file, give it a different `id`, and change the values — the
   application code that reads policies (`ResourcePolicyConfigProvider`,
   see below) picks a policy by `id`.
4. Save and open a pull request the same way as a prompt change.

## How to add or change an asset's criticality tier (no code required)

1. Go to `resources/assets/asset-criticality-catalog.yaml`.
2. Add an entry under `assets:` with the host's `hostname` and/or `ip` (as
   seen in that SIEM's `agent` block) and a `tier` (`tier1_critical` |
   `tier2_high` | `tier3_medium` | `tier4_low`).
3. Anything not listed falls back to `default_tier` — change that if the
   whole environment's baseline should shift.
4. Save and restart the AI orchestrator (or call
   `AssetCriticalityLoader.reload()`). This tier feeds both MlRiskAgent's
   weighted risk score and DecisionAgent's Tier 3 policy floor — see
   `resources/assets/README.md` for the full consequence of a tier change.

## Folder guide

| Folder | Status this phase | What it holds |
|---|---|---|
| `prompts/` | **Live** | LLM prompt templates. `llm-analyst/` is fully migrated from the old `llm_analyst_agent/prompts.py`. |
| `policies/` | **Live** | Incident-response policy config, read by DecisionAgent's PolicyEngine. |
| `assets/` | **Live** | Host → business-criticality catalog, read by MlRiskAgent's weighted risk score and DecisionAgent's Tier 3 policy floor. |
| `response-actions/` | Scaffolded, empty | Future home of the Response Action Catalog (currently hardcoded in `decision_agent/action_catalog.py`) — deferred to Phase 8. |
| `rules/mitre/` | Scaffolded, empty | Future home of MITRE detection rules (currently hardcoded TypeScript classes) — deferred to Phase 3b. |
| `playbooks/` | Placeholder | Not migrated this phase — see note below. |
| `templates/` | Placeholder | Not populated this phase. |
| `workflow-templates/` | Placeholder | The real n8n workflow JSON files already live at `automation/n8n/workflows/` (already file-based/git-versioned) — see that folder's own README. Consolidating them here is a later decision, not an urgent gap. |
| `knowledge/` | Placeholder | The real Incident Response Knowledge Base already lives at `apps/backend/data/knowledge/` (already file-based/git-versioned) — see this repo's root README's "Knowledge Base & RAG Agent module" section. Consolidating it here is a later decision, not an urgent gap. |
| `reports/` | Placeholder | Not populated this phase. |
| `dashboard/` | Placeholder | Not populated this phase. |
| `parsers/` | Placeholder | Not populated this phase. |
| `mappings/` | Placeholder | Not populated this phase. |
| `schema/` | Reference only | See `schema/README.md` — explains why the runnable validation code lives per-app rather than here. |

## How loading actually works (for engineers)

- **Files are the source of truth this phase** — not a database. Every
  resource is plain text, versioned in git, reviewable in a PR like code.
- Each app has its own loader reading this shared tree:
  - Python: `apps/ai-orchestrator/resources/{resource_loader,prompt_loader,policy_loader}.py`
  - TypeScript: `apps/backend/src/shared/resources/{ResourceLoader,PromptLoader,PolicyLoader,RuleLoader}.ts`
- Every loader implements the same three-method contract — `getAll()` /
  `get_all()`, `getById()` / `get_by_id()`, `reload()` — on purpose: a
  future database-backed or remote-config provider can implement the same
  contract and swap in without any calling code changing.
- **Hot-reload is opt-in**, not automatic. Python loaders have
  `start_watching()`/`stop_watching()` (via `watchdog`); TypeScript loaders
  have the same (via `chokidar`). Nothing currently calls these at process
  startup — a future phase can wire that into each app's startup hook once
  hot-reload in production is actually wanted. Until then, changing a file
  takes effect on the next `reload()` call or app restart.
- Every resource file is validated against a schema before it's accepted —
  see `schema/README.md`. A malformed file makes the loader raise loudly
  (not silently skip it), so a broken YAML/Markdown file is caught
  immediately, not discovered later at 2am.

## What's still hardcoded (not this phase)

See each area's own README for specifics:
- `resources/response-actions/README.md` — Response Action Catalog, deferred to Phase 8.
- `resources/rules/mitre/README.md` — MITRE detection rules, deferred to Phase 3b.

Both have a `// TODO` / `# TODO` comment in the source file that currently
hardcodes them, pointing back here.
