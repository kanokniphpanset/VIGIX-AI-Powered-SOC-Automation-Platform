# Resource Schemas

Every resource type has a validation schema — a prompt file must have an
`id`, a `version`, and every `{variable}` it uses declared; a policy file
must have numeric thresholds in range, etc. (See `resources/README.md` for
the full picture.)

## Why the actual schema code isn't in this folder

The original plan for this phase put the runnable Zod (TypeScript) and
Pydantic (Python) schema classes directly under `resources/schema/`,
alongside everything else in this shared tree. In practice, two real
constraints in this repo make that not work cleanly:

1. **TypeScript**: `apps/backend/tsconfig.json` sets `"rootDir": "src"` and
   `"include": ["src/**/*.ts"]`. `tsc` refuses to compile a file that
   imports something outside `rootDir` ("File is not under 'rootDir'").
   Since `resources/` lives at the repo root, well outside
   `apps/backend/src/`, a `.ts` schema file living here couldn't be
   imported by the backend's own build without either widening `rootDir`
   (a change well outside this phase's scope) or working around it in a
   way that adds fragility for no real benefit.
2. **Python**: `apps/ai-orchestrator` resolves imports like
   `from src.xxx import yyy` because `apps/ai-orchestrator` itself is on
   `sys.path`. Reaching a `.py` file living at the repo root (outside
   `apps/ai-orchestrator` entirely) would require manually appending that
   path to `sys.path` at runtime — doable, but a fragile, unusual pattern
   compared to a normal package-relative import, for two resource types.

So: the actual schema code lives per-app instead —

- Python: `apps/ai-orchestrator/resources/schema/{prompt_schema,policy_schema}.py`
- TypeScript: `apps/backend/src/shared/resources/schema/{prompt,policy,rule}.schema.ts`

Both implementations validate the **same underlying file format** — e.g.
`policy.schema.ts` and `policy_schema.py` both expect the exact snake_case
field names used in `resources/policies/incident-response-policy.yaml` (not
each language's usual naming convention), because they're validating one
shared file, not maintaining two different resource formats.

This folder is kept as the one place to look for what the contract *is*, in
plain language, even though the enforcement code sits next to each
consumer. If a resource type's shape needs to change, update the resource
files' comments and both schema implementations together.
