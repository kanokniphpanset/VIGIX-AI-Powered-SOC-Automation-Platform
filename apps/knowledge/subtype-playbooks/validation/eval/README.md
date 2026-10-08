# Evaluation kit (offline)

Scores the real recommendation path against a **DRAFT** Ground Truth. Nothing here touches a database, a running service or an LLM, and nothing launches an attack.

| piece | where |
|---|---|
| Ground Truth (DRAFT, not IR-reviewed) | `ground-truth.draft.json` - 32 cases (19 first response, 13 after Re-hunt) with `basis` rule ids, expected actions + target parts + scope strings, prohibited actions, process checks, expected Re-hunt decisions |
| inputs per case (recorded alerts, isolated fixtures, simulated round-2 records, organization fixtures) | `apps/backend/test/eval/evalCases.ts` |
| runner (real `GenerateRecommendationUseCase` over in-memory repositories) | `apps/backend/test/eval/evalRunner.ts` |
| scoring functions (pure, unit-tested on hand-made data) | `apps/backend/test/eval/evalScoring.ts` |
| run + report | `cd apps/backend && npx jest test/SubtypeEvalKit` -> `results/latest.md`, `results/latest.json` |

Rules of the kit
- The Ground Truth is **never generated from system output** and the kit never writes it (it is hashed before and after every run; the report records the hash). A change to it must be logged in `_meta.change_log` with a reason that does not depend on the output.
- A score is a score against a DRAFT reference. IR acceptance of the file is what would make a score an acceptance result; until then `ir_reviewed` stays `false` and the report says so.
- Systems: `subtype` = enforce mode (the review override is set only inside the test); `legacy` = mode off with the deterministic `FakeRecommendationAgent`. The legacy number is **not** the production legacy path (LLM + RAG) - it only shows what the old, ungated candidate-per-playbook behaviour looks like on the same inputs. Only single-source SSH cases have a legacy context, so legacy runs on 3 + 12 cases.
- Metrics and denominators are defined in the report footer. 0/0 is printed as `n/a`, never as 100 %.
- Data classes are reported per case: RECORDED_ALERT, RECORDED_ALERT+ANALYST_ASSERTION, SYNTHETIC_FIXTURE, RECORDED_ALERT+SIMULATED_ROUND2_RECORDS. A synthetic-fixture pass is not a live-incident pass; a deterministic run is not an actual-LLM run.
