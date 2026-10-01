# VIGIX additional evaluation — reproducibility notes

Adds only the evidence missing from the frozen Real Wazuh evaluation: **(A)** a controlled procedural baseline, **(B)** recommendation consistency, **(C)** negative / reject-path validation, plus paper tables, datasets, figures and text. Nothing from the frozen evaluation was re-run or changed (see *Integrity* below). No secrets, API keys or `.env` files are stored here.

## What is frozen and how that was checked
`frozen-manifest.json` (written before anything ran) holds the sha256 of 31 files (`results/**` except this folder, and the three evaluation source files `groundTruth.ts`, `groundTruthReal.ts`, `EvaluationService.ts`) plus row counts of the frozen database `soar_eval`. `frozen-verification.json` (written at the end) shows: **0 of 31 files changed**, `soar_eval` row counts identical, policy / playbook / MITRE counts unchanged, development database `soar_platform` unchanged (260 alerts / 39 incidents). The 17 numbers of the Clean/Intervention runs quoted in `paper-metrics.json` are checked against `results/evaluation-audit.json` by `build-paper-outputs.ts`, which stops if any differs (17/17 identical).

## Database, services, environment
| Item | Value |
|---|---|
| Frozen evaluation database | `soar_eval` — read only, never written; backup `backups/db/soar_eval-frozen-before-additional-20260930.sql` (git-ignored) |
| Database used here | `soar_addl_eval` — a clone restored from that backup (19 alerts / 19 incidents, 29 policies, 11 playbooks). Scripts refuse to run against any other database name. Not the production/development database `soar_platform`. |
| AI orchestrator | second instance on `:8001` bound to `soar_addl_eval` (stopped afterwards) |
| LLM actually used | `vllm-spark-01/gemma4-26b-uncensored` on a self-hosted OpenAI-compatible vLLM endpoint — see `CORRECTIONS.md` |
| Wazuh | manager / indexer / dashboard 4.9.2 (Docker), agent 4.9.2 on `attack-endpoint`; the additional evaluation **read** the Wazuh Indexer (baseline evidence collection) and did **not** modify any Wazuh rule, decoder, agent or index |
| Alerts | the alerts of the frozen Clean Run v2 (same Wazuh documents); no new attack was generated |
| Recommendation agent | production-parity wiring (`responseSetup` + ACTION_COMPLIANCE policies), `LlmRecommendationAgent` |

## Cases and repetitions
- Baseline: 9 evaluable cases (TC-01, 02, 03, 04, 06, 07, 08, 09, 10); TC-05 unavailable, not fabricated.
- Consistency: TC-01, TC-02, TC-04, TC-06, TC-07, TC-09 × **5 repetitions** = 30 runs, identical evidence snapshot per case (context hash identical in every repetition), nothing persisted.
- Negative validation: 10 controlled invalid recommendations + 17 governance/human-decision checks.

## Timestamps (UTC, 2026-09-30)
| Step | Start → end |
|---|---|
| Baseline | 12:49:32.515 → 12:49:32.743 (9 cases) |
| Negative validation | 12:51:46.079 → 12:51:46.454 |
| Consistency, attempt 1 (6 cases × 5) | 12:48:47 → 13:01:56 — TC-09's 5 calls failed: LLM endpoint timeout / connection error |
| Consistency, TC-09 re-run during the outage | 13:02:38 → 13:02:52 — 5 failures, same cause |
| Consistency, TC-09 re-run after the endpoint returned | 13:06:01 → 13:09:53 — 5 validated runs |

The 10 calls that failed because the LLM endpoint was unreachable are **excluded from the consistency denominator but listed** in `data/consistency.json` (`excluded_infrastructure_failures`) and all attempt files are kept. They are availability failures of the model server, not recommendation inconsistency, and are not reported as "0% consistency".

## Commands (from the repository root; Git Bash)
```bash
# 0. safety: frozen manifest + backup + clone (see the task log); then the eval process environment
cd apps/backend
EVAL_DB=soar_addl_eval bash scripts/eval/eval-env.sh start-orchestrator      # separate shell/background
EVAL_DB=soar_addl_eval . scripts/eval/eval-env.sh                              # exports DATABASE_URL=…/soar_addl_eval etc. into this shell only

# A. baseline
npx ts-node --transpile-only scripts/eval/additional/baseline.ts
# B. consistency (attempt 1; TC-09 re-run with --cases TC-09 --tag -rerun-tc09), then merge
npx ts-node --transpile-only scripts/eval/additional/consistency.ts --reps 5
npx ts-node --transpile-only scripts/eval/additional/consistency.ts --reps 5 --cases TC-09 --tag -rerun-tc09
npx ts-node --transpile-only scripts/eval/additional/merge-consistency.ts
# C. negative / reject path
npx ts-node --transpile-only scripts/eval/additional/negative.ts
# paper datasets and documents (no DB, no network)
npx ts-node --transpile-only scripts/eval/additional/build-paper-outputs.ts
# figures (matplotlib only, local virtualenv created for this task)
python -m venv results/additional-evaluation/.venv && results/additional-evaluation/.venv/Scripts/python.exe -m pip install matplotlib
results/additional-evaluation/.venv/Scripts/python.exe results/additional-evaluation/generate-paper-figures.py
```
(The consistency attempt-1 files were renamed to `consistency-attempt1*` before the re-run; the file names in the commands above are the defaults.)

## Generated files
`paper-metrics.json` (every metric: value, numerator, denominator, population, source, run_id, interpretation, limitation) · `paper-results.md` (Tables 1–6, 6b) · `paper-results-narrative.md` · `figure-captions.md` · `figure-data.json` · `figures/figure1…6 (.png + .pdf)` · `generate-paper-figures.py` · `frozen-manifest.json`, `frozen-verification.json` · `CORRECTIONS.md` · `data/` (`baseline.json`, `consistency.json` + attempt files and raw candidates, `negative.json`, logs).

## Metric formulas
- **Recommendation Consistency (per case)** = runs whose *validated primary recommendation* equals the modal validated primary recommendation / total runs, where identical = same playbook + same primary action (step 1) + same target type + same target value; a run that fails validation counts as not consistent. Pooled = Σ consistent runs / Σ runs. Also reported: agreement on the complete step set. Not accuracy.
- **Unsupported Recommendation Rejection Rate** = controlled invalid recommendations rejected / total controlled invalid recommendations (only scenarios whose unmodified *positive control* validated are counted). Not AI accuracy.
- **Baseline** plan scoring reuses the deterministic functions of VIGIX (playbook alignment, allowed-action set, required evidence via `missingEvidenceForTarget` + ACTION_COMPLIANCE policies). Baseline `investigation_time` = end of plan creation − start of evidence collection (wall clock, ms precision). `decision_*` = NULL.
- All main metrics (compliance, evidence coverage, playbook alignment, policy compliance, workflow completion, investigation time, detection-to-response, verification time, intervention/retry rates) are quoted unchanged from `results/evaluation-audit.json`; formulas are in that audit and `results/evaluation-audit.md`.

## Assumptions
- *Controlled procedural baseline* is a deterministic non-AI procedure (static playbook lookup) — **not** a human study, and its latency is machine time. It treats every indicator extracted from the alert as confirmed, which is more permissive than VIGIX's actionable-IOC rule, so evidence/required-evidence gating is not compared.
- Consistency runs use the context of the incident **as at the first-round generation** (earlier recommendations hidden, `previousSteps = []`); otherwise the validator's `NO_NEW_STEP` rule would reject a repeat by design.
- Negative scenarios inject exactly one fault into a candidate that first validated; contexts are built from real incidents of the frozen runs (NEG-02 removes the command-line indicators from a copy of the context).

## Limitations
10 predefined cases (9 evaluable), one run per condition for the frozen Real Wazuh results; 5 repetitions × 6 cases for consistency with one LLM; consistency is not correctness; the baseline says nothing about analyst performance and no baseline decision latency exists; the negative scenarios are single-fault, written by the evaluator (a 10/10 rejection is expected of a deterministic rule set) and NEG-02's *layer* expectation was mis-specified (see `paper-results.md`, Table 6); RESOLVED = the verification procedure did not detect the specified recurrence condition within the tested window, not proof of eradication; no statistical significance is claimed; the ML risk-score table is empty and was not evaluated.
