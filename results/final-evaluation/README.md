# results/final-evaluation — VIGIX final (thesis) evaluation

Start with `final-evaluation-report.md` (KPI table, per-case table, metric mapping, findings, limitations, audit checklist, Thai narrative).

## Contents

| File | Purpose |
|---|---|
| `final-evaluation-report.md` | full report |
| `final-kpi-summary.json` | final KPI table + principle checks + findings re-check |
| `final-per-test-case.json` | per-case table and detailed per-case records |
| `final-recommendation-compliance.json`, `final-investigation-time.json`, `final-time-to-decision.json`, `final-workflow-completion.json`, `final-intervention-rate.json`, `final-retry-rate.json`, `final-verification.json`, `final-consistency.json`, `final-negative-validation.json`, `final-human-policy-validation.json`, `final-baseline-comparison.json` | one file per KPI (formula, sources, per-case values, statistics) |
| `final-db-metrics.sql`, `final-db-case-map.sql`, `final-db-metrics-output.txt` | independent SQL recomputation of the DB-derived KPIs and its output |
| `figures/` | six figures, `.png` + `.pdf` (matplotlib, default style) |
| `pre-run-integrity.json`, `post-run-integrity.json`, `final-db-creation.json` | environment, hashes, frozen-artifact checks, DB creation |
| `data/` | consistency, negative/governance and baseline raw data |
| `logs/` | run logs (main, IR-reject, consistency, metrics) |
| `generate-final-figures.py` | figure generator (reads only `final-*.json`) |

Run labels: `results/runs/final-main-real-wazuh-20261001/run.json`, `results/runs/final-ir-reject-real-wazuh-20261001/run.json`.

## Environment recorded (2026-10-01)

Git `feature/report-period-windows` @ `cdfcaf7a5e90` (**dirty** — see hashes in the integrity files); evaluation DB `soar_final_eval`;
LLM `vllm-spark-01/gemma4-26b-uncensored` (self-hosted vLLM); Wazuh 4.9.2 manager + agent; Qdrant 1.19.1 (no collections); MISP unhealthy.
`pre-run-integrity.json` contains the private LLM endpoint host name — redact before publishing. No secrets (passwords/API keys) are stored in these files.

## Reproduce (repository root, Windows Git-Bash; Docker stack, Wazuh and the vLLM endpoint must be up)

```bash
export PYTHONUTF8=1
python apps/backend/scripts/eval/final/pre-run-integrity.py --phase pre
python apps/backend/scripts/eval/final/create-final-db.py            # clone frozen dump into soar_final_eval, reset run data
cd apps/backend && EVAL_DB=soar_final_eval . scripts/eval/eval-env.sh
start-orchestrator                                                    # second AI orchestrator on :8001 bound to the final DB
npx ts-node --transpile-only scripts/eval/run-real-evaluation.ts --mode intervention --label final-main-real-wazuh-20261001
npx ts-node --transpile-only scripts/eval/run-real-evaluation.ts --mode intervention --decision reject --cases TC-06 --label final-ir-reject-real-wazuh-20261001
export EVAL_ADD_DB=soar_final_eval EVAL_SOURCE_RUN=final-main-real-wazuh-20261001 EVAL_OUT_ROOT="$PWD/../../results/final-evaluation"
npx ts-node --transpile-only scripts/eval/additional/baseline.ts
npx ts-node --transpile-only scripts/eval/additional/negative.ts
npx ts-node --transpile-only scripts/eval/additional/consistency.ts --reps 5 --retry-infra
FINAL_MAIN_RUN=final-main-real-wazuh-20261001 FINAL_REJECT_RUN=final-ir-reject-real-wazuh-20261001 npx ts-node --transpile-only scripts/eval/final/final-metrics.ts
cd ../.. && python apps/backend/scripts/eval/final/pre-run-integrity.py --phase post
results/additional-evaluation/.venv/Scripts/python.exe results/final-evaluation/generate-final-figures.py
cat results/final-evaluation/final-db-case-map.sql results/final-evaluation/final-db-metrics.sql | MSYS_NO_PATHCONV=1 docker exec -i soar-postgres sh -c 'psql -U "$POSTGRES_USER" -d soar_final_eval'
```

LLM output is not deterministic: a re-run will produce different timings and may produce different retries/consistency values. Stop the second orchestrator (python process with `port=8001`) when finished.

## Rules followed

Ground Truth fixed before AI output; database is the source of truth; frozen results never modified; failures recorded as failures; infrastructure failures classified
separately (none occurred); AI does not set severity, approve, execute or close; IR_TEAM is the decision authority; MOCK and REAL_WAZUH verification never mixed; no LLM evaluator;
TC-05 `ENVIRONMENT_UNAVAILABLE`; the baseline is a procedural reference only.
