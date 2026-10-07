# results/extended-evaluation — LOW / False Positive, ESCALATED, RAG, Windows

Read `extended-evaluation-report.md` first. Database: `soar_ext_eval` (clone of the frozen Knowledge Base). Ground-truth pins: `ground-truth.sha256`.

| File | Content |
|---|---|
| `extended-low-fp.json` | part A: 7 benign scenarios (4 LOW, 2 MEDIUM false positives, 1 CRITICAL approved change), metrics, all checks |
| `extended-escalation.json` | part C: 3-round REAL_WAZUH re-hunt → escalated; failed first attempt kept |
| `extended-rag.json` | part B: retrieval metrics, two arms (empty vs 17 runbooks), paired table, repeated generation, IP-order diagnostic |
| `extended-windows.json` | part D: ENVIRONMENT_UNAVAILABLE (until a Windows agent is connected) |
| `extended-kpi-summary.json` | summary of the parts |
| `extended-db-metrics.sql`, `extended-db-metrics-output.txt` | independent SQL cross-check |
| `ext-integrity.json`, `ext-db-creation.json` | frozen/final/dev databases unchanged, KB identical, rules unchanged |
| `runs/` , `../runs/ext-rag-*` | raw run records; `data/` repeated-generation and order experiment; `logs/` run logs |
| `figures/` | 4 figures (`.png` + `.pdf`); `generate-extended-figures.py` |

Code: `apps/backend/scripts/eval/extended/` (`create-ext-db.py`, `calibrate.ts`, `groundTruthExtended.ts`, `run-low-fp.ts`, `run-escalation.ts`, `rag/*`, `order-experiment.ts`, `build-extended.ts`, `ext-integrity.py`, `windows/simulate-tc05.ps1`).

## Reproduce (repo root; Docker stack + Wazuh + LLM endpoint up)
```bash
export PYTHONUTF8=1
python apps/backend/scripts/eval/extended/create-ext-db.py
docker run -d --name vigix-eval-qdrant -p 127.0.0.1:6335:6333 qdrant/qdrant:latest        # isolated Qdrant (6334 is soar-qdrant's gRPC port)
cd apps/backend
npx ts-node --transpile-only scripts/eval/extended/rag/pin-rag-gt.ts
(QDRANT_URL=http://127.0.0.1:6335 PORT=4100 npx ts-node --transpile-only scripts/eval/extended/rag/search-server.ts &)
(BACKEND_URL=http://127.0.0.1:4100 EVAL_DB=soar_ext_eval bash scripts/eval/eval-env.sh start-orchestrator &)   # orchestrator :8001
EVAL_DB=soar_ext_eval . scripts/eval/eval-env.sh
npx ts-node --transpile-only scripts/eval/extended/run-low-fp.ts --label ext-low-fp-20261001
npx ts-node --transpile-only scripts/eval/extended/run-escalation.ts --label ext-esc-20261001-r2
npx ts-node --transpile-only scripts/eval/run-real-evaluation.ts --mode clean --label ext-rag-off-20261001        # Qdrant empty
QDRANT_URL=http://127.0.0.1:6335 AI_ORCHESTRATOR_URL=http://localhost:8001 npx ts-node --transpile-only scripts/indexRunbooksToQdrant.ts
npx ts-node --transpile-only scripts/eval/run-real-evaluation.ts --mode clean --label ext-rag-on-20261001
npx ts-node --transpile-only scripts/eval/extended/build-extended.ts --lowfp ext-low-fp-20261001 --esc ext-esc-20261001-r2 --esc-failed ext-esc-20261001 --rag-off ext-rag-off-20261001 --rag-on ext-rag-on-20261001
```
LLM output varies: a re-run gives different timings, retries and possibly different recommendations. Stop the second orchestrator (python, `port=8001`), the search server (`:4100`) and `vigix-eval-qdrant` when done.
