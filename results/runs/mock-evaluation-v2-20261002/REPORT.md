# Mock Evaluation v2 — run report (2026-10-02, after the `networkRole` context fix)

Run label `mock-evaluation-v2-20261002`; DB `soar_mockv2_eval` (clone of `soar_final_eval`, workflow data reset; Knowledge Base checksums identical to the frozen DB;
`soar_final_eval` and all earlier result directories untouched). Procedure = the final-evaluation procedure (`--mode intervention`, IR decision = approve, real Wazuh re-hunt).
Ground-truth SHA-256 `ddb18d5d4dee4ffe…` = identical to the final run, i.e. the test cases are unchanged.
LLM `vllm-spark-01/gemma4-26b-uncensored` (vLLM, temperature/seed not changed). Total cases 10, evaluable 9 (TC-05 `ENVIRONMENT_UNAVAILABLE`), unavailable 1.
Files: `run.json` (raw), `metrics/final-*.json` (KPIs), `pre-/post-run-integrity.json`, `code-under-test.diff` + `git-diff-stat.txt`, `logs/`.

## 1. Pre-flight
| Item | Result | Note |
|---|---|---|
| Backend | PASS (in-process) | the harness runs the backend use cases in-process via Prisma; no backend HTTP server is part of this procedure and none was started |
| AI orchestrator | PASS | second instance :8001 bound to `soar_mockv2_eval` |
| PostgreSQL eval DB | PASS | connected to `soar_mockv2_eval` |
| Wazuh manager API | PASS | host port is **55500** (Windows reserves 55000); `WAZUH_API_URL` set per process, `.env` untouched |
| Wazuh indexer | PASS | cluster green |
| Wazuh agent | PASS | attack-endpoint ID 009 Active; Wazuh 4.9.2 |
| vLLM | PASS | model offered by the endpoint |
| KB records | PASS | 11 playbooks / 26 MITRE / 14 actions; checksums equal to the frozen DB |
| Qdrant | PASS | `soar-qdrant` 1.19.1, no collections (same as the final run) |
| Evaluator = v2 | PASS | `EvaluationService.ts` with `targetRole` (hash in `pre-run-integrity.json`) |
| No unintended changes | PASS with notes | working tree is dirty by **intended** changes only (see §5, deviations). The integrity script reports `previous frozen manifest unchanged = FAIL` solely because `EvaluationService.ts` is the new v2 evaluator |

## 2. Case results
| Case | Status | Recommendation | Validation | Retry | IR decision | Verification | Final result |
|---|---|---|---|---|---|---|---|
| TC-01 Brute Force | AVAILABLE | BLOCK-SOURCE-IP → 172.19.0.7 | VALIDATED | 0 | approved (IR_TEAM) | RESOLVED (REAL_WAZUH) | PASS |
| TC-02 Malware | AVAILABLE | ISOLATE-ENDPOINT → attack-endpoint | VALIDATED | 1 | approved | none — REHUNT_INSUFFICIENT_CRITERIA | INCOMPLETE |
| TC-03 Phishing | AVAILABLE | QUARANTINE-EMAIL, BLOCK-URL, BLOCK-DOMAIN, ISOLATE-ENDPOINT | VALIDATED | 2 | approved | RESOLVED (REAL_WAZUH) | PASS (analyst IOC promotion = intervention) |
| TC-04 Account Compromise | AVAILABLE | DISABLE-ACCOUNT, BLOCK-SOURCE-IP, RESET-CREDENTIAL, REVOKE-SESSION | VALIDATED | 0 | approved | RESOLVED (REAL_WAZUH) | PASS |
| TC-05 PowerShell | ENVIRONMENT_UNAVAILABLE | not attempted | — | — | — | — | ENVIRONMENT_UNAVAILABLE (no Windows endpoint with a Wazuh agent) |
| TC-06 SQL Injection | AVAILABLE | BLOCK-SOURCE-IP → 172.19.0.7 | VALIDATED | 0 | approved | RESOLVED (REAL_WAZUH) | PASS |
| TC-07 C2 | AVAILABLE | BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, ISOLATE-ENDPOINT | VALIDATED | 0 | approved | RESOLVED (REAL_WAZUH) | PASS |
| TC-08 Suspicious Process | AVAILABLE | **none** | NO_VALID_RECOMMENDATION after 5 attempts | 5 | not reached | none | FAIL |
| TC-09 Data Exfiltration | AVAILABLE | BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, ISOLATE-ENDPOINT | VALIDATED | 0 | approved | RESOLVED (REAL_WAZUH) | PASS |
| TC-10 Privilege Escalation | AVAILABLE | DISABLE-ACCOUNT, RESET-CREDENTIAL, REVOKE-SESSION (evaluser) | VALIDATED | 0 | approved | none — REHUNT_INSUFFICIENT_CRITERIA | INCOMPLETE |

Per-case alert/incident/recommendation IDs, steps, timestamps, policy/playbook snapshot and the six-plus-one compliance flags are in `run.json` and `metrics/final-per-test-case.json`.
Totals: PASS 6, FAIL 1, INCOMPLETE 2, ENVIRONMENT_UNAVAILABLE 1.

## 3. TC-07 / TC-09 target analysis (observation only; validator unchanged)
| Case | Source IP | Destination IP | Selected target (BLOCK-DESTINATION-IP) | Role of target | Result |
|---|---|---|---|---|---|
| TC-07 | 172.19.0.6 (endpoint) | 172.19.0.5 (server) | 172.19.0.5 | destination | correct (targetRole = true, COMPLIANT) |
| TC-09 | 172.19.0.6 (endpoint) | 172.19.0.5 (server) | 172.19.0.5 | destination | correct (targetRole = true, COMPLIANT) |

No BLOCK-SOURCE-IP step occurs in these two cases. TC-01/04/06 BLOCK-SOURCE-IP targets 172.19.0.7 = the alert `srcip` (checked by `targetRole`).

## 4. Metric results (Mock Evaluation v2; evaluator with `targetRole`)
| Metric | Result |
|---|---|
| Recommendation Compliance | **8/8 = 100%** of evaluated recommendations; 8/9 = 88.89% of attempted cases (TC-08 produced no valid recommendation, so it is not evaluated — it counts as FAIL in the per-case result) |
| Recommendation Consistency | **30/30 = 100%** (6 cases TC-01/02/04/06/07/09 × 5 repetitions on the same evidence, real LLM + validator, nothing persisted; 2 repetitions re-run after LLM-endpoint failures, recorded in `metrics/final-consistency.json`). TC-03/TC-08/TC-10 are not in the consistency case set |
| Investigation Time | mean 116.94 s, median 81.75 s, sd 80.60 s, min 46.19 s, max 293.99 s (n = 8) |
| Decision Recording Latency | mean 0.063 s (n = 8, min 0.051, max 0.083). This is the latency of the **scripted** IR approval in the harness, not human decision time — not a human-performance metric |
| Human-in-the-Loop / Permission control | all 5 principle checks true: severity from Wazuh not AI; no response executed without IR approval; no incident closed by AI; IR_TEAM is the decision authority (8/8 decided approvals `IR_TEAM`, approved); timestamps monotonic |
| Verification / Re-hunt | 6 RESOLVED (REAL_WAZUH) and 2 ERROR (TC-02, TC-10: `REHUNT_INSUFFICIENT_CRITERIA`, "No supported IOC is available to query"); TC-08 none (no response), TC-05 N/A |
| Workflow Completion | **6/9 = 66.67%** (60% of all ten) |
| Retry | 3/9 = 33.33% of evaluable cases had a retry; total retry count 8 (TC-02 1, TC-03 2, TC-08 5) |
| Intervention | 2/9 = 22.22% (TC-03: analyst promoted existing IOCs; TC-08: analyst added process/command-line IOCs) |
| Escalation | N/A — no case reached a third re-hunt round in this run. ESCALATED was tested separately in the extended evaluation, not here |

## 5. Failures
| Case | Stage | Exact error | Root cause established? | Class |
|---|---|---|---|---|
| TC-08 | Recommendation validation | `NO_VALID_RECOMMENDATION after 5 model attempts`. Rejected attempts: `TARGET_TYPE_MISMATCH` (ACT-KILL-PROCESS / ACT-QUARANTINE-FILE aimed at host `attack-endpoint`, or QUARANTINE-FILE at the process `/tmp/.cache/kworkerd`) and `INSUFFICIENT_EVIDENCE` (COMMAND_LINE / FILE_HASH not recorded for that target) | Validator behaved as designed (it rejected invalid output). Why the LLM kept producing these 5 times is **not established**. Facts: the same case needed 3 attempts and ended COMPLIANT in the final run; this incident has **no IP IOC**, so the new `role=` prompt text did not appear in its prompt; the sample is one run | LLM variability is the most consistent explanation but is unproven; not an environment problem |
| TC-02 | Verification (re-hunt) | `REHUNT_INSUFFICIENT_CRITERIA` — no supported IOC. The alert yields no hash/file IOC (iocRecall 0/2: hash `275a021b…`, file `/root/Downloads/Invoice_Q4_2026.xls.exe` expected by the ground truth are not in the alert); the model chose ISOLATE-ENDPOINT | The missing searchable IOC is a property of the test scenario/alert, not of the AI. The frozen v2 spec/ground truth (hash unchanged) does not add an IOC, so nothing was altered | test-data limitation |
| TC-10 | Verification (re-hunt) | `REHUNT_INSUFFICIENT_CRITERIA` — only IOC is `USERNAME evaluser`, which the Wazuh re-hunt cannot search | same as TC-02 | test-data limitation |
| TC-05 | Setup | `ENVIRONMENT_UNAVAILABLE` | no Windows endpoint | environment |
| — | Reporting tool | `final-metrics.ts` crashed on `r.safety` / `r.incidentFinal` being undefined for the attempted case without a recommendation (TC-08) | the script assumed every attempted case has a recommendation | tooling (see deviations) |

Deviations from "change nothing" (all recorded, none alters a metric formula or the system under test): (1) a **copy** `scripts/eval/final/final-metrics.v2.ts` adds only null-guards (`r.safety?.`, `r.incidentFinal?.`) so the KPI script can run when a case has no recommendation; the original script is untouched and a case without a plan is treated as vacuously safe (no executions). (2) `order-experiment.ts` gained an `ORDER_EXPERIMENT_OUT` override (earlier step, not used in this run). (3) The integrity script was run from a scratch copy writing into this directory so `results/final-evaluation/` was not overwritten.

## 6. Comparison with previous results (not merged)
| | Compliance | Workflow | Intervention | Retry | Consistency |
|---|---|---|---|---|---|
| Final run, old evaluator (before `networkRole`) | 9/9 = 100% | 7/9 | 2/9 | 2/9 | 29/30 (96.67%, earlier additional evaluation) |
| Final run re-scored with the v2 evaluator (before fix) | 7/9 = 77.78% (TC-07, TC-09 wrong role) | 7/9 | 2/9 | 2/9 | — |
| **This run (Mock Evaluation v2, after fix)** | **8/8 = 100%** (8/9 attempted) | **6/9** | 2/9 | 3/9 | **30/30 = 100%** |
| Order experiment (diagnostic, TC-07/09 only) | 18/20 correct destination picks, 0/20 source picks — diagnostic, **not** a Mock v2 result | | | | |

What changed: TC-07/TC-09 now choose the destination IP in the full workflow (they were the two role failures). Workflow Completion dropped 7/9 → 6/9 because TC-08 produced no valid recommendation this time; TC-02/TC-10 stay incomplete for the same re-hunt reason as before. Single run, LLM output is non-deterministic: the TC-08 outcome differs between the two runs.

## 7. Freeze recommendation
**NOT READY TO FREEZE**
- TC-08 failed to produce a valid recommendation and its cause is not established (the run is complete and honest, but the result for that case is unexplained).
- TC-02/TC-10 cannot complete verification (searchable IOC absent in the frozen scenario) and TC-05 is unavailable, so 3 of 10 cases do not reach the full workflow.
- Results are not shown to be reproducible (one main run; TC-08 differed from the previous run).
- Everything else holds: all required cases were attempted, no manual bypass or validator change, evaluator completed, human-in-the-loop principles passed, evidence preserved.
Suggested next steps (not done): repeat TC-08 (e.g. 3 main runs) to see whether the failure is stable; decide whether TC-02/TC-10 get a searchable IOC in the v2 scenario spec before freezing.
