# Supplementary Test — Recommendation Consistency / Repeatability (15 repetitions)

**Scope.** Supplementary test. It is not part of Final Evaluation v3.3 and changes nothing there: Correct Recommendation stays **4/10 = 40.00 %**, the Final denominator, metrics, Ground Truth, artifacts and DB (`soar_v33_eval`) are untouched. **Consistency measures repeatability, not correctness.**

## 1. Objective
Measure whether the VIGIX recommendation pipeline returns the same recommendation when the same case is processed repeatedly.

## 2. Experimental Design
`3 cases (TC-03, TC-08, TC-10) × 15 repetitions = 45 runs`, using the repository's own mechanism `scripts/eval/additional/consistency.ts` (unmodified; `--reps 15 --cases TC-03,TC-08,TC-10`, no `--retry-infra`, so no failed run was repeated).

What a "run" is here (differs from re-running the whole scenario): each run executes the real recommendation pipeline (context builder → LLM agent with one bounded correction → deterministic validator, the production `GenerateRecommendation` use case) against the **same incident / same evidence snapshot** that Final Evaluation v3.3 stored for that case. No new attack is generated, no re-hunt is run, and no recommendation is saved. Only the AI output can vary, and the evidence snapshot hash was identical in all 15 runs of each case (verified). The test therefore measures LLM-pipeline repeatability for fixed input, **not** variability caused by re-executing the attack or telemetry. The first-round context is used (earlier recommendations hidden), as in the original generation.

Retry handling: 1 run = 1 final accepted (or failed) result of the use case; `attempts` (agent calls: the initial generation plus at most one correction) is recorded per run, not counted as separate runs.

## 3. Environment
| Item | Value |
|---|---|
| Run label | `supplementary-consistency-15r` |
| Window (UTC) | 2026-10-03T12:42:39Z → 13:11:08Z |
| Source | branch `feature/report-period-windows`, HEAD `245b536`, no tracked diff before/after |
| Ground Truth | `correctness-gt-v3.3` SHA-256 `d2f1dae6…5951a8`, `REAL_GROUND_TRUTH` `9a800bab…69f6de`, identical before and after (not used for scoring) |
| Model | `vllm-spark-01/gemma4-26b-uncensored`, orchestrator PID 24080 on `:8001` |
| Database | `soar_supp_consistency_eval` = copy of `soar_v33_eval` (the mechanism needs the Final incidents, so it is **not** an empty DB); source DB counts verified equal before the run. Runtime DB proof: 5 sessions, all `soar_supp_consistency_eval` (`logs/runtime-db-pg_stat_activity.txt`) |
| Source run for incidents | `final-evaluation-v3.3` (`EVAL_SOURCE_RUN`) |
| Normalisation | trim + lowercase, duplicates once, order ignored; canonical signature = sorted `ACTION::target` joined by `|`; exact comparison; no LLM judge |

## 4. Results
| Case | Runs | Valid | Generation Success | Core Consistency | Action-set | Target | Playbook | First-pass | Mean retry |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| TC-03 | 15 | 15 | 15/15 = 100.00 % | 12/15 = **80.00 %** | 12/15 = 80.00 % | 100 % | 15/15 = 100 % | 14/15 | 0.067 |
| TC-08 | 15 | 14 | 14/15 = 93.33 % | 13/14 = **92.86 %** | 13/14 = 92.86 % | 100 % | 14/14 = 100 % | 10/15 | 0.333 |
| TC-10 | 15 | 15 | 15/15 = 100.00 % | 8/15 = **53.33 %** | 8/15 = 53.33 % | 100 % | 15/15 = 100 % | 14/15 | 0.067 |
| **Overall** | **45** | **44** | **44/45 = 97.78 %** | **33/44 = 75.00 %** | **33/44 = 75.00 %** | **128/128 = 100 %** | **44/44 = 100 %** | **38/45 = 84.44 %** | **0.156** |

Denominators: Core, Action-set and Playbook consistency use **valid** recommendation runs as denominator (modal count / valid runs); the conservative value over all runs is 33/45 = 73.33 % overall (TC-03 80.00 %, TC-08 13/15 = 86.67 %, TC-10 53.33 %). Target consistency is pair-level: action-target pairs whose target equals the modal target of that action (per case) / all pairs (128). First-pass = valid on the first agent call / all runs. Mean retry = mean(agent calls − 1) over all runs. Overall values are pooled; the macro mean of the three per-case core values is 75.40 %.

Run composition: total 45, valid 44, failed generation 1 (validation failure 1, timeout/error 0).

## 5. Recommendation Signatures
```text
TC-03  (valid 15)
  Signature A = 12/15  BLOCK-DOMAIN(vigix-eval-phish.net) | BLOCK-URL(http://vigix-eval-phish.net/o365/verify?id=hr.clerk) | QUARANTINE-EMAIL(it-support@vigix-eval-phish.net)
  Signature B =  3/15  A + ISOLATE-ENDPOINT(attack-endpoint)           runs r02, r08, r09

TC-08  (valid 14, 1 failed)
  Signature A = 13/14  BLOCK-HASH(c488c4fb…4448d64) | KILL-PROCESS(/tmp/.cache/kworkerd) | QUARANTINE-FILE(/tmp/.cache/kworkerd)
  Signature B =  1/14  A + ISOLATE-ENDPOINT(attack-endpoint)           run r14
  not valid   =  1/15  r04 (INVALID_AI_OUTPUT)

TC-10  (valid 15)
  Signature A =  8/15  DISABLE-ACCOUNT(evaluser) | REVOKE-SESSION(evaluser)
  Signature B =  5/15  A + RESET-CREDENTIAL(evaluser)                  runs r01, r02, r03, r04, r12
  Signature C =  2/15  A + ISOLATE-ENDPOINT(attack-endpoint)           runs r09, r14
```
Full run lists: `metrics/recommendation-signatures.json`; one file per run: `cases/TC-xx/run-NN.json` (run id `supplementary-consistency-15r:TC-xx:rNN`, recommendation, playbook, action-target pairs, validation status, attempts, timestamps via the run record).

## 6. Variability Analysis (from the recorded runs)
* **Action:** all variability is in the *action set*. Every deviation is an **additional** action on top of the modal set (ISOLATE-ENDPOINT in 3 + 1 + 2 runs, RESET-CREDENTIAL in 5 TC-10 runs). No run dropped a modal action, and no run changed an action's target.
* **Target:** none — every action received the same target in every valid run (128/128 pairs). The action-target relation is stable; what varies is which actions are included.
* **Playbook:** none — the same playbook in all 44 valid runs (`PB-PHISHING`, `PB-SUSPICIOUS-PROCESS`, `PB-ACCOUNT-COMPROMISE`).
* **Missing recommendation / validation failure:** 1 run (TC-08 r04). Both agent calls were rejected with `INVENTED_TARGET`: the target given for ACT-BLOCK-HASH was `c488c4fb…4448d6` (63 hex characters) — the evidence hash with its last character missing, so it is not a recorded IOC. Recorded as a failed run and not repeated.
* **Retry:** 7 of 45 runs needed the correction call (TC-03 r11; TC-08 r03, r04, r06, r11, r14; TC-10 r15). Retry does not explain the action-set variation by itself: of the 6 deviating TC-08/TC-03/TC-10 runs with an extra ISOLATE-ENDPOINT only TC-08 r14 used a retry.
* The recorded data do not say *why* the model sometimes adds an action; no cause is claimed beyond the outputs above.

## 7. TC-10 Interpretation
TC-10 was **incorrect** in Final Evaluation v3.3 (the unexpected extra `REVOKE-SESSION`). In this test **all 15 runs contained `REVOKE-SESSION`**, but the exact set varied (53.33 % consistent on the full set), and in 7 runs further actions were added. As a descriptive observation only (not part of the consistency metrics): the frozen GT for TC-10 is `DISABLE-ACCOUNT → evaluser` alone and none of the 15 repeated outputs equals it. For TC-03 and TC-08 the modal signature coincides with the frozen GT pair set, and the deviating runs contain extra ISOLATE-ENDPOINT. These remarks do not change the Final Evaluation result. TC-10 is an example of a case that can be fairly repeatable on its core (REVOKE-SESSION always present) while still not matching the Ground Truth, and the converse also applies: Consistency ≠ Accuracy.

## 8. Comparison with the repository's older definition
The script's own summary reports 44/45 = 97.78 % ("same playbook + same *primary* (first) action + same target"); that definition ignores every step after the first and therefore reads 100 % for TC-03 and TC-10. The metrics in this report follow the requested full-set definition and are lower. Both numbers are in `data/consistency.json` / `metrics/`, and they must not be mixed.

## 9. Integrity
| Check | Result |
|---|---|
| Source changed | NO (HEAD `245b536`, no tracked diff) |
| Ground Truth changed | NO (hashes before = after) |
| Final Evaluation modified | NO (`final-evaluation-v3.3/run.json` SHA-256 `236a3c30…8ed9` before = after; `soar_v33_eval` counts unchanged: 10/10/9/7/232 audit logs) |
| Failed runs removed or replaced | NO (TC-08 r04 kept) |
| Database writes during the run | The mechanism stores no recommendation, but the policy engine wrote **480 `POLICY_EVALUATED` audit rows** into the cloned DB (232 → 712; no other table changed). Only the clone was affected (`evidence/audit-log-delta.txt`) |
| Output path | the first write went to a stray `C:\c\Users\…` path (a Windows path-handling quirk of the `EVAL_OUT_ROOT` I passed from Git Bash); the two output files were moved unchanged into `data/` and the empty stray directory removed |

## 10. Limitations
* 15 repetitions per case and only 3 scenarios; no confidence intervals.
* One model/configuration; repeated on the same stored evidence snapshot, so evidence-side variability (attack, telemetry, ingestion) is not measured.
* The replay context is rebuilt from the stored incident (first-round condition) at a later time, so it is not guaranteed identical to the context of the original Final generation.
* Consistency is deterministic string comparison of canonical signatures; semantically equivalent but differently composed sets count as different.
* Not a measure of correctness or of human performance. Final-run TC-03/TC-08 results are not re-scored here.
* Target consistency is a pair-level agreement; with only one target per action here it is trivially 100 % unless the action set changes.

## 11. Conclusion
The experiment compared canonical action-target signatures, deterministically, over 15 repeated generations per case on a fixed evidence snapshot. Playbook selection (100 %) and the target chosen for each action (128/128) were stable. Exact full-set recommendation consistency was 75.00 % overall (33/44 valid runs; TC-03 80.00 %, TC-08 92.86 %, TC-10 53.33 %), with the deviation always being an extra action added to the modal set, and generation succeeded in 44 of 45 runs (one validation failure). These results describe repeatability for this configuration and do not replace or modify Correct Recommendation or any Final Evaluation v3.3 result.

## 12. Files
`run.json` (= `data/consistency.json`), `data/consistency.json`, `data/consistency-raw-candidates.json`, `metrics/consistency-summary.json`, `metrics/per-case-metrics.json`, `metrics/recommendation-signatures.json`, `cases/TC-03|TC-08|TC-10/run-01…15.json`, `logs/run-console.txt`, `logs/*`, `evidence/*`, `build_metrics.py`.
