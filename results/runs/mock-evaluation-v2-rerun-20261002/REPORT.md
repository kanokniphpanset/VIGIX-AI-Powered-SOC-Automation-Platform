# Mock Evaluation v2 (re-run after the TC-07/09, TC-08 and B4 fixes) - 2026-10-02

Label `mock-evaluation-v2-rerun-20261002`. Authoritative artifacts: `run.json`, `metrics/`, `logs/`, `pre-/post-run-integrity.json`, `code-under-test.diff`.
Procedure = the earlier Mock v2 / final procedure: `--mode intervention`, IR decision = approve (scripted IR), real Wazuh re-hunt, 10 cases in one pass, then consistency (6 cases x 5) and `final-metrics.v2.ts`.
The earlier run `mock-evaluation-v2-20261002` (pre-fix) is NOT merged into anything here.

## B. Environment
| Item | Value |
|---|---|
| Database | `soar_mockv2f_eval` = clone of `soar_final_eval`, workflow data reset; KB table checksums identical to `soar_final_eval` (actions 14, MITRE 26, playbooks 11, steps 36, policies 29, rules 29, runbooks 17) |
| Orchestrator | second instance `http://localhost:8001` bound to the eval DB; backend use cases run in-process (no backend HTTP server) |
| Wazuh | 4.9.2, manager API host port 55500 (per-process override), indexer green, agent `attack-endpoint` (009) active, custom rules 100310-100350 loaded and identical to the repo |
| LLM | `vllm-spark-01/gemma4-26b-uncensored` on the vLLM endpoint in `apps/ai-orchestrator/.env` (reachable throughout; no infrastructure events) ; temperature/seed not changed |
| Code | branch `feature/report-period-windows` @ `f3114be`, working tree dirty by intended changes only; tracked-diff SHA-256 `f6b5951b55b12db0...` identical before and after the run (no change during the run) |
| Ground truth | `groundTruthReal.ts` SHA-256 `e54d003515bdcb19...` (see Deviations) |
| Start / end | main run 2026-10-02T09:48:24Z - 10:12:13Z; consistency + metrics until 10:33Z |
| Re-hunt | `REHUNT_PROVIDER=wazuh`, index `wazuh-alerts-4.x-*` |

## C. Case results
| Case | Attack | Status | Compliance | Consistency | Workflow | HITL | Verification | IOC recall | Retries | Escalated | Notes |
|---|---|---|---|---|---|---|---|---|---:|---|---|
| TC-01 | Brute Force | PASS | COMPLIANT | 5/5 | complete | IR approve | RESOLVED | 2/2 | 0 | no | BLOCK-SOURCE-IP -> 172.19.0.7 |
| TC-02 | Malware | INCOMPLETE | COMPLIANT | 5/5 | incomplete | IR approve | none (REHUNT_INSUFFICIENT_CRITERIA) | 0/2 | 0 | no | ISOLATE-ENDPOINT; hash/path not extracted as IOC (PSI-1) so no searchable re-hunt criterion |
| TC-03 | Phishing | PASS | COMPLIANT | not in set | complete | IR approve | RESOLVED | 4/4 | 3 | no | analyst IOC promotion x4 (intervention) |
| TC-04 | Account Compromise | PASS | COMPLIANT | 5/5 | complete | IR approve | RESOLVED | 2/2 | 0 | no | |
| TC-05 | PowerShell | ENVIRONMENT_UNAVAILABLE | NOT_EVALUATED | - | - | - | - | - | 0 | - | no Windows endpoint / Wazuh agent / Sysmon |
| TC-06 | SQL Injection | PASS | COMPLIANT | 5/5 | complete | IR approve | RESOLVED | 1/1 | 0 | no | |
| TC-07 | C2 | PASS | COMPLIANT | 5/5 | complete | IR approve | RESOLVED | 3/3 | 0 | no | BLOCK-DESTINATION-IP -> 172.19.0.5 (destination) |
| TC-08 | Suspicious Process | PASS | COMPLIANT | not in set | complete | IR approve | RESOLVED | 4/4 | 0 | no | KILL-PROCESS, QUARANTINE-FILE (same path), BLOCK-HASH (full SHA-256); 1 generation attempt |
| TC-09 | Data Exfiltration | PASS | COMPLIANT | 5/5 | complete | IR approve | RESOLVED | 3/3 | 0 | no | BLOCK-DESTINATION-IP -> 172.19.0.5 |
| TC-10 | Privilege Escalation | INCOMPLETE | COMPLIANT | not in set | incomplete | IR approve | none (REHUNT_INSUFFICIENT_CRITERIA) | 1/1 | 0 | no | DISABLE-ACCOUNT -> evaluser; USERNAME is not a searchable re-hunt type |

## D. Aggregate metrics (all recomputed from PostgreSQL; `metrics/final-kpi-summary.json`)
| Metric | Value |
|---|---|
| Recommendation Compliance (seven-criterion evaluator incl. targetRole; Mock v2 definition, not directly comparable with the frozen six-criterion evaluation) | 9/9 = 100% of evaluated (9/9 of attempted cases = 100%; 9/10 of all cases, TC-05 not evaluated) |
| Recommendation Consistency | 30/30 = 100% (TC-01/02/04/06/07/09 x 5, same evidence snapshot; 30 validated, 1 distinct primary recommendation per case). TC-03/08/10 are not in the consistency set (existing definition) |
| Workflow Completion | 7/9 = 77.78% (7/10 = 70% of all ten) |
| HITL / permission control | all principle checks true: severity from Wazuh not AI, no response executed without IR approval, no incident closed by AI, IR is the decision authority, timestamps monotonic |
| Verification / Re-hunt (REAL_WAZUH) | RESOLVED 7/9 = 77.78% of cases with a completed response; 2 ERROR (TC-02, TC-10: REHUNT_INSUFFICIENT_CRITERIA) |
| Investigation Time | n=9, mean 123.79 s, median 105.77, SD 91.77, min 46.27, max 357.67 |
| Decision Recording Latency (Time-to-Decision) | n=9, mean 0.056 s, median 0.055, SD 0.009 (scripted IR decision, so it measures recording only, not human deliberation) |
| Retry / Intervention | Retry 1/9 = 11.11% of cases (3 invalid generation calls, all TC-03); Intervention 1/9 = 11.11% (TC-03 analyst IOC promotion); infrastructure failures 0 |
| Escalation | 0/9 - ESCALATED did not occur and was not induced |
| IOC recall (before correction) | TC-01 2/2, TC-02 0/2, TC-03 4/4, TC-04 2/2, TC-06 1/1, TC-07 3/3, TC-08 4/4, TC-09 3/3, TC-10 1/1 = 20/22 |

The "Mock Verification 10/10" line in `final-kpi-summary.json` is the archived simulated-re-hunt baseline and was not produced by this run; it is not part of these results.

## E. Exclusions
- TC-05: `ENVIRONMENT_UNAVAILABLE` (no Windows endpoint with a Wazuh agent / PowerShell logging). Not counted as pass or fail; excluded from the denominator of compliance, workflow, retry, intervention, verification and time metrics (evaluable = 9 of 10). Still counted in "all ten" where stated.
- No other case excluded. TC-02 and TC-10 are INCOMPLETE, kept in all denominators.

## F. Failures and observations
**System / capability (not patched, observed):**
- TC-02: Wazuh FIM alert carries hash and path only in `syscheck.*`; the IOC extractor reads `data.*` only (PSI-1), so the incident has 0 hash/file IOCs, recall 0/2 and no re-hunt criterion.
- TC-10: only a USERNAME IOC exists; USERNAME is not a re-huntable type and no IP/domain/URL/hash exists in a local `usermod` event (PSI-4). Nothing was invented.
**Environment:** TC-05 as above.
**LLM behaviour:** TC-03 needed 3 retries (4 attempts) before a valid recommendation; the retry mechanism worked as designed. TC-08 needed none this time (a truncated 63-character hash and a host-as-process target occurred in the earlier debugging runs, not here).
**Harness:** none discovered in this run. `final-metrics.v2.ts` (null-guard copy) ran with no cross-differences between run.json and the database.

## G. Comparison with earlier debugging runs (not merged)
- TC-08 earlier Mock v2: NO_VALID_RECOMMENDATION after 5 attempts; current: validated, COMPLIANT, RESOLVED, recall 4/4. The 3/4 seen in the debugging run was the known `|` parsing defect, fixed before this run.
- TC-07/TC-09 earlier pre-`networkRole` runs picked the source IP; current runs target the destination (172.19.0.5). Earlier Mock v2 (pre-fix) workflow 6/9 vs 7/9 now. Single runs of a non-deterministic LLM; not a controlled comparison.

## Deviations and caveats (must be read before freezing)
1. The "existing frozen ground truth" is not byte-identical to the final run's: `groundTruthReal.ts` hash is `e54d0035...` (final run: `ddb18d5d...`). The only intended change is the TC-08 entry (added expected file-path and SHA-256 IOCs, structured `expectedEvidence`, `evidenceLimits`), made in the earlier TC-08 scenario task before this run; `expectedActions` is unchanged. The `groundTruth.ts` mock entry was changed the same way. `EvaluationService.ts` is the v2 evaluator (targetRole). The pre-/post-run integrity script therefore reports "previous frozen manifest unchanged = FAIL" for these 3 files; all other checks pass.
2. Other code under test beyond the earlier Mock v2 run: `alertIocs.ts` (PROCESS_NAME from `data.audit.exe`), `RecommendationValidator.ts` (multi-kind IOC map), `iocRecall.ts` + `run-real-evaluation.ts` (pipe handling), `simulations.ts` (TC-08 telemetry adds `data.command/file/sha256`). All are in `code-under-test.diff`.
3. "Mock" alerts here are the lab-controlled and real-action telemetry that passes through real Wazuh (same as the earlier Mock v2); the static JSON files in `resources/mock-attacks-tc/` are not used by this harness.
4. IR decision is a scripted approve; TTD therefore is not human latency. Single main run; reproducibility across runs is not shown (consistency covers repeated generation on the same evidence only).
5. Intervention mode: the only correction applied was the TC-03 analyst IOC promotion.

## H. Freeze decision
**READY_FOR_FREEZE** (with the deviations above disclosed): all 9 applicable cases ran the full pipeline to their natural end, TC-05 is documented as excluded, the code-under-test hash was identical before and after the run, no system change was made during the run, the evaluator finished with no cross-differences, and every number is recomputable from `soar_mockv2f_eval` + `run.json`. TC-02 and TC-10 remain INCOMPLETE because of the documented IOC-extraction / re-hunt capability limits, recorded as observed. These artifacts are the authoritative Mock Evaluation v2 results for the mock dataset.

## I. Freeze repair notes (documentation only, added after the run; no result changed)
- **Compliance definition.** Mock v2 uses seven criteria: the six original ones plus `targetRole` (added deliberately for the TC-07/TC-09 source/destination requirement; unit-tested in `test/EvaluationCompliance.test.ts`). Recomputing from `run.json` gives 9/9 under both seven and six criteria, so the verdicts and aggregate are identical; only the definition label differs. Do not compare directly with the frozen six-criterion evaluation.
- **Provenance.** `code-under-test-manifest.txt` lists every file that differs from commit `f3114be` with its SHA-256, purpose and whether it affects results, including the untracked files that `code-under-test.diff` cannot contain. The tracked-diff hash (`f6b5951b55b12db0`) is unchanged since the run.
- **TC-08 `evidenceLimits` is stale documentation:** its statement that the extractor does not read `data.audit.*` is outdated relative to current code. It does not affect scoring; the ground truth (and its hash `e54d003515bdcb19`) was deliberately not edited.
- **Rows in `final-kpi-summary.json` not produced by this run:** Mock Verification 10/10 (archived baseline), Negative Validation (not available), Human/Policy Validation (0/0). HITL evidence for this run is the `principles` checks plus the per-case approvals/decisions in the database. Step-set Consistency 28/30 is a supplementary, stricter measure; the primary Recommendation Consistency is 30/30.
- **Reporting artefact:** `final-recommendation-compliance.json` TC-08 `supplementary_target_checks` shows ACT-KILL-PROCESS as `kindMatches=false` because `final-metrics.v2.ts` resolves a value to its first IOC (file). It is not part of the verdict. Documented, script not changed.
- **Rounding.** Mean Time-to-Decision is 0.056 s from database timestamps (3 decimals) and 0.057 s when recomputed from the 2-decimal values in `run.json`; the reported value is the database one.
- Files edited for this section: `REPORT.md`, `metrics/final-kpi-summary.json`, `metrics/final-recommendation-compliance.json` (metadata/labels only). Hashes before the edit: kpi `2125906897de…`, compliance `0a23c5f34f6a…`, REPORT `cf63e743508e…`, run.json `26f06aea8ee6…` (unchanged).
