# TC-05 Ground Truth v3.3 — Test Report

> Status of this round: **no LLM evaluation was executed.** LLM evaluation was not executed in this round. Therefore no new AI Correct Recommendation result is claimed.
> (ยังไม่มีผล Correct Recommendation ของ AI รอบใหม่ เนื่องจากรอบนี้ไม่ได้รัน LLM evaluation)

## 1. Objective

Verify that the Correct Recommendation Ground Truth `correctness-gt-v3.3` (which adds TC-05) is defined correctly, that all 10 cases have a well-formed GT, that the strict matching rules are unchanged, and that the unit tests pass. In addition, score the **already observed** recommendations stored in existing frozen artifacts against v3.3 (no new generation).

## 2. Ground Truth change and rationale

| Item | v3.2 | v3.3 |
|---|---|---|
| TC-05 expected pairs | none (case not in correctness GT) | `ACT-BLOCK-DOMAIN → vigix-eval-ps-stager.test` |
| TC-01..04, TC-06..10 | — | unchanged vs v3.2 |
| SHA-256 | `05d81e1b79b4fc1c1cef5a8cc838e27bdb156bdc33e30bcdea497106bf7f2278` | `d2f1dae6d576d8e0534bc8a26cae4a7afc5f6a529e06da2f675a5b44855951a8` |

Verified in this round: removing only the TC-05 pair from the current GT reproduces the v3.2 hash exactly, so TC-05 is the only difference.

Rationale (from the TC-05 GT review, REAL_WAZUH PowerShell/DNS scenario):
- The case is a Sysmon DNS query (event 22) by `powershell.exe` for `vigix-eval-ps-stager.test`; the lookup failed. The observable indicator is the domain.
- `ACT-BLOCK-DOMAIN` targets that indicator. The target is derived from the rule-100300 `queryName` field of the scenario, not from an AI output. PB-POWERSHELL step 2 is the playbook basis for the action *type*; the correctness of the pair rests on the scenario evidence (domain observed in telemetry), not on the playbook containing the action.
- `ACT-ISOLATE-ENDPOINT` is **excluded**: no evidence in this scenario that the endpoint itself is compromised (no process injection, no persistence, no successful C2 connection). The strict rule therefore classifies an ISOLATE recommendation for TC-05 as an unexpected pair.
- No optional pairs were added; `allowedActions` is not read.

## 3. Environment

| Item | Value |
|---|---|
| Branch | `feature/report-period-windows` |
| HEAD | `245b536` (`eval: freeze TC-05 real Wazuh E2E evaluation`) |
| GT version | `correctness-gt-v3.3` (committed in `444fed9`) |
| Model | **NOT RUN** |
| Evaluation mode / database | none in this round (unit tests touch no DB; rescoring reads `run.json` files only) |
| Sources rescored | `results/final-evaluation`-derived v2 rerun `mock-evaluation-v2-rerun-20261002` (file sha `26f06aea8ee6…`); `tc05-e2e-real-wazuh-20261003` (file sha `f2d6f06ee55c…`) |
| New files in this round | `apps/backend/scripts/eval/final/rescore-correct-recommendation.ts`, `results/gt-v3.3-test/*` |

## 4. Ten-case GT table

| Case | Expected actions | Expected targets | Pairs | Optional | GT status |
|---|---|---|---|---|---|
| TC-01 | BLOCK-SOURCE-IP | @ATTACKER_IP | 1 | 0 | defined |
| TC-02 | QUARANTINE-FILE, BLOCK-HASH, ISOLATE-ENDPOINT | /root/Downloads/Invoice_Q4_2026.xls.exe; 275a021b…fd0f; attack-endpoint | 3 | 0 | defined (v3.2 value) |
| TC-03 | BLOCK-URL, BLOCK-DOMAIN, QUARANTINE-EMAIL | http://vigix-eval-phish.net/o365/verify?id=hr.clerk; vigix-eval-phish.net; it-support@vigix-eval-phish.net | 3 | 0 | defined |
| TC-04 | DISABLE-ACCOUNT, RESET-CREDENTIAL, BLOCK-SOURCE-IP | victim; victim; @ATTACKER_IP | 3 | 0 | defined (v3.1 value) |
| **TC-05** | **BLOCK-DOMAIN** | **vigix-eval-ps-stager.test** | **1** | **0** | **defined (new in v3.3)** |
| TC-06 | BLOCK-SOURCE-IP | @ATTACKER_IP | 1 | 0 | defined |
| TC-07 | BLOCK-DOMAIN, BLOCK-DESTINATION-IP | vigix-eval-c2.net; @TESTSERVER_IP | 2 | 0 | defined |
| TC-08 | KILL-PROCESS, QUARANTINE-FILE, BLOCK-HASH | /tmp/.cache/kworkerd; /tmp/.cache/kworkerd; @KWORKERD_SHA256 | 3 | 0 | defined (v3.1 value) |
| TC-09 | BLOCK-DOMAIN, BLOCK-DESTINATION-IP | vigix-eval-exfil.net; @TESTSERVER_IP | 2 | 0 | defined |
| TC-10 | DISABLE-ACCOUNT | evaluser | 1 | 0 | defined |

Placeholders (`@ATTACKER_IP`, `@TESTSERVER_IP`, `@KWORKERD_SHA256`) are resolved from facts recorded before the attack in the same run, never from an AI output.

## 5. Unit test results

Command: `jest` over the 12 related suites, JSON saved to `jest-results.json`.

| Suite | Tests |
|---|---|
| CorrectRecommendation | 29 |
| EvaluationCompliance | 15 |
| IocRecallPipe | 7 |
| IocThreatIntelVerdict | 4 |
| MockRehuntAdapter | 25 |
| RealWazuhProcessIoc | 7 |
| RealWazuhSysmonDnsIoc | 7 |
| RelatedAlertIocProvenance | 8 |
| RunRehuntVerification.integration | 18 |
| Tc05HarnessWiring | 14 |
| ValidatorMultiKindTarget | 6 |
| WazuhRehuntAdapter | 70 |
| **Total** | **210** |

Suites: 12/12 passed. Tests: 210 total, **210 passed, 0 failed, 0 skipped**. Total jest time 6.94 s. None of these tests touch a database. Raw output: `jest-results.json`, `jest-console.txt`, `jest-suite-summary.json`.

## 6. Correct Recommendation results (rescoring of existing observations)

This is a **retrospective rescoring of previously observed, frozen recommendations**; nothing was generated in this round. Each run is scored on its own; they are not merged into one run.

### 6.1 v2 frozen run (`mock-evaluation-v2-rerun-20261002`) scored against v3.3

| Case | Observed (final) vs GT | Correct |
|---|---|---|
| TC-01 | all pairs match | Correct |
| TC-02 | missing QUARANTINE-FILE and BLOCK-HASH | Incorrect |
| TC-03 | all pairs match | Correct |
| TC-04 | missing RESET-CREDENTIAL; unexpected ISOLATE-ENDPOINT→attack-endpoint | Incorrect |
| TC-05 | ENVIRONMENT_UNAVAILABLE in that run | N/A (not evaluated; not a failure) |
| TC-06 | all pairs match | Correct |
| TC-07 | unexpected BLOCK-URL, ISOLATE-ENDPOINT | Incorrect |
| TC-08 | all pairs match | Correct |
| TC-09 | unexpected BLOCK-URL, ISOLATE-ENDPOINT | Incorrect |
| TC-10 | all pairs match | Correct |

Result: **5/9 = 55.56 %** (denominator 9 = cases with an observed recommendation in that run).

### 6.2 TC-05 E2E run (`tc05-e2e-real-wazuh-20261003`) scored against v3.3

| Case | Observed (final) | Correct |
|---|---|---|
| TC-05 | unexpected ACT-ISOLATE-ENDPOINT → vigix-win10-ps (expected BLOCK-DOMAIN pair was present; no missing pair, only the unexpected ISOLATE pair) | Incorrect |

Result: **0/1 = 0 %** (N = 1; no statistical conclusion possible).

### 6.3 Composite view (labelled)

If the two sources above are put side by side: 5 correct of 10 cases = 50 %. This is a **composite of two different runs** (v2 frozen for TC-01..04, 06..10; TC-05 E2E for TC-05), not a single-run result and not a new AI result. It should not be reported as one evaluation's Correct Recommendation Rate.

### 6.4 Disclosure

GT v3.1–v3.3 were designed after the v2 outputs had been seen (rule-based, from playbook evidence). The v2 rescoring is therefore **not blind**. Only TC-05 E2E ran after its GT was fixed, and its single case is the only post-GT observation. TC-05 being scored Incorrect here means the observed recommendation contained an unexpected ISOLATE-ENDPOINT pair under the strict rule; it does not mean the GT was fitted to the output.

## 7. Compliance and other metrics — previous frozen evaluation results

All values in this section are **previous frozen evaluation results**, not re-measured here. They are different constructs and must not be read as accuracy.

| Metric | Value | Denominator / source | Notes |
|---|---|---|---|
| Correct Recommendation Rate | 5/9 = 55.56 % (v2, retrospective); 0/1 (TC-05 E2E) | see §6 | only metric in this report that measures the action→target set against GT |
| Recommendation Compliance | v2: 9/9 cases COMPLIANT (TC-05 not evaluated); TC-05 E2E: 7/7 criteria met, 1/1 case COMPLIANT | 7 criteria per case | measures policy/playbook/evidence rules, **not** correctness of the action set. TC-05 E2E was COMPLIANT yet Incorrect |
| Core Recommendation Consistency | 30/30 (6 cases × 5 repeats) | frozen v2, **not rescored** | playbook + primary action + target type + target value; step-set consistency 28/30 |
| First-pass (valid on first use-case call) | v2: 8/9 use-case calls level (7/9 at model-response level); TC-05 E2E: first call failed, second valid | use-case call vs model response differ | TC-03 had 4 calls (3 failed) in v2 |
| IOC Recall | v2: 20/22; TC-05 E2E: 1/1 | IOCs expected | independent of recommendation correctness |

N/A is not FAIL. Compliance is not Accuracy.

## 8. Per-case view (observed recommendation available?)

| Case | GT defined | Expected pairs | Observed available | Correct | Compliance | Workflow | Verification | IOC recall |
|---|---|---|---|---|---|---|---|---|
| TC-01 | yes | 1 | v2 | Correct | COMPLIANT | complete (resolved) | RESOLVED (REAL_WAZUH) | 2/2 |
| TC-02 | yes | 3 | v2 | Incorrect | COMPLIANT | incomplete (open) | none – REHUNT_INSUFFICIENT_CRITERIA | 0/2 |
| TC-03 | yes | 3 | v2 | Correct | COMPLIANT | complete (resolved) | RESOLVED | 4/4 |
| TC-04 | yes | 3 | v2 | Incorrect | COMPLIANT | complete (resolved) | RESOLVED | 2/2 |
| TC-05 | yes | 1 | TC-05 E2E (none in v2) | Incorrect (E2E) / N/A (v2) | COMPLIANT (E2E) | complete (resolved) | RESOLVED (REAL_WAZUH) | 1/1 |
| TC-06 | yes | 1 | v2 | Correct | COMPLIANT | complete (resolved) | RESOLVED | 1/1 |
| TC-07 | yes | 2 | v2 | Incorrect | COMPLIANT | complete (resolved) | RESOLVED | 3/3 |
| TC-08 | yes | 3 | v2 | Correct | COMPLIANT | complete (resolved) | RESOLVED | 4/4 |
| TC-09 | yes | 2 | v2 | Incorrect | COMPLIANT | complete (resolved) | RESOLVED | 3/3 |
| TC-10 | yes | 1 | v2 | Correct | COMPLIANT | incomplete (open) | none – REHUNT_INSUFFICIENT_CRITERIA | 1/1 |

## 9. Integrity

- No LLM call, no `run-real-evaluation`, no simulation, no mock evaluation in this round.
- No edits to: the correctness GT, `correctRecommendation.ts`, `EvaluationService`, Compliance evaluator, playbook/policy/action seeds, `groundTruthReal.ts`, `.env`, `.claude/launch.json`. (Verified by `git status`/`git diff`, see Phase 10 results delivered with this report.)
- `soar_final_eval` and `soar_platform` were not used; `results/final-evaluation/` untouched.
- The rescoring script is read-only over the `run.json` files (source sha256 recorded in `correct-recommendation-v3.3-matrix.json`).
- Nothing was committed.

## 10. Limitations

- No new AI output: Correct Recommendation under v3.3 has **not** been measured on a fresh run.
- v2 rescoring is retrospective and non-blind (§6.4); TC-05 has N = 1, a custom rule, operator-triggered activity and no recurrence control.
- v2 TC-05 was ENVIRONMENT_UNAVAILABLE; the 10-case figure (§6.3) mixes two runs.
- Raw LLM output of the TC-05 run was not persisted; only final recommendations stored in `run.json` are scored.
- Strict set matching: any unexpected pair makes a case Incorrect, so the metric is intentionally conservative; it does not grade partial credit.
- A fresh, single-run, 10-case LLM evaluation under `correctness-gt-v3.3` is still required for a reportable Correct Recommendation Rate.

## Final status

`GT_V3_3_TESTED_READY_FOR_FREEZE`
