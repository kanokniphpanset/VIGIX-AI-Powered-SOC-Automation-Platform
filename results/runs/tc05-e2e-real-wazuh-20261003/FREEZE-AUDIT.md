# FREEZE-AUDIT - TC-05 REAL_WAZUH end-to-end run `tc05-e2e-real-wazuh-20261003`

Audit performed read-only after the run (documentation only; no source, Ground Truth, metric or artifact was modified).
Code-under-test re-verified against the post-run snapshot at 2026-10-03T11:03:16Z: **no file changed** (22 files, hashes in the appendix).

## Result summary

| # | Area | Result |
|---|---|---|
| A | TC-05 Ground Truth | **PASS** |
| B | Correctness Ground Truth | **PASS** |
| C | Code-under-test | **PASS** |
| D | Existing Ground Truth integrity (TC-01..04, 06..10) | **PASS** |
| E | Evaluation logic | **PASS** |
| F | TC-05 E2E artifacts | **PASS WITH GAPS** |
| G | Database integrity | **PASS** |
| H | Wazuh integrity | **PASS** |
| I | Re-hunt integrity | **PASS WITH GAP** |
| J | Timing integrity | **PASS** |

Overall: **PASS_WITH_FINDINGS**. No integrity violation was found. The result for TC-05 (Correct Recommendation 0/1, Compliance 7/7) stands unchanged.

## Key hashes

| Item | SHA-256 |
|---|---|
| `REAL_GROUND_TRUTH` (current, JSON of the array) | `9a800baba905dfc8aca73810ef9f4984ac5923b3909eb013984bd11fcc69f6de` |
| v2 baseline `REAL_GROUND_TRUTH` (`mock-evaluation-v2-rerun-20261002`) | `e54d003515bdcb1915075ce5a80bccae634d534eb8a915485c2a501ec2b68319` |
| Current with the OLD TC-05 entry put back | `e54d003515bdcb1915075ce5a80bccae634d534eb8a915485c2a501ec2b68319` (equal to the v2 baseline: only TC-05 differs) |
| Correctness GT `correctness-gt-v3.3` | `d2f1dae6d576d8e0534bc8a26cae4a7afc5f6a529e06da2f675a5b44855951a8` |
| Tracked diff (`git diff -- apps/backend apps/ai-orchestrator`), before = after the run | `5019020c5c88e469e8bc84031e5d5e5f88da394a6881ad4151a8d1f3d7f5c4eb` |
| Custom rules file (manager = repository) | `f3da602b25f4a9a95dd5f72e46104e7ceea296e02f2dfde8c68a87c4d25e0f9a` |

## Findings by area

**A - TC-05 Ground Truth (PASS).** `mode CUSTOM_RULE_REAL_ACTION`, `ruleId 100300`, level 12, `T1059.001`, expected IOC `domain vigix-eval-ps-stager.test`,
`expectedActions [ACT-BLOCK-DOMAIN]`, `expectedTargets [vigix-eval-ps-stager.test]`, playbook PB-POWERSHELL; no `ACT-ISOLATE-ENDPOINT` among expected actions. Evidence: `Tc05HarnessWiring.test.ts` (14 tests) and the check against the live module.

**B - Correctness GT (PASS).** Version `correctness-gt-v3.3`, SHA equal to the value above; 0 optional pairs; TC-05 has exactly one pair (`ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test`, targetKind `domain`); an unexpected action makes the result INCORRECT (`CorrectRecommendation.test.ts`, 29 tests); `allowedActions` is not read by the scorer.

**C - Code-under-test (PASS).** Every file in the appendix has the same SHA-256 in the pre-run snapshot, the post-run snapshot and at audit time; none has a modification time after the run start (10:36:55Z). Commit `f3114be24fb9e0f4a96f4ff5244d83ffa135fc86`, **working tree dirty** (nothing of the code under test is committed). Rule 100300 installed on the manager = repository file.

**D - Existing Ground Truth (PASS).** Replacing the TC-05 entry by its previous content reproduces the v2 baseline hash exactly, so TC-01..04 and TC-06..10 are byte-identical to v2. The correctness pairs of TC-02, TC-04 and TC-08 are asserted exactly in `CorrectRecommendation.test.ts`.

**E - Evaluation logic (PASS).** `EvaluationService.ts` `47bbc8ad8b7916d...` and `RecommendationValidator.ts` `e0c37133b21edf3...` equal the `code-under-test-manifest.txt` of the v2 freeze. `GenerateRecommendation.usecase.ts`, `RunRehuntVerification.usecase.ts`, `CreateVerification.usecase.ts`, `WazuhRehuntAdapter.ts` and `WazuhIndexerAdapter.ts` have no diff against HEAD. The runner/simulation changes for TC-05 are confined to the agent used per case, the alert wait time, the TC-05 preflight checks, the trigger definition and the timing label.

**F - Artifacts (PASS WITH GAPS).** Present: `run.json`, `metrics/final-correct-recommendation.json`, `pre-run-integrity.json`, `post-run-integrity.json`, `logs/main-run.log`, `logs/start.txt`, `preflight-failed.json`, `logs/main-run.preflight-failed-wazuh-api-55000.log`, and (added by this documentation step) `REPORT.md` and `FREEZE-AUDIT.md`.
The first preflight failure happened **before case execution** (check `Wazuh manager API`, port 55000 not published); it carries no case data and is not a TC-05 evaluation result; `run.json` comes from attempt #2 only.
Gaps: (1) the full KPI set of `final-metrics.v2.ts` was **not generated** for this run - only the Correct Recommendation metric exists; the KPIs are read directly from `run.json` in `REPORT.md`; (2) the process-level overrides (`WAZUH_API_URL`, `TC05_OPERATOR_WAIT_MS`, `EVAL_DB`) are not recorded inside `run.json` - they are recorded in `REPORT.md` section 2.

**G - Database (PASS).** `soar_tc05_eval`: 1 alert, 1 incident, 1 recommendation, 31 audit logs. `soar_final_eval` unchanged (10 alerts, 10 incidents, 10 recommendations, 484 audit logs). Dev DB `soar_platform` unchanged (260 alerts, 39 incidents). The smoke database `soar_tc05_smoke` (13 alerts) is separate and holds only smoke/probe data. Knowledge Base of the evaluation DB equals `soar_final_eval` (MD5 of actions, playbooks and policies identical; 14 actions, 26 MITRE techniques, 11 playbooks, 36 steps, 29 policies, 17 runbooks).

**H - Wazuh (PASS).** Agent 010 `vigix-win10-ps` Active (v4.9.2, Windows 10 Education). Rule hash above, equal to the repository file. The alert `1791023881.1721259` exists in the manager's `alerts.json` and in the indexer (doc `-cFXAaEBT0qgUD4ho08f`) and its Sysmon event 22 content equals the stored `raw_payload`. The indexer client has no write method; the TC-05 simulation branch has no code that writes an alert or event.

**I - Re-hunt (PASS WITH GAP).** REAL_WAZUH, `searchedIocs` contains `vigix-eval-ps-stager.test`, `matchingEvents 0`, `iocRecurrence false`, no hard-coded `RESOLVED`. Gap: there was **no recurrence control**; this limitation was not recorded by the run itself and is now recorded in `REPORT.md` section 8.

**J - Timing (PASS).** Timing mode `OPERATOR_TRIGGERED`; Investigation Time 129.24 s (recomputed from the timeline: 129.24 s); detection/trigger time (65.54 s) is measured from the runner's wait start and includes the operator's waiting time, so it is not an AI investigation time or a VIGIX detection latency; Time-to-Decision 0.06 s is a scripted IR decision.

## Additional findings (do not change any number)

* **F-1 Unit of "generation".** `GenerateRecommendation` performs one bounded internal correction per call (`attempts` 1 or 2). The v2 figures "12 generations" and "First-pass 8/9" count **use-case calls**. At the **model-response** level the v2 run contains 17 responses (TC-03: 3 failed calls x 2 + a corrected success = 8; TC-02: a corrected success = 2; seven cases 1 each) and only 7 of 9 cases were valid on the first response (TC-02 needed the internal correction). This TC-05 run: 3 model responses, 2 calls. Documents must state the unit.
* **F-2 Root cause of the TC-05 retry.** `PARTIALLY_CONFIRMED` (see `REPORT.md` section 7). The raw model output is not persisted.
* **F-3 Uncommitted code and an unsafe file.** All code under test is uncommitted. The repository root contains an untracked, **not ignored** file `.env.txt` (database/service settings); it must not be staged (`git add -A` would add it).
* **F-4 TC-05 vs TC-02 criterion.** `ACT-ISOLATE-ENDPOINT` is an expected pair for TC-02 (GT v3.2) and not for TC-05 (GT v3.3) because TC-05 provides no evidence of compromise; the paper must explain the difference.

## Decisions deliberately NOT taken (would require a full re-run)

No change to backslash handling, no candidate logging, no change to the Ground Truth or to any metric or validator.

## Files proposed for the commit (not committed)

See the final message of this audit step for the exact list; the commit must exclude `.env.txt`.

## Appendix - code-under-test SHA-256 (identical in pre-run snapshot, post-run snapshot and at audit time)

| File | SHA-256 |
|---|---|
| `apps/backend/src/evaluation/groundTruthReal.ts` | `89d24951a9a8f2e743cc2c5c070ede1f2a322d4a78d80d9cbaf4b59880e4f3a6` |
| `apps/backend/src/evaluation/groundTruthCorrectness.ts` | `36a489881475a3b72b425666efcffe020f7cf700b1eed84c32cedf6dd83f3eb3` |
| `apps/backend/src/evaluation/correctRecommendation.ts` | `33941467c252624844b418ff1742583d69b7d3edd864727b17d514a07df72de0` |
| `apps/backend/src/evaluation/EvaluationService.ts` | `47bbc8ad8b791606982eecde2fd776b080d213a0dd68eeed0efc4ca6c7feea3d` |
| `apps/backend/src/evaluation/types.ts` | `c5cf173a1c3707714ab33414bfa3f9bebb891f4530cb751ab0839c5984aa9f91` |
| `apps/backend/src/evaluation/iocRecall.ts` | `09606cb59f8361c5b175a32b85c47525c2aed5395d22ce38f90926d637749c7b` |
| `apps/backend/src/infrastructure/recommendation-validation/RecommendationValidator.ts` | `e0c37133b21edfb817bcbe7aaf7e14836ed7d18a21514859fa36c10ba38507e3` |
| `apps/backend/src/infrastructure/ai/RecommendationPromptBuilder.ts` | `b9d63c0767897cff8fc2a79e8866cb9aac888a7773bc532f65615fc9afe9362f` |
| `apps/backend/src/domain/investigation/alertIocs.ts` | `b3add72b004fa3782e28524db60903c872985279e1a746ece5eb46f236b96a73` |
| `apps/backend/src/application/recommendation/services/RecommendationContextBuilder.ts` | `8766e03674668021185a59a6ec28e66c862220e704b4f8845120852ac020c8b7` |
| `apps/backend/scripts/eval/run-real-evaluation.ts` | `cd507388d154183e230c6c6fad1aefec87e5fc2e95c23cf236ae4594fcf339f4` |
| `apps/backend/scripts/eval/simulations.ts` | `b0b1bca35e6adb28a2f67525b7d6100c582b92e42b9107f6a7c5e8801e18f2ab` |
| `apps/backend/scripts/eval/wiring.ts` | `e94d1c18fd9d1932a2a56ff82dd973f6f211dccd91dc28818c94bae3658c8335` |
| `apps/backend/scripts/eval/indexerClient.ts` | `77193c0f221b45943db78651e1b08c0663b235b8a9e965572767becaae3c374f` |
| `apps/backend/scripts/eval/eval-env.sh` | `a10b8af9dc69da8d64e64abf8e58774abc105e38eca7f00276399ee915fe31ac` |
| `apps/backend/scripts/eval/final/final-metrics.v2.ts` | `5658a4206e2c561732d5a278f30ec014d09e9176574581bc5e3fa3424ba2d5de` |
| `apps/backend/scripts/eval/final/correct-recommendation-metrics.ts` | `1557b89b55f97e9307c6dc705e860c3344e98e1cecd9d1d2b3cdf7979d32e7e7` |
| `apps/backend/prisma/seeds/playbook.seed.ts` | `d26c6fd29be3d3f73877200d283c708c6e2227b107d1053faffd3dd0a8232a97` |
| `apps/backend/prisma/seeds/policy.seed.ts` | `8f49bbc20a18c51a468aad80643aa9afae2601ae4d98d05679a96e4f4fefd68c` |
| `apps/backend/prisma/seeds/action.seed.ts` | `3c6ec7bc7992e2b37f4389d79eea1847b69cbe8c7c91565b029586ae6bd34532` |
| `apps/backend/src/domain/knowledge/actionKnowledge.ts` | `801bf8b96a95d773c5de14405bf05e3188d54a1683dd46ac1a84f12135962960` |
| `infra/docker/wazuh-manager/vigix_eval_rules.xml` | `f3da602b25f4a9a95dd5f72e46104e7ceea296e02f2dfde8c68a87c4d25e0f9a` |

## Appendix - run artifact SHA-256

| File | SHA-256 |
|---|---|
| `run.json` | `f2d6f06ee55c23a6579034b97707c5ded1793dc8d7805792b6ec594342b6e16d` |
| `metrics/final-correct-recommendation.json` | `797be04189a5bbe65c1a9d7e3f6137f7441e9b51749a41c970913bc848e44187` |
| `pre-run-integrity.json` | `329ead28e8fbb17f7dc96938d7499840158bad8b83d4c150736017a05c3eb1e1` |
| `post-run-integrity.json` | `20c99f213be49035c7b65b0d6372908788038141a1a3e63f26a5cef5f23e8c7a` |
| `preflight-failed.json` | `0dc68ccba5f3d3bfba9f4dccb7de7b649a6e13125d24d639968f08e36c4d6050` |
| `logs/main-run.log` | `4e53fcd431ea63babca63e96cdb1adf55345c268fd2c6efe1281b034003f4f0e` |
| `logs/main-run.preflight-failed-wazuh-api-55000.log` | `dca8139f0f68cf5204734a7cf71dc009579cb5a69dd9cce1bf2cff441f1ba4c1` |
| `logs/start.txt` | `af1ff1506cdec80e2bc3b8a8cc71def46f95b7b362147da52cd386dc808b4153` |
