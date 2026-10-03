# TC-05 PowerShell - REAL_WAZUH end-to-end evaluation (run `tc05-e2e-real-wazuh-20261003`)

Status of this document: **documentation only**. Nothing in `run.json`, `metrics/`, the logs, the Ground Truth or the code was changed
to write it. The numbers below are read from `run.json`, `metrics/final-correct-recommendation.json` and the run's database
(`soar_tc05_eval`).

## 1. Run identity

| Item | Value |
|---|---|
| Scope | **TC-05 only** (one case, one run; no other test case was executed) |
| Evaluation type | **REAL_WAZUH** (`run.json` `evaluationType`), mode `intervention`, IR decision = scripted approve |
| Timing mode | **OPERATOR_TRIGGERED** (the scenario command was run by a person on the Windows endpoint) |
| Run window (UTC) | 2026-10-03T10:36:55.610Z -> 2026-10-03T10:40:35.426Z |
| Git | branch `feature/report-period-windows`, commit `f3114be24fb9e0f4a96f4ff5244d83ffa135fc86`, **working tree dirty** (the code under test is not committed; see `FREEZE-AUDIT.md`) |
| Evaluation database | `soar_tc05_eval` (clone of `soar_final_eval` with workflow data reset; Knowledge Base identical) |
| Mock data | none. No mock alert, no injected indexer event (the harness has no write path for TC-05; asserted by `Tc05HarnessWiring.test.ts`) |

## 2. Environment

| Item | Value |
|---|---|
| Windows endpoint | `DESKTOP-3MP7GB3` (Windows 10 Education, VMware), Wazuh agent **010 `vigix-win10-ps`**, agent/manager version 4.9.2, Sysmon 15.22 |
| Telemetry | Sysmon Event ID 22 (DnsQuery) raised by `powershell.exe` |
| Wazuh rule | **100300**, **level 12**, **MITRE T1059.001** - a CUSTOM rule (`infra/docker/wazuh-manager/vigix_eval_rules.xml`) that matches this exact lab name; the stock ruleset has no rule for a PowerShell DNS query. Reported as `CUSTOM_RULE_REAL_ACTION`, never as a stock detection |
| Custom rules file hash | `f3da602b25f4a9a95dd5f72e46104e7ceea296e02f2dfde8c68a87c4d25e0f9a` (manager copy = repository copy, before and after the run) |
| LLM | `vllm-spark-01/gemma4-26b-uncensored` on the self-hosted vLLM endpoint (`LLM_PROVIDER` is defined twice in `apps/ai-orchestrator/.env`; the effective path is `LLM_BASE_URL` + `LLM_MODEL`, see `results/additional-evaluation/CORRECTIONS.md`) |
| AI orchestrator | second instance on `:8001`, bound to `soar_tc05_eval` |
| Re-hunt | `REHUNT_PROVIDER=wazuh`, index `wazuh-alerts-4.x-*` |
| Process-level overrides (no file was edited) | `EVAL_DB=soar_tc05_eval`, `WAZUH_API_URL=https://localhost:55500` (the manager API is published on host port 55500), `TC05_OPERATOR_WAIT_MS=1800000` |

## 3. Ground Truth used

* Playbook: **PB-POWERSHELL**.
* Expected IOC: **`DOMAIN -> vigix-eval-ps-stager.test`**.
* Expected action -> target (Correct Recommendation GT `correctness-gt-v3.3`): **`ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test`**.
* **`ACT-ISOLATE-ENDPOINT` is NOT in the Ground Truth.** The scenario proves PowerShell and DNS activity on the endpoint; it does not prove that the
  endpoint was compromised, so no Ground Truth was written that infers compromise from activity alone.
* `REAL_GROUND_TRUTH` hash `9a800baba905dfc8aca73810ef9f4984ac5923b3909eb013984bd11fcc69f6de` (the v2 baseline `e54d003515bdcb1915075ce5a80bccae634d534eb8a915485c2a501ec2b68319` is reproduced when the TC-05 entry is replaced by its previous content, i.e. only TC-05 differs from v2).
* Correctness GT `correctness-gt-v3.3`, SHA-256 `d2f1dae6d576d8e0534bc8a26cae4a7afc5f6a529e06da2f675a5b44855951a8`; strict (action, target) pair matching, no optional pair, `allowedActions` is not read.

## 4. End-to-end result

| Step | Result | Evidence |
|---|---|---|
| Scenario | run by the operator at 10:37:56Z (17:37:56 +07) on the VM: `powershell.exe` resolves `vigix-eval-ps-stager.test` (DNS lookup only, nothing downloaded) | operator output; `simulation.facts.triggerMode = manual` |
| Wazuh alert | rule 100300, level 12, T1059.001, agent `vigix-win10-ps`, alert id `1791023881.1721259`, 2026-10-03T10:38:01.155+0000; read from the Wazuh Indexer (doc `-cFXAaEBT0qgUD4ho08f`) | `wazuh`, `ruleMatch/levelMatch/mitreMatch = true` |
| Ingest | received by VIGIX 2026-10-03T10:38:07.906Z, severity high, incident `fb479b6b-9d58-4001-a82a-98f93c22d0ec`, 1 evidence row | `timeline` |
| IOC extraction | `DOMAIN vigix-eval-ps-stager.test` (from `data.win.eventdata.queryName`), `PROCESS_NAME` (powershell.exe path), `USERNAME` | `threat_intel_iocs`; IOC recall 1/1 |
| AI investigation | completed (agent execution `PARTIAL_SUCCESS`, 9 agent results stored) | `workflow.aiAnalysisCompleted = true` |
| Recommendation | PB-POWERSHELL, step 1 `ACT-ISOLATE-ENDPOINT -> vigix-win10-ps`, step 2 `ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test`; both steps require approval | `recommendations`, `recommendation_steps` |
| Validation | `VALIDATED` on the 2nd use-case call (see section 7) | audit log |
| IR decision | approved, role IR_TEAM, actor `eval-ir` (scripted API call, 0.06 s) | `approvals` |
| Response | plan `COMPLETED`, target `vigix-win10-ps` (the first step); manual/simulated execution | `response_plans` |
| REAL_WAZUH re-hunt | `RESOLVED`, `matchingEvents=0`, `iocRecurrence=false`, `spreadDetected=false` | `verifications`, section 8 |

All 11 workflow flags in `run.json` are true; final incident status `resolved`.

## 5. Metrics (N = 1; no statistic or percentage is claimed beyond the single case)

| Metric | Value |
|---|---|
| Recommendation Compliance | **COMPLIANT, 7/7 criteria** (attackAlignment, evidenceSupport, knowledgeValidity, policyCompliance, playbookAlignment, approvalCorrectness, targetRole); `failedChecks = []` |
| Correct Recommendation | **0/1 (INCORRECT)** |
| IOC Recall | 1/1 |
| Retry | **1** (harness / use-case-call definition: one failed `GenerateRecommendation` call; see section 7 for model responses) |
| Intervention | 0 |
| Investigation Time | **129.24 s** (recommendation created 10:40:17.198Z - investigation start 10:38:07.957Z; includes the model responses of the failed call and of the retry) |
| Time-to-Decision | **0.06 s**, a scripted IR decision (API latency, not human decision time) |
| Verification | **RESOLVED** (REAL_WAZUH) |

## 6. Correct Recommendation analysis

* Expected: `ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test`. Actual: `ACT-ISOLATE-ENDPOINT -> vigix-win10-ps` **and** `ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test`.
* `ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test` **matches** the Ground Truth; nothing expected is missing; the playbook matches.
* `ACT-ISOLATE-ENDPOINT -> vigix-win10-ps` is an **unexpected action**. The strict rule (every expected pair present AND no unexpected pair) therefore gives **INCORRECT**
  (`reason: "unexpected: ACT-ISOLATE-ENDPOINT -> vigix-win10-ps"`).
* This is **not a validator failure** (the recommendation was `VALIDATED` and is `COMPLIANT`: isolating the endpoint is allowed by PB-POWERSHELL step 1 and its evidence requirements were met)
  and **not a harness failure** (the harness executed every stage). It is the outcome the pre-registered rule defines.
* The Ground Truth was **not changed after seeing this result**. Whether PB-POWERSHELL step 1 should be an expected action for a scenario that does not prove compromise
  is a design decision; any change must be a new Ground Truth version fixed before the next evaluation round, not applied retroactively.
* Compliance (system/policy validity) and Correct Recommendation (match against Ground Truth) measure different things; 100 % / 0 of 1 is consistent with that.

## 7. Retry finding (root cause: `PARTIALLY_CONFIRMED`)

What happened (audit log `RECOMMENDATION_GENERATION_FAILED` + `RECOMMENDATION_GENERATED`):

* The first `GenerateRecommendation` call used its bounded internal correction (`attempts: 2`): **both** model answers were rejected.
  * answer 1: `INVENTED_TARGET` for `ACT-DISABLE-ACCOUNT` (target `DESKTOP-3MP7GB3\kanoknipha`, one backslash) and for `ACT-KILL-PROCESS` (path with single backslashes);
  * answer 2: the same `INVENTED_TARGET` for `ACT-DISABLE-ACCOUNT`; `ACT-KILL-PROCESS` now used the stored (doubled) path, passed the target check and failed with `INSUFFICIENT_EVIDENCE: COMMAND_LINE`
    (the incident has no command-line IOC: Sysmon event 22 does not carry one - a correct rejection).
* The second call produced one answer that passed validation (`attempts: 1`).
* Therefore the run contains **3 model responses** for the recommendation (2 + 1), while the harness counts **retry = 1** (failed use-case calls).
* **The raw model output of the first call was not persisted** (the audit log keeps the violation texts only; the orchestrator console is not an artifact).

Evidence about the escaped / duplicated backslashes (counted with SQL on the stored values):

| Value | Real backslashes |
|---|---|
| Windows' own text (`system.message`, `Image: C:\Windows\System32\...`) | single (5 separators) |
| `data.win.eventdata.image` as produced by Wazuh and stored by VIGIX | **10** (each separator doubled) |
| stored `USERNAME` IOC `DESKTOP-3MP7GB3\\kanoknipha` | **2** |
| target given by the model for `ACT-DISABLE-ACCOUNT` (both answers) | **1** |

* Confirmed: the validator compares targets as exact strings; the model's target and the stored IOC differ by backslash representation; the doubling is already present in the alert Wazuh produced.
* Supporting but **not proof**: the prompt shows the same IOC in two forms (raw `value=...` in the IOC list, `JSON.stringify` in "Targetable values"), and the same model writes the user with one backslash in its own analysis text.
* **Not established:** the internal mechanism by which the model produced the one-backslash form. No claim is made about it.
* No code was changed to address this (see section 11).

## 8. Re-hunt limitation

* Verification mode `REAL_WAZUH`, evidence source `WAZUH_INDEXER`, index `wazuh-alerts-4.x-*`.
* Searched IOC: `searchedIocs = [DOMAIN vigix-eval-ps-stager.test]`; hosts `[vigix-win10-ps]`; `excludedIocs = []`; nothing skipped. The detection-rule signature is passed to the adapter but the adapter searches by IOC only.
* `matchingEvents = 0`, `iocRecurrence = false`, `threatContained = true`. The result is derived by `CreateVerification` from the search evidence; **no `RESOLVED` is hard-coded** anywhere in the harness.
* **There was no recurrence control.** The scenario was not repeated after the response and the runner's `--recurrence` option was not used, so this run does not show that the re-hunt would have reported `NOT_RESOLVED` had the activity recurred
  (that capability is only exercised by the adapter's own tests and by earlier runs of other cases).
* `RESOLVED` therefore means: **the IOC was not found in the verification window** (10:40:20Z - 10:40:35Z). It is not proof that the threat was eradicated.

## 9. Operator limitation

* The scenario was triggered **by a person** on the Windows VM (harness mode `manual`).
* "Detection latency" (65.54 s) is measured from the moment the runner started waiting (10:36:55.616Z) to the Wazuh alert (10:38:01.155Z); the operator ran the command at about 10:37:56Z.
  **It contains the operator's waiting and reaction time and must not be read as VIGIX detection latency.**
* Investigation Time (129.24 s) starts when VIGIX opens the investigation (10:38:07.957Z) and **does not include** the operator waiting time; it must not be mixed with the detection figure.
* The alert reached VIGIX about 6.75 s after the Wazuh alert timestamp.

## 10. Preflight attempt #1

* The first launch (about 10:35Z; file time 17:35 +07) **failed in preflight, before any case execution**: check `Wazuh manager API` was DOWN because `WAZUH_API_URL` pointed to port 55000, which the manager does not publish (it is published on 55500).
* No case data was written (`soar_tc05_eval` had 0 alerts afterwards). The failure is **not a TC-05 evaluation result**.
* Evidence kept: `preflight-failed.json` and `logs/main-run.preflight-failed-wazuh-api-55000.log`.
* **Attempt #2** (start 10:36:46Z, with the process-level override `WAZUH_API_URL=https://localhost:55500`) is the run whose result is reported here: its preflight passed every check and `run.json` contains one case, TC-05.

## 11. Not done, by decision (would change the implementation and require a full re-run)

* No change to backslash handling (extractor, validator, prompt builder).
* No candidate logging added to `RECOMMENDATION_GENERATION_FAILED`.
* No change to `groundTruthReal.ts`, `groundTruthCorrectness.ts`, `correctRecommendation.ts`, the validator, `alertIocs.ts`, the prompt builder, `WazuhRehuntAdapter`, `EvaluationService`, metric definitions or the playbook/policy/action seeds.

## 12. Other limitations

* One run, one case, one LLM endpoint; no confidence interval is claimed.
* Controlled telemetry: real Sysmon event on a real Windows endpoint, but detected by a custom rule written for this exact lab name.
* The IR approval is a scripted API call; Time-to-Decision is not a human decision time.
* The unit "generation" differs between documents: the harness and the v2 report count use-case calls; this run needed 3 model responses for 2 calls (see section 7 and `FREEZE-AUDIT.md` finding F-1).

## 13. Artifacts (SHA-256)

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
