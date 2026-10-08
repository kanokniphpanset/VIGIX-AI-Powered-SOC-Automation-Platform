# Final Evaluation v3.3 — REAL_WAZUH, TC-01 … TC-10

All numbers below come from this run only (`run.json`, `metrics/final-metrics.json`, PostgreSQL `soar_v33_eval`). No value from v2, from the TC-05 E2E run or from the retrospective rescoring (5/9, 5/10) is used.

## 1. Evaluation Overview
| Item | Value |
|---|---|
| Run ID | `final-evaluation-v3.3` |
| Window (UTC) | 2026-10-03T11:38:02Z → 12:04:53Z (26 min 51 s) |
| Type / mode | REAL_WAZUH / `intervention`; IR decision = scripted `approve` (stands in for the human IR_TEAM) |
| Cases | TC-01 … TC-10 in one run; **10 evaluated, 0 excluded** |
| TC-05 timing mode | OPERATOR_TRIGGERED (a person ran the scenario on the Windows VM) |
| Infrastructure events | 0 (LLM never unreachable) |

## 2. Environment
Branch `feature/report-period-windows`, commit `245b536` (no tracked change); DB `soar_v33_eval` (KB cloned, workflow tables emptied, verified 0 rows before the run, DB bound to the :8001 orchestrator — see FREEZE-AUDIT §4); model `vllm-spark-01/gemma4-26b-uncensored`; Wazuh 4.9.2 (manager in Docker, API :55500), agents 009 (Linux attack-endpoint) and 010 (`vigix-win10-ps`, Windows 10, Sysmon 15.22); custom rules file hash `f3da602b…0f9a`; `REHUNT_PROVIDER=wazuh`, `RECOMMENDATION_AGENT=llm`; the 12 related test suites passed 210/210 before the run.

## 3. Ground Truth
`correctness-gt-v3.3` SHA-256 `d2f1dae6…5951a8`; `REAL_GROUND_TRUTH` SHA-256 `9a800bab…69f6de`; both identical before and after the run (recomputed). TC-05 = `ACT-BLOCK-DOMAIN → vigix-eval-ps-stager.test`, no ISOLATE, no optional pair.

## 4. Evaluation Protocol
Per case: attack/simulation → real Wazuh alert read from the indexer → ingest → investigation + AI analysis → AI recommendation (validator; up to 5 use-case calls, each with one internal correction) → IR decision (scripted approve) → scripted response → REAL_WAZUH re-hunt → deterministic scoring (no LLM judge). Correct Recommendation is strict: playbook match AND every expected (action, target) pair present AND no unexpected pair. The AI never executes a response; every incident went through `human_approval` / IR_TEAM.

## 5. Test Case Results
| Case | Expected Action→Target | AI Action→Target (final) | Correct | Compliance | First-pass | IOC Recall | Workflow | Re-hunt |
|---|---|---|---|---|---|---|---|---|
| TC-01 | BLOCK-SOURCE-IP→attacker IP | BLOCK-SOURCE-IP→172.19.0.3 | **Correct** | COMPLIANT | yes | 2/2 | complete | RESOLVED |
| TC-02 | QUARANTINE-FILE→Invoice_Q4_2026.xls.exe; BLOCK-HASH→275a021b…fd0f; ISOLATE-ENDPOINT→attack-endpoint | ISOLATE-ENDPOINT→attack-endpoint | Incorrect (missing QUARANTINE-FILE, BLOCK-HASH) | COMPLIANT | yes | 0/2 | incomplete (open) | none (REHUNT_INSUFFICIENT_CRITERIA) |
| TC-03 | BLOCK-URL, BLOCK-DOMAIN, QUARANTINE-EMAIL (phish.net values) | QUARANTINE-EMAIL, BLOCK-URL, BLOCK-DOMAIN (same values) | **Correct** | COMPLIANT | no (3 calls, 2 failed) | 4/4 | complete | RESOLVED |
| TC-04 | DISABLE-ACCOUNT→victim; RESET-CREDENTIAL→victim; BLOCK-SOURCE-IP→attacker IP | the three expected + **REVOKE-SESSION→victim** | Incorrect (unexpected REVOKE-SESSION) | COMPLIANT | yes | 2/2 | complete | RESOLVED |
| **TC-05** | **ACT-BLOCK-DOMAIN → vigix-eval-ps-stager.test** | **none — NO_VALID_RECOMMENDATION after 5 calls** | **Incorrect (no final recommendation)** | NOT_EVALUATED | no (5 calls, 5 failed) | 1/1 | incomplete (open) | not reached |
| TC-06 | BLOCK-SOURCE-IP→attacker IP | BLOCK-SOURCE-IP→172.19.0.3 | **Correct** | COMPLIANT | yes | 1/1 | complete | RESOLVED |
| TC-07 | BLOCK-DOMAIN→c2.net; BLOCK-DESTINATION-IP→test server | the two expected + **BLOCK-URL, ISOLATE-ENDPOINT** | Incorrect (2 unexpected) | COMPLIANT | yes | 3/3 | complete | RESOLVED |
| TC-08 | KILL-PROCESS, QUARANTINE-FILE→/tmp/.cache/kworkerd; BLOCK-HASH→sha256 | same three pairs | **Correct** | COMPLIANT | yes | 4/4 | complete | RESOLVED |
| TC-09 | BLOCK-DOMAIN→exfil.net; BLOCK-DESTINATION-IP→test server | the two expected + **BLOCK-URL, ISOLATE-ENDPOINT** | Incorrect (2 unexpected) | COMPLIANT | yes | 3/3 | complete | RESOLVED |
| TC-10 | DISABLE-ACCOUNT→evaluser | DISABLE-ACCOUNT + **REVOKE-SESSION→evaluser** | Incorrect (unexpected REVOKE-SESSION) | COMPLIANT | yes | 1/1 | incomplete (open) | none (REHUNT_INSUFFICIENT_CRITERIA: no supported IOC to query) |

## 6. Correct Recommendation (primary metric)
**Correct Recommendations = 4/10 = 40.00 %** (correct: TC-01, TC-03, TC-06, TC-08; incorrect: TC-02, TC-04, TC-05, TC-07, TC-09, TC-10).
The denominator is 10: no case was excluded. TC-05 is counted as *not correct* because the system produced no valid final recommendation; the harness records `correctRecommendation = null` for it. For reference only, among the 9 cases that did produce a recommendation: 4/9 = 44.44 %.
Failure types of the 6 incorrect cases: TC-02 has missing pairs (and is the only case with a missing pair); TC-04, TC-07, TC-09 and TC-10 contain all expected pairs **plus** unexpected extras (REVOKE-SESSION ×2, BLOCK-URL ×2, ISOLATE-ENDPOINT ×2), so they fail only the strict no-unexpected-pair rule; TC-05 has no recommendation.

## 7. Recommendation Compliance (a different metric — not accuracy)
COMPLIANT in 9/9 evaluated cases (9/10 of all cases; TC-05 is NOT_EVALUATED because no recommendation exists to evaluate). Compliance checks policy/playbook/evidence rules; 5 of those 9 COMPLIANT cases are Incorrect under the Ground Truth (TC-02, 04, 07, 09, 10).

## 8. Consistency
Core Recommendation Consistency: **not measured** — this was a single run with no repeated generations, so there is no numerator/denominator. The v2 figure (30/30) is not carried over.

## 9. First-pass / Retry / Intervention
* First-pass (first use-case call valid): **8/10 = 80 %** (failures: TC-03, TC-05). Response-level first-pass was not computed.
* Retry rate: cases needing at least one re-generation call **2/10** (TC-03, TC-05); failed use-case calls 7 of 16 total.
* Intervention rate: **2/10** — both `ANALYST_IOC_CORRECTION` (TC-03, TC-05: promote an existing IOC to analyst-confirmed/actionable). Recorded, not hidden.
* Escalation (re-hunt escalation after R_max rounds): **0/7 re-hunts, 0 %** - every executed re-hunt ended RESOLVED in round 1, so the escalation path was never triggered and this run proves nothing about it. (Separately: all 10 incidents required IR_TEAM human approval under RULE-P07; 9 approvals were created and approved by the scripted IR step; TC-05 never reached approval. That is an approval requirement, not an escalation.)
* Infrastructure failure rate: 0/10.

## 10. IOC Recall
21/23 = 91.30 % of expected IOCs; 9/10 cases with full recall. Only TC-02 failed (0/2: hash and file path not extracted).

## 11. Workflow Completion
7/10 (TC-01, 03, 04, 06, 07, 08, 09). Not complete: TC-02 and TC-10 (re-hunt could not run, so the incident stays open) and TC-05 (no recommendation).

## 12. Verification / Re-hunt
Re-hunt executed 7/10; RESOLVED 7/10. "RESOLVED" means only that no related event was found within the configured re-hunt scope and time window; it does not prove the threat was eradicated. TC-02 and TC-10: REHUNT_INSUFFICIENT_CRITERIA. TC-05: not reached. The TC-05 control check (unrelated domain `vigix-eval-control-unrelated.test` → 0 matches) was made at preflight; it was not repeated in the run because TC-05's re-hunt never executed.

## 13. Investigation Time
Alert ingest → recommendation, 9 cases with a value (TC-05 has none): mean 95.86 s, median 77.77 s, min 47.10 s (TC-06), max 243.43 s (TC-03, with retries). TC-05 detection latency of 43.58 s includes the operator's reaction time.

## 14. Failures and Limitations
* **TC-05 failure (a genuine model/validator result, not infrastructure):** all 5 use-case calls (10 model responses) were rejected with `INVENTED_TARGET` (e.g. `ACT-DISABLE-ACCOUNT` on `DESKTOP-3MP7GB3\kanoknipha`, `ACT-KILL-PROCESS` on the `powershell.exe` path) and `INSUFFICIENT_EVIDENCE` (KILL-PROCESS requires COMMAND_LINE). The model never produced a valid recommendation, so `ACT-BLOCK-DOMAIN` was never accepted. Violations: `validation/recommendation-generation-failures.json`. The alert, severity (high, from Wazuh level 12), MITRE T1059.001 and the DOMAIN IOC were correct.
* TC-05 limits: custom rule 100300 matching this exact lab name; operator-triggered; Sysmon on the VM was not directly inspected by this session; N = 1.
* The strict metric penalises every extra action; 4 of the 6 incorrect cases contain all expected pairs plus extras.
* Single run, one model, no repeats: no variance or confidence interval; consistency not measured.
* The IR approval is a script, not a human.
* GT v3.1–v3.3 were designed after the v2 outputs had been seen; this is the first run under the frozen GT.

## 15. Integrity / Reproducibility
GT unchanged (both SHA-256 recomputed after the run equal the freeze values); no tracked file modified (HEAD `245b536`); all files in `metrics/prerun-file-sha256.txt` identical after the run; evaluation DB isolated (`soar_v33_eval`, 0 workflow rows before the run); no mock alert, no injected indexer event; no source/GT/playbook/policy/validator edit during the run; nothing committed. Artifacts: `run.json`, `metrics/final-metrics.json`, `cases/TC-xx.json`, `validation/`, `logs/run-console.txt`, `logs/audit_logs-full.json`.

## 16. Conclusion
Under the frozen GT v3.3 the system produced a strictly correct recommendation in 4 of 10 cases (40.00 %). Compliance was 9/9 for evaluated cases but is not accuracy. TC-05 was executed on the real Windows/Sysmon path, but the model produced no validator-accepted recommendation in 5 calls. Workflow completed in 7/10 and re-hunt resolved 7/10 within the configured scope. These results come from a single run of one model.
