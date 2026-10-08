# Supplementary Test — Re-hunt Escalation (R_max = 3)

**Scope.** Supplementary test, separate from `final-evaluation-v3.3`. Nothing in the Final Evaluation was changed (Correct Recommendation stays 4/10 = 40.00 %; Compliance, Workflow Completion, Ground Truth and the Final DB/artifacts untouched). The result is not combined with the 10 Final cases.

## 1. Test Objective
Check that when an incident has had a response and the Wazuh re-hunt still cannot confirm resolution in 3 consecutive rounds (`R_max = 3`, `MAX_INVESTIGATION_ROUNDS` in `CreateVerification.usecase.ts`), the system sets the incident to ESCALATED (`escalated`) and does not start a 4th round:

```text
Response → Re-hunt #1 NOT_RESOLVED → Re-hunt #2 NOT_RESOLVED → Re-hunt #3 NOT_RESOLVED → ESCALATED (no round 4)
```

This is the *re-hunt* escalation. IR_TEAM approval requirements and IR rejections are different things and are not counted as escalation here.

## 2. Why this runner and this case
* `run-real-evaluation.ts --recurrence` performs **one** re-hunt per case, so it can show one NOT_RESOLVED but cannot reach round 3 / ESCALATED.
* The repository's own runner `scripts/eval/extended/run-escalation.ts` (used earlier for the Extended Evaluation) does the full loop with the product code and real Wazuh evidence. It was run **unmodified**.
* Case: ESC-01, which reuses **TC-07** C2-beacon telemetry (Wazuh rule 100320, level 13, high). Chosen because its IOCs (IPv4, domain, URL) are searchable by the REAL_WAZUH re-hunt and the beacon can be repeated deterministically after each response. It was not chosen to force a result: the NOT_RESOLVED / reopen / ESCALATE decisions are made by product code from indexer evidence.

## 3. Environment
| Item | Value |
|---|---|
| Source | branch `feature/report-period-windows`, HEAD `245b536`, no tracked diff |
| Run label / runner | `supp-escalation-20261003` / `run-escalation.ts` (unmodified) |
| Window (UTC) | 2026-10-03T12:31:06Z → 12:34:22Z |
| R_max | 3 |
| Model | `vllm-spark-01/gemma4-26b-uncensored`; Wazuh 4.9.2, agent 009; `REHUNT_PROVIDER=wazuh` |
| GT | escalation ground truth SHA-256 `bd8aeaf8…7d79` equals the pin in `results/extended-evaluation/ground-truth.sha256` (unchanged); correctness GT v3.3 and `REAL_GROUND_TRUTH` not used or modified |
| Database | the runner only accepts the name `soar_ext_eval`. The historic `soar_ext_eval` (27 alerts / 21 incidents / 815 audit logs) was renamed `soar_ext_eval_archive_20261003` (data verified identical), and a fresh `soar_ext_eval` (KB copy, all workflow tables 0 rows; playbooks 11, actions 14, policies 29, MITRE 26, runbooks 17) was used. Afterwards the fresh DB was renamed `soar_supp_escalation` (1 alert, 1 incident, 3 verifications, 99 audit logs) and the archive was restored to `soar_ext_eval` (27 alerts, 21 incidents, 16 recommendations, 13 verifications, 815 audit logs: identical to before). |
| Runtime DB proof | `pg_stat_activity`: 5 sessions, all `soar_ext_eval`; orchestrator PID 15220 holds 5 Postgres connections (`logs/runtime-db-pg_stat_activity.txt`) |
| Incident | `47e1cf76-9ffb-4fb1-9623-cbb09611c706` |

## 4. Re-hunt Evidence
| Round | Outcome | Evidence | Continue? |
|---|---|---|---|
| 1 (investigation #1) | **NOT_RESOLVED** | recurrence alert `1791030772.2028579` in the indexer; 3 matching events, IOC recurrence true; verification `d59bc04b…` 12:33:14 | yes → investigation #2 reopened, incident `investigating` |
| 2 (investigation #2) | **NOT_RESOLVED** | recurrence alert `1791030800.2031225`; 3 matching events; verification `8ec65c73…` 12:33:46 | yes → investigation #3 reopened, incident `investigating` |
| 3 (investigation #3) | **NOT_RESOLVED** | recurrence alert `1791030832.2033871`; 3 matching events; verification `a01e64f6…` 12:34:19 | **no** → incident `escalated` (`MAX_INVESTIGATION_ROUNDS_REACHED`), handed to SOC and IR_TEAM |

Per-round files: `evidence/rehunt-round-1.json` … `rehunt-round-3.json`; escalation audit trail: `evidence/escalation.json`; full extract: `evidence/db-extract.json`.

## 5. Escalation Result
* Observed final status: **escalated** (incident status; `closed_at` empty)
* Observed maximum re-hunt round: **3** (3 `REHUNT_STARTED`, 3 `VERIFICATION_COMPLETED`, investigations #1–#3)
* Round 4 observed: **NO**

## 6. Assertions
| Assertion | Expected | Observed | Result |
|---|---|---|---|
| Round 1 exists | YES | verification #1 + `REHUNT_STARTED` (investigation 1) | PASS |
| Round 2 exists | YES | verification #2 + `REHUNT_STARTED` (investigation 2) | PASS |
| Round 3 exists | YES | verification #3 + `REHUNT_STARTED` (investigation 3) | PASS |
| All 3 rounds unresolved | YES | NOT_RESOLVED ×3, none RESOLVED | PASS |
| Max observed round = 3 | 3 | 3 | PASS |
| Final status ESCALATED | YES | `escalated` | PASS |
| No Round 4 | YES | 3 verifications, 3 re-hunts, max investigation #3, 0 new response tickets or recommendations after round 3, a 2nd verification of the same ticket refused (`ALREADY_VERIFIED`) | PASS |
| Audit trail preserved | YES | `INVESTIGATION_REOPENED` ×2, `INVESTIGATION_ESCALATED` ×1, `INCIDENT_ESCALATED` ×1 (reason `MAX_INVESTIGATION_ROUNDS_REACHED`) | PASS |
| Escalation not caused by approval/other reasons | YES | reason list is only `MAX_INVESTIGATION_ROUNDS_REACHED`; the 3 IR approvals were scripted approvals, not escalation | PASS |

The runner's own checks R1a–R3a, E1–E10: **15/15 passed** (including: escalated incident cannot be resolved by hand — `RESOLVE_REQUIRES_VERIFICATION`; no AI/system actor changed the status; nothing executed after the escalation).

## 7. Result
**PASS** — within the scenario below.

## 8. Limitations and disclosures
* **New-round recommendations were not produced.** After round 1 and round 2 the automatic generation for the reopened investigation failed (`RECOMMENDATION_GENERATION_FAILED`, reason `NO_NEW_RECOMMENDATION`, 12 audit records; the runner also made 5 further model attempts per round, none VALIDATED). For rounds 2 and 3 the runner therefore handed an *unexecuted step of recommendation #1* to IR (a recorded harness fallback; see `run.json` `observations`). The escalation transition does not depend on this, but this test does **not** demonstrate "new AI recommendation each round".
* The recurrence is generated by the runner; the NOT_RESOLVED / reopen / ESCALATE decisions are the product's, based on real Wazuh indexer evidence (`evidenceSource = WAZUH_INDEXER`).
* IR approvals and the "manual" responses are scripted and simulated; no human participated and no containment was actually performed.
* Single scenario (TC-07 telemetry), single run, one model.
* The test uses the product's escalated status as the ESCALATED state; the system stores it as `escalated`.

## 9. Conclusion
In this supplementary scenario, three consecutive REAL_WAZUH re-hunts returned NOT_RESOLVED, the incident was set to `escalated` after the third, no fourth round was started, and the escalation is recorded in the audit trail with the reason `MAX_INVESTIGATION_ROUNDS_REACHED`. The test confirms the R_max = 3 escalation behavior for this scenario only; it does not evaluate recommendation quality, human performance or readiness for production use, and it does not change any Final Evaluation v3.3 result.

## 10. Files
`run.json` (copy of `results/extended-evaluation/runs/supp-escalation-20261003.json`, which the runner also wrote there), `logs/run-console.txt`, `logs/start.txt`, `logs/end.txt`, `logs/runtime-db-pg_stat_activity.txt`, `evidence/rehunt-round-{1,2,3}.json`, `evidence/escalation.json`, `evidence/db-extract.json`, `metrics/escalation-metrics.json`, `build_artifacts.py`.
