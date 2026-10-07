# VIGIX additional evaluation — paper results

Generated 2026-09-30T13:13:16.033Z. Real Wazuh main results are **frozen** (quoted from `results/evaluation-audit.json`; 17 values checked identical). Baseline, consistency and negative validation are separate, newly measured conditions. The earlier MOCK evaluation is not used in any table. *Recommendation Compliance/Consistency* are not accuracy; *RESOLVED* means the verification procedure did not detect the specified recurrence condition within the tested window, not proof of eradication.

## Table 1 — Evaluation cases (Real Wazuh, Clean Run v2)

| Case | Attack type | Wazuh rule | MITRE technique | Evaluation status | Recommendation (Clean Run) | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| TC-01 | Brute Force | 5712 (L10; stock rule) | T1110 | Evaluated end to end | PB-SSH-BRUTEFORCE: BLOCK-SOURCE-IP (COMPLIANT) | RESOLVED (REAL_WAZUH) |
| TC-02 | Malware | 100301 (L12; custom rule, real action) | T1204.002 | Recommendation scored; re-hunt ERROR | PB-MALWARE: ISOLATE-ENDPOINT (COMPLIANT) | ERROR INSUFFICIENT_CRITERIA |
| TC-03 | Phishing | 100310 (L10; custom rule, controlled telemetry) | T1566.002 | Attempted — no valid recommendation | none (validator rejected every attempt) | not reached |
| TC-04 | Account Compromise | 40112 (L12; stock rule) | T1078, T1110 | Evaluated end to end | PB-ACCOUNT-COMPROMISE: DISABLE-ACCOUNT, BLOCK-SOURCE-IP, RESET-CREDENTIAL, … (COMPLIANT) | RESOLVED (REAL_WAZUH) |
| TC-05 | PowerShell | – | T1059.001 (expected) | ENVIRONMENT_UNAVAILABLE (no Windows endpoint) | not run | not run |
| TC-06 | SQL Injection | 31103 (L7; stock rule) | T1190 | Evaluated end to end | PB-SQL-INJECTION: BLOCK-SOURCE-IP (COMPLIANT) | RESOLVED (REAL_WAZUH) |
| TC-07 | Command & Control | 100320 (L13; custom rule, controlled telemetry) | T1071.001 | Evaluated end to end | PB-C2: BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, … (COMPLIANT) | RESOLVED (REAL_WAZUH) |
| TC-08 | Suspicious Process | 100330 (L10; custom rule, controlled telemetry) | T1059.004 | Attempted — no valid recommendation | none (validator rejected every attempt) | not reached |
| TC-09 | Data Exfiltration | 100340 (L13; custom rule, controlled telemetry) | T1048 | Evaluated end to end | PB-DATA-EXFIL: BLOCK-DESTINATION-IP, BLOCK-DOMAIN, ISOLATE-ENDPOINT (COMPLIANT) | RESOLVED (REAL_WAZUH) |
| TC-10 | Privilege Escalation | 100350 (L14; custom rule, real action) | T1098 | Recommendation scored; re-hunt ERROR | PB-ACCOUNT-COMPROMISE: DISABLE-ACCOUNT, RESET-CREDENTIAL (COMPLIANT) | ERROR INSUFFICIENT_CRITERIA |

## Table 2 — Main VIGIX evaluation (Real Wazuh, Clean Run v2)

| Metric | Value | Numerator / denominator | Population |
| --- | ---: | ---: | --- |
| Recommendation Compliance | 100% (among evaluated) · 77.78% (among attempted) | 7/7 · 7/9 | validated recommendations · attempted cases |
| Evidence Coverage | 77.78% | 7/9 | attempted cases |
| Playbook Alignment | 100% | 7/7 | validated recommendations |
| Policy Compliance | 100% | 7/7 | validated recommendations |
| Workflow Completion | 55.56% | 5/9 | attempted cases |
| Investigation Time | mean 40.27 s, median 33.79 s, SD 26.61 s, min 22.32 s, max 98.12 s | n = 7 | cases with a recommendation |
| Intervention Rate | 0% | 0/9 | attempted cases (no correction allowed in a Clean Run) |
| Retry Rate (cases with ≥ 1 retry) | 22.22% | 2/9 | attempted cases; total retry count 10 (a count, mean 1.11/case) |

## Table 3 — Clean Run vs Intervention Run (Real Wazuh)

| Metric | Clean Run | Intervention Run |
| --- | ---: | ---: |
| Recommendation Compliance (among evaluated) | 100% (7/7) | 100% (9/9) |
| Recommendation Compliance (among attempted) | 77.78% (7/9) | 100% (9/9) |
| Workflow Completion | 55.56% (5/9) | 77.78% (7/9) |
| Investigation Time | mean 40.27 s (n=7); median 33.79, SD 26.61 | mean 72.23 s (n=9); median 46.46, SD 79.55 |
| Detection-to-Response (from VIGIX ingest) | mean 40.39 s (n=7) | mean 72.34 s (n=9) |
| Intervention Rate | 0% (0/9) | 22.22% (2/9) |
| Retry Rate (cases) | 22.22% (2/9); total retries 10 | 22.22% (2/9); total retries 6 |
| Verification outcomes | 5 RESOLVED, 2 ERROR | 7 RESOLVED, 2 ERROR |

The Intervention Run is a different condition (analyst-assisted); it is shown for comparison and is not the system's unaided performance.

## Table 4 — Controlled procedural baseline vs VIGIX (comparable measurements only)

| Metric | Baseline (no AI, n = 9) | VIGIX Clean Run | VIGIX Intervention Run | Comparability |
| --- | ---: | ---: | ---: | --- |
| Case produced a proposed response (coverage) | 9/9 | 7/9 (valid recommendation) | 9/9 | same population of 9 evaluable cases |
| Playbook alignment among proposed responses | 9/9 | 7/7 | 9/9 | same ground truth, same deterministic check |
| Attack alignment (actions inside the allowed set) | 9/9 | 7/7 | 9/9 | same ground truth, same deterministic check |
| Response actions per proposed response (mean) | 2.78 (n=9) | 2.29 (n=7) | 2.22 (n=9) | count of steps/actions in the proposal |
| Investigation time (start → proposed response available), mean | 0.013 s (median 0.01, SD 0.009, n=9) | 40.27 s (median 33.79, SD 26.61, n=7) | 72.23 s (median 46.46, SD 79.55, n=9) | same interval definition; different content (baseline has no LLM stage) — machine latency, not analyst performance |

**Not compared (measurements are not comparable):** decision latency (baseline value is NULL: no approval instance and no human; VIGIX's ≈0.06 s is a scripted approval); evidence/indicator counts (VIGIX's incident also holds AI-extracted indicators, the baseline only deterministic ones); policy compliance, approval correctness, verification (the baseline has no Policy/approval/verification stage); required-evidence gating (the baseline treats every extracted indicator as confirmed, VIGIX only evidence-linked or analyst-added ones).

## Table 5 — Recommendation consistency (identical evidence, repeated runs)

| Case | Runs | Consistent runs | Consistency % | Validated runs | Distinct validated primary recommendations |
| --- | ---: | ---: | ---: | ---: | ---: |
| TC-01 | 5 | 5 | 100 | 5 | 1 |
| TC-02 | 5 | 5 | 100 | 5 | 1 |
| TC-04 | 5 | 5 | 100 | 5 | 1 |
| TC-06 | 5 | 5 | 100 | 5 | 1 |
| TC-07 | 5 | 4 | 80 | 5 | 2 |
| TC-09 | 5 | 5 | 100 | 5 | 1 |
| **All cases (pooled)** | 30 | 29 | 96.67 | 30 | – |

Per-case mean 96.67% (SD 8.16 percentage points over 6 cases). Consistent = same playbook, primary action, target type and target value as the modal validated primary recommendation; runs that fail validation count as inconsistent. The evidence snapshot hash was identical in every repetition of every case.

## Table 6 — Negative validation (controlled invalid recommendations)

| Scenario | Invalid condition | Expected | Actual | Validator | Policy | Final result |
| --- | --- | --- | --- | --- | --- | --- |
| NEG-01 Unsupported target (IOC not in the evidence) | the recommended target is an IP address that does not exist in the incident's evidence | VALIDATOR REJECT (INVENTED_TARGET) | REJECTED | INVALID: INVENTED_TARGET, INVENTED_IOC | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-02 Required evidence type absent | ACT-KILL-PROCESS on a recorded process while the COMMAND_LINE evidence it requires is absent from the incident | POLICY REJECT (INSUFFICIENT_EVIDENCE) | REJECTED | INVALID: INSUFFICIENT_EVIDENCE | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-03 Policy: wrong responsible role | responsibleRole "IR_TEAM" while Policy assigns "SOC" to this action | POLICY REJECT (WRONG_RESPONSIBLE_ROLE) | REJECTED | INVALID: WRONG_RESPONSIBLE_ROLE | POLICY-DERIVED: WRONG_RESPONSIBLE_ROLE | REJECTED |
| NEG-04 Policy: approval waived | candidate marks approval as not required and says to execute without approval while Policy requires an approval | POLICY REJECT (POLICY_BYPASS) | REJECTED | INVALID: POLICY_BYPASS | POLICY-DERIVED: POLICY_BYPASS | REJECTED |
| NEG-05 Action outside the selected playbook | ACT-ISOLATE-ENDPOINT is not allowed by the SQL-injection playbook | VALIDATOR REJECT (ACTION_NOT_IN_PLAYBOOK) | REJECTED | INVALID: ACTION_NOT_IN_PLAYBOOK, ACTION_NOT_APPLICABLE, RUN… | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-06 Action that does not exist in the Action Catalog | the recommended action code ACT-WIPE-DISK is not in the catalog | VALIDATOR REJECT (INVENTED_ACTION) | REJECTED | INVALID: INVENTED_ACTION | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-07 Target of the wrong type for the action | ACT-BLOCK-SOURCE-IP (operates on an IP) aimed at the host "attack-endpoint" | VALIDATOR REJECT (TARGET_TYPE_MISMATCH) | REJECTED | INVALID: TARGET_TYPE_MISMATCH | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-08 Playbook different from the backend-selected one | step names playbook PB-MALWARE while the backend selected PB-SQL-INJECTION | VALIDATOR REJECT (PLAYBOOK_MISMATCH) | REJECTED | INVALID: PLAYBOOK_MISMATCH | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-09 Fabricated evidence reference | evidenceRefs cites "E99", an evidence id that does not exist in this investigation | VALIDATOR REJECT (INVENTED_EVIDENCE) | REJECTED | INVALID: INVENTED_EVIDENCE, NO_EVIDENCE | no Policy-derived violation (rejected by validator knowledg… | REJECTED |
| NEG-10 Invented indicator in free text | the reason cites the IP 203.0.113.250, which is not in the incident evidence | VALIDATOR REJECT (INVENTED_IOC) | REJECTED | INVALID: INVENTED_IOC | no Policy-derived violation (rejected by validator knowledg… | REJECTED |

Unsupported Recommendation Rejection Rate = 10/10 = 100% (Policy-derived rules rejected 2 scenarios (NEG-03, NEG-04: responsible role, approval waiver) and validator knowledge/grounding rules rejected 8; NEG-02 was expected at the Policy layer but the required evidence (COMMAND_LINE for ACT-KILL-PROCESS) comes from the Action's own knowledge, not from an ACTION_COMPLIANCE policy, so it was rejected at the validator layer — the layer expectation was mis-specified, the rejection itself occurred); 10/10 were rejected with the expected violation code. Each scenario's unmodified candidate first validated (positive control), so each rejection is attributable to the injected fault.

### Table 6b — Human-decision and governance gates (real use cases, cloned database)

| Check | Scenario | Expected | Actual | Result |
| --- | --- | --- | --- | --- |
| G0 | SOC sends step 2 of a validated recommendation to IR | ticket PENDING_IR_DECISION (needs IR decision) | OK(PENDING_IR_DECISION) | PASS |
| G1 | start the response before any IR decision | blocked (APPROVAL_PENDING) | APPROVAL_PENDING | PASS |
| G2 | re-hunt/verification requested before the response is completed | blocked (RESPONSE_NOT_COMPLETED) | RESPONSE_NOT_COMPLETED | PASS |
| G3 | approval attempted by role "SOC" (approval belongs to IR_TEAM) | denied (ROLE_MISMATCH) | ROLE_MISMATCH | PASS |
| G4 | approval attempted by role "AI_AGENT" (approval belongs to IR_TEAM) | denied (ROLE_MISMATCH) | ROLE_MISMATCH | PASS |
| G5 | approval attempted by role "admin" (approval belongs to IR_TEAM) | denied (ADMIN_NOT_APPROVER) | ADMIN_NOT_APPROVER | PASS |
| G6 | IR_TEAM decision without a note | denied (NOTE_REQUIRED) | NOTE_REQUIRED | PASS |
| G7 | denied attempts left the ticket untouched | PENDING_IR_DECISION, approval pending | PENDING_IR_DECISION, approval pending | PASS |
| G8 | IR REJECTS the AI recommendation | ticket → PENDING_MANUAL_DECISION (not executed, not closed) | OK(rejected); ticket PENDING_MANUAL_DECISION | PASS |
| G9 | a reject does not close or resolve the incident | incident status unchanged (open) | open | PASS |
| G10 | start the response after the reject | blocked (APPROVAL_PENDING) | APPROVAL_PENDING | PASS |
| G11 | the rejected recommendation was never executed | 0 step executions | 0 step executions | PASS |
| G12 | decide the same approval twice | denied (ALREADY_DECIDED) | ALREADY_DECIDED | PASS |
| G13 | manual decision after reject by a non-IR role | denied (ROLE_MISMATCH) | ROLE_MISMATCH | PASS |
| G14 | manual decision by IR without a note | denied (NOTE_REQUIRED) | NOTE_REQUIRED | PASS |
| G15 | IR records the manual decision after the reject | ticket → READY_FOR_EXECUTION with a stored IR note; nothing executed automatically | OK(READY_FOR_EXECUTION); READY_FOR_EXECUTION; step executions 0 | PASS |
| G16 | manually mark the incident RESOLVED (bypassing verification) | blocked (RESOLVE_REQUIRES_VERIFICATION); status unchanged | RESOLVE_REQUIRES_VERIFICATION; status open | PASS |

Governance gate checks passed: 17/17.