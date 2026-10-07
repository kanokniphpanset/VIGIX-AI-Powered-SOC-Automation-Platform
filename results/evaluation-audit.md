# VIGIX evaluation audit — preparation for the paper

Generated 2026-09-30T12:35:50.461Z · read-only audit of existing results · **no evaluation was re-run, no ground truth / policy / playbook / MITRE / result file was modified** (only `results/evaluation-audit.{md,json}` and three new scripts under `apps/backend/scripts/eval/` were added).

## 1. Executive summary

- **Data integrity: all 11 checks PASS.** Every one of the 19 evaluation alerts exists in the live Wazuh Indexer with identical rule/agent/timestamp; the audit re-score from PostgreSQL equals the stored `run.json` results for every case; the MOCK baseline is byte-identical to its archive and equals the stated baseline; the real ground truth hash is unchanged; timestamps are monotonic in every case.
- **Primary KPI (Real Wazuh, Clean Run v2, n = 9 attempted, 7 evaluated):** Recommendation Compliance 100% (7/7 evaluated; 77.78% of 9 attempted); Investigation Time mean 40.27 s / median 33.79 s (n=7); Time-to-Decision mean 0.06 s (scripted decision); Verification: 5/7 executed responses ended RESOLVED, 2 ended in re-hunt ERROR.
- **Intervention Run v2:** compliance 100% (9/9) after 2 analyst corrections (TC-03, TC-08); this is a *different condition* from the Clean Run and must not be reported as the system's unaided accuracy.
- **Verification control (recurrence):** confirmed from PostgreSQL — matching events = 29, iocRecurrence = true, result = NOT_RESOLVED, incident = investigating, investigations #1:COMPLETED / #2:ACTIVE (reopened by RULE-V01, RULE-V03). It is a single positive control on one case.
- **Not paper-ready as stated:** Time-to-Decision (scripted approval, ≈0.06 s), Verification Effectiveness as a claim of *containment* (responses were simulated, attacks ran once, sensitivity shown once), the MOCK timing metrics (contain manual gaps), and anything about rejection/manual-decision paths, ML risk score and Windows/PowerShell (no data). See §11–§12.
- **Overall verdict: NEEDS_MORE_DATA** for verification-related claims and human-decision timing; **READY_FOR_PAPER (with the stated caveats)** for Recommendation Compliance, Playbook Alignment, Policy Compliance, Workflow Completion, Investigation Time and the retry/intervention descriptions, provided the sample (10 predefined cases, 9 attempted, one run per condition) is stated.

## 2. Data Integrity Check

| ID | Check | Result | Detail |
| --- | --- | --- | --- |
| I1 | soar_eval contains exactly the incidents of the three primary runs | PASS | alerts=19, incidents=19, cases with incident in run.json=19 |
| I2 | every eval alert is siem_source=wazuh from the real lab agent | PASS | agents: attack-endpoint |
| I3 | every ingested alert exists in the live Wazuh Indexer with identical rule.id/agent/timestamp | PASS | 19/19 matched |
| I4 | no MOCK / manual verification exists in soar_eval | PASS | 13 verifications, 0 not from WAZUH_INDEXER |
| I5 | real ground truth unchanged since each run (sha256) | PASS | current ddb18d5d4dee4ffe…; runs: ddb18d5d4dee4ffe…, ddb18d5d4dee4ffe…, ddb18d5d4dee4ffe… |
| I6 | MOCK baseline archive is byte-identical to scripts/eval-out/evaluation.json | PASS | sha256 38a83f2fbf590b2c… |
| I7 | MOCK baseline equals the stated baseline (100% 10/10, 2152 s, 1387 s, 10/10 MOCK, 4/10, 43 retries) | PASS | {"compliance":"10/10","workflow":"10/10","invAvg":2151.98,"decAvg":1387.1,"verificationMock":10,"real":0,"retryCases":4,"retryTotal":43,"interventionCases":4} |
| I8 | audit re-score from PostgreSQL equals the stored run.json results | PASS | compliance, retries, verification result, investigation time and time-to-decision all agree for every case |
| I9 | timestamps are monotonic (alert ≤ … ≤ verification) in every case | PASS | no violations |
| I10 | real-run incidents are not shared between runs | PASS | 19 distinct incidents |
| I11 | soar_platform was not written by the harness (pre-eval baseline: 260 alerts / 39 incidents) | PASS | now {"alerts":260,"incidents":39,"latestAlert":"2026-09-30T10:26:19.940Z","evalAlertsAlsoInPlatform":0} — any growth in alerts comes from the manager's custom-vigix webhook, not from the harness |
| I12 | MOCK and REAL_WAZUH share no incident | PASS | 0 shared incident ids between the archived MOCK run and the three real runs |

Additional integrity observations (not failures, but they bound what the data can show):

- **Superseded runs are not in `soar_eval`.** Clean Run #1 and the partial post-fix run were followed by a database reset; only their `run.json` files (`results/runs/`) and SQL dumps (`backups/db/`) remain. They are excluded from every number below (register: `results/runs/README.md`).
- **The archived MOCK row for TC-01 is a hybrid**: its incident was built from a real Wazuh alert of agent `attack-endpoint` (the older `run-evaluation.ts` selects the latest alert by rule id only) with a mock verification. MOCK numbers are therefore given for the archived 10 cases *and* for the 9 pure-mock cases.
- **soar_platform was untouched**: 260 alerts / 39 incidents, identical to the pre-evaluation snapshot, and none of the evaluation alerts is present there (the manager's webhook hop to the development backend was not part of the evaluation path).
- **Verification provenance:** all 13 verifications in `soar_eval` carry `evidenceSource = WAZUH_INDEXER`; none is MOCK or manual.

## 3. Primary KPI

| Metric | Result | Numerator | Denominator | Mode | Paper Ready |
| ------ | -----: | -----: | -----: | ---- | ----------- |
| Recommendation Compliance — MOCK baseline (10 archived cases) | 100% | 10 | 10 | MOCK (deterministic scorer) | YES — with caveat: TC-01 is a hybrid; 4 cases needed intervention |
| Recommendation Compliance — MOCK (9 pure-mock cases) | 100% | 9 | 9 | MOCK | YES — with caveat |
| Recommendation Compliance — Real Clean | 100% | 7 | 7 | REAL_WAZUH (deterministic) | YES — with caveat: report BOTH denominators — 77.78% of 9 attempted (TC-03, TC-08 produced no valid recommendation) |
| Recommendation Compliance — Real Intervention | 100% | 9 | 9 | REAL_WAZUH (deterministic) | YES — with caveat: only together with the Clean result and the 2 analyst corrections |
| Investigation Time — MOCK baseline | mean 2151.98 / median 2062.9 / min 22.35 / max 5195.02 s | – | n=10 | MOCK stepwise run | NO: contains manual gaps of hours (max 5195 s); not a latency |
| Investigation Time — MOCK repeated single-pass (N=2) | mean 53.09 s ± 29.05 | – | 20 case-runs | MOCK uninterrupted | YES — with caveat: only 2 repetitions; mean ± SD only, no median in the file |
| Investigation Time — Real Clean | mean 40.27 / median 33.79 / min 22.32 / max 98.12 s | – | n=7 | REAL_WAZUH, uninterrupted | YES — with caveat: includes third-party LLM latency; excludes the 2 cases with no valid recommendation (right-censored); single run |
| Investigation Time — Real Intervention | mean 72.23 / median 46.46 / min 22.07 / max 265.41 s | – | n=9 | REAL_WAZUH, uninterrupted | YES — with caveat: includes retry rounds (TC-03 265 s, TC-08 129 s) and analyst-correction step |
| Time-to-Decision — MOCK baseline | mean 1387.1 / median 975.34 / min 0.05 / max 3426.44 s | – | n=10 | MOCK stepwise run | NO: mixes scripted (≈0.05 s) and manual-gap (up to 3426 s) decisions |
| Time-to-Decision — Real Clean | mean 0.06 / median 0.06 / min 0.04 / max 0.07 s | – | n=7 | REAL_WAZUH, scripted IR decision | NO as human decision time: it is the latency of a scripted API approval; report only as system overhead |
| Time-to-Decision — Real Intervention | mean 0.06 / median 0.06 / min 0.05 / max 0.06 s | – | n=9 | REAL_WAZUH, scripted IR decision | NO |
| Verification Effectiveness — MOCK | – | – | – | MOCK | NOT_AVAILABLE: MOCK NO_MATCH is simulated (CleanRehuntAdapter) — 10/10 completed is workflow reachability, not effectiveness |
| Verification Effectiveness — Real Clean | 71.43% | 5 | 7 | REAL_WAZUH | NO as an effectiveness claim — report as an outcome distribution (§8) |
| Verification Effectiveness — Real Intervention | 77.78% | 7 | 9 | REAL_WAZUH | NO |

Verification Effectiveness = cases whose real re-hunt confirmed no recurrence (`RESOLVED`) / cases with a completed response execution. Outcome vocabulary of the requested taxonomy as it maps onto VIGIX: `RESOLVED` = RESOLVED; `NOT_RESOLVED` = NOT_RESOLVED; `NOT_CONTAINED` = NOT_RESOLVED with `threatContained=false`; `SPREAD` = NOT_RESOLVED with `spreadDetected=true`; `ERROR` = re-hunt failed (`REHUNT_*`), no verification created.

Outcome distribution of executed responses: **Real Clean** {"RESOLVED":5,"ERROR":2} · **Real Intervention** {"RESOLVED":7,"ERROR":2} · **Recurrence control** {"NOT_CONTAINED":1}

## 4. Supporting Metrics

| Metric | Result | Numerator | Denominator | Mode | Paper Ready |
| ------ | -----: | -----: | -----: | ---- | ----------- |
| Workflow Completion — MOCK baseline | 100% | 10 | 10 | MOCK | YES — with caveat: 'complete' = all 11 workflow flags true incl. a MOCK verification |
| Workflow Completion — Real Clean | 55.56% (50% of all 10) | 5 | 9 | REAL_WAZUH | YES: recomputed from DB rows per step (not 'an incident exists'); incomplete = TC-02(re-hunt INSUFFICIENT_CRITERIA); TC-03(no valid recommendation); TC-08(no valid recommendation); TC-10(re-hunt INSUFFICIENT_CRITERIA) |
| Workflow Completion — Real Intervention | 77.78% (70% of all 10) | 7 | 9 | REAL_WAZUH | YES: incomplete = TC-02(re-hunt INSUFFICIENT_CRITERIA); TC-10(re-hunt INSUFFICIENT_CRITERIA) |
| Intervention Rate — MOCK baseline | 40% | 4 | 10 | MOCK | YES — with caveat: cases TC-03, 07, 08, 09 (analyst IOC, MITRE catalog, playbook seed) |
| Intervention Rate — Real Clean | 0% | 0 | 9 | REAL_WAZUH | YES — with caveat: 0% by construction (no correction is allowed in a Clean Run); blocked cases are counted as failures instead |
| Intervention Rate — Real Intervention | 22.22% | 2 | 9 | REAL_WAZUH | YES — with caveat: the 'analyst' is a fixed script; reason for both = Missing/non-actionable IOC (TC-03 e-mail; TC-08 process+command) |
| Recommendation Retry Rate — MOCK baseline | 40% | 4 | 10 | MOCK | YES — with caveat: total retry count 43 is a count, not a percentage |
| Recommendation Retry Rate — Real Clean | 22.22% | 2 | 9 | REAL_WAZUH | YES — with caveat: total retry count 10 (avg 1.11/case); TC-03 and TC-08 hit the harness cap of 5 → right-censored |
| Recommendation Retry Rate — Real Intervention | 22.22% | 2 | 9 | REAL_WAZUH | YES — with caveat: total retry count 6 (avg 0.67/case) |
| Evidence Coverage — MOCK baseline | 100% | 10 | 10 | MOCK | YES — with caveat: evidenceSupport criterion after manual IOC fixes |
| Evidence Coverage — Real Clean (per attempted case) | 77.78% | 7 | 9 | REAL_WAZUH | YES — with caveat: the informative figure — cases with no valid recommendation count as not covered |
| Evidence Coverage — Real Clean (per recommendation) | 100% | 7 | 7 | REAL_WAZUH | NO: tautological — only validator-passed recommendations exist, so 100% by construction |
| Evidence Coverage — Real Intervention (per attempted case) | 100% | 9 | 9 | REAL_WAZUH | YES — with caveat: after analyst IOC correction; membership test, not semantic (see TC-07 self-targeting) |
| Policy Compliance — MOCK baseline | 100% | 10 | 10 | MOCK | YES — with caveat |
| Policy Compliance — Real Clean | 100% | 7 | 7 | REAL_WAZUH | YES — with caveat: step approval flag == Policy snapshot and a responsible role present; no negative test exists |
| Policy Compliance — Real Intervention | 100% | 9 | 9 | REAL_WAZUH | YES — with caveat |
| Playbook Alignment — MOCK baseline | 100% | 10 | 10 | MOCK | YES — with caveat: measured after PB-C2/PB-DATA-EXFIL were seeded during the run |
| Playbook Alignment — Real Clean | 100% | 7 | 7 | REAL_WAZUH | YES — with caveat: obtained AFTER fixing a selector tie-break defect found in the first real run (TC-09 chose PB-C2 instead of PB-DATA-EXFIL) — disclose |
| Playbook Alignment — Real Intervention | 100% | 9 | 9 | REAL_WAZUH | YES — with caveat |
| Approval Correctness — MOCK baseline | 100% | 10 | 10 | MOCK | YES — with caveat: approvals recorded by scripts |
| Approval Correctness — Real Clean | 100% | 7 | 7 | REAL_WAZUH | YES — with caveat: all decisions are scripted 'approved' by IR_TEAM; rejected decisions in the data = 0 |
| Approval Correctness — Real Intervention | 100% | 9 | 9 | REAL_WAZUH | YES — with caveat: rejected decisions = 0 |

## 5. Real Wazuh Metrics

| Metric | Result | Numerator | Denominator | Mode | Paper Ready |
| ------ | -----: | -----: | -----: | ---- | ----------- |
| Detection-to-Response — MOCK | – | – | – | MOCK | NOT_AVAILABLE: alert timestamps are synthetic; not defined for mock |
| Detection-to-Response (from Wazuh alert timestamp) — Real Clean | mean 52.37 / median 42.47 / min 32.71 / max 110.16 s | – | n=7 | REAL_WAZUH | YES — with caveat: includes the harness' indexer polling/ingest delay (≈12 s) — not VIGIX latency |
| Detection-to-Response (from VIGIX ingest) — Real Clean | mean 40.39 / median 33.9 / min 22.41 / max 98.25 s | – | n=7 | REAL_WAZUH | YES — with caveat: closest to workflow latency (ingest → response start); includes LLM latency and a scripted SOC/IR step |
| Detection-to-Response (from Wazuh alert timestamp) — Real Intervention | mean 83.89 / median 60.16 / min 32.78 / max 275.96 s | – | n=9 | REAL_WAZUH | YES — with caveat |
| Detection-to-Response (from VIGIX ingest) — Real Intervention | mean 72.34 / median 46.57 / min 22.18 / max 265.52 s | – | n=9 | REAL_WAZUH | YES — with caveat |
| Verification/Re-hunt Time — Real Clean | mean 0.03 / median 0.03 / min 0.02 / max 0.04 s | – | n=5 verifications | REAL_WAZUH | YES — with caveat: REHUNT_STARTED → verification stored (indexer query + verification); the harness' 15 s indexer-refresh wait is outside it; single small index |
| Verification/Re-hunt Time — Real Intervention | mean 0.03 / median 0.03 / min 0.02 / max 0.04 s | – | n=7 verifications | REAL_WAZUH | YES — with caveat |
| Time to re-hunt ERROR (failed re-hunts) — Real Clean / Intervention | 0.01 s / 0 s | – | n=2 / 2 | REAL_WAZUH | NO: an error, not a verification |

Wazuh-query time vs verification-processing time cannot be separated: the audit trail stores one `REHUNT_STARTED` and one `VERIFICATION_COMPLETED`/`verified_at` timestamp, so only the total is reported. Manual test-setup time (lab preparation, the simulated attack itself, the harness' 3 s pause before response completion and 15 s indexer-refresh wait) is **not** included in any workflow latency above.

## 6. Per-case Audit

All values recomputed from PostgreSQL (`soar_eval`); *TTD* = Time-to-Decision (scripted), *D→R* = Detection-to-Response measured from VIGIX ingest, *Verif.* = verification time.

### 6.1 Real Clean Run v2

| TC | Attack | Wazuh rule / level / MITRE | Playbook (actual vs expected) | Actions → targets (step order) | Compliance | Inv. s | TTD s | D→R s (ingest) | Verif. s | Retries | Intervention | Verification | Final | Workflow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TC-01 | Brute Force | 5712 / L10 / T1110 | PB-SSH-BRUTEFORCE vs PB-SSH-BRUTEFORCE | BLOCK-SOURCE-IP→172.19.0.6 | COMPLIANT | 23.05 | 0.07 | 23.2 | 0.03 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-02 | Malware | 100301 / L12 / T1204.002 | PB-MALWARE vs PB-MALWARE | ISOLATE-ENDPOINT→attack-endpoint | COMPLIANT | 33.79 | 0.05 | 33.9 | – | 0 | none | ERROR INSUFFICIENT_CRITERIA | open | incomplete |
| TC-03 | Phishing | 100310 / L10 / T1566.002 | none vs PB-PHISHING | no valid recommendation | NOT_EVALUATED | – | – | – | – | 5 | none | not reached | open (no recommendation) | incomplete |
| TC-04 | Account Compromise | 40112 / L12 / T1078,T1110 | PB-ACCOUNT-COMPROMISE vs PB-ACCOUNT-COMPROMISE | DISABLE-ACCOUNT→victim<br>BLOCK-SOURCE-IP→172.19.0.6<br>RESET-CREDENTIAL→victim<br>REVOKE-SESSION→victim | COMPLIANT | 41.55 | 0.05 | 41.66 | 0.02 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-05 | PowerShell | – | – | – | ENVIRONMENT_UNAVAILABLE | – | – | – | – | – | – | – | – | not run |
| TC-06 | SQL Injection | 31103 / L7 / T1190 | PB-SQL-INJECTION vs PB-SQL-INJECTION | BLOCK-SOURCE-IP→172.19.0.6 | COMPLIANT | 22.32 | 0.04 | 22.41 | 0.03 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-07 | Command & Control | 100320 / L13 / T1071.001 | PB-C2 vs PB-C2 | BLOCK-DESTINATION-IP→172.19.0.5<br>BLOCK-DOMAIN→vigix-eval-c2.net<br>BLOCK-URL→http://vigix-eval-c2.net:8080/…<br>ISOLATE-ENDPOINT→attack-endpoint | COMPLIANT | 98.12 | 0.06 | 98.25 | 0.04 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-08 | Suspicious Process | 100330 / L10 / T1059.004 | none vs PB-SUSPICIOUS-PROCESS | no valid recommendation | NOT_EVALUATED | – | – | – | – | 5 | none | not reached | open (no recommendation) | incomplete |
| TC-09 | Data Exfiltration | 100340 / L13 / T1048 | PB-DATA-EXFIL vs PB-DATA-EXFIL | BLOCK-DESTINATION-IP→172.19.0.8<br>BLOCK-DOMAIN→vigix-eval-exfil.net<br>ISOLATE-ENDPOINT→attack-endpoint | COMPLIANT | 38.09 | 0.06 | 38.21 | 0.03 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-10 | Privilege Escalation | 100350 / L14 / T1098 | PB-ACCOUNT-COMPROMISE vs PB-ACCOUNT-COMPROMISE | DISABLE-ACCOUNT→evaluser<br>RESET-CREDENTIAL→evaluser | COMPLIANT | 24.97 | 0.06 | 25.08 | – | 0 | none | ERROR INSUFFICIENT_CRITERIA | open | incomplete |

### 6.2 Real Intervention Run v2

| TC | Attack | Wazuh rule / level / MITRE | Playbook (actual vs expected) | Actions → targets (step order) | Compliance | Inv. s | TTD s | D→R s (ingest) | Verif. s | Retries | Intervention | Verification | Final | Workflow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TC-01 | Brute Force | 5712 / L10 / T1110 | PB-SSH-BRUTEFORCE vs PB-SSH-BRUTEFORCE | BLOCK-SOURCE-IP→172.19.0.6 | COMPLIANT | 22.18 | 0.06 | 22.31 | 0.04 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-02 | Malware | 100301 / L12 / T1204.002 | PB-MALWARE vs PB-MALWARE | ISOLATE-ENDPOINT→attack-endpoint | COMPLIANT | 56.9 | 0.06 | 57.01 | – | 0 | none | ERROR INSUFFICIENT_CRITERIA | open | incomplete |
| TC-03 | Phishing | 100310 / L10 / T1566.002 | PB-PHISHING vs PB-PHISHING | QUARANTINE-EMAIL→it-support@vigix-eval-phish.net<br>BLOCK-URL→http://vigix-eval-phish.net/o3…<br>BLOCK-DOMAIN→vigix-eval-phish.net | COMPLIANT | 265.41 | 0.06 | 265.52 | 0.03 | 3 | ANALYST_IOC_CORRECTION | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-04 | Account Compromise | 40112 / L12 / T1078,T1110 | PB-ACCOUNT-COMPROMISE vs PB-ACCOUNT-COMPROMISE | DISABLE-ACCOUNT→victim<br>BLOCK-SOURCE-IP→172.19.0.6<br>RESET-CREDENTIAL→victim | COMPLIANT | 34.28 | 0.06 | 34.39 | 0.03 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-05 | PowerShell | – | – | – | ENVIRONMENT_UNAVAILABLE | – | – | – | – | – | – | – | – | not run |
| TC-06 | SQL Injection | 31103 / L7 / T1190 | PB-SQL-INJECTION vs PB-SQL-INJECTION | BLOCK-SOURCE-IP→172.19.0.6 | COMPLIANT | 22.07 | 0.05 | 22.18 | 0.02 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-07 | Command & Control | 100320 / L13 / T1071.001 | PB-C2 vs PB-C2 | BLOCK-DESTINATION-IP→172.19.0.5<br>BLOCK-DOMAIN→vigix-eval-c2.net<br>BLOCK-URL→http://vigix-eval-c2.net:8080/…<br>ISOLATE-ENDPOINT→attack-endpoint | COMPLIANT | 47.8 | 0.06 | 47.92 | 0.02 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-08 | Suspicious Process | 100330 / L10 / T1059.004 | PB-SUSPICIOUS-PROCESS vs PB-SUSPICIOUS-PROCESS | KILL-PROCESS→/tmp/.cache/kworkerd | COMPLIANT | 128.9 | 0.06 | 129.02 | 0.03 | 3 | ANALYST_IOC_CORRECTION | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-09 | Data Exfiltration | 100340 / L13 / T1048 | PB-DATA-EXFIL vs PB-DATA-EXFIL | BLOCK-DESTINATION-IP→172.19.0.5<br>BLOCK-DOMAIN→vigix-eval-exfil.net<br>BLOCK-URL→http://vigix-eval-exfil.net:80…<br>ISOLATE-ENDPOINT→attack-endpoint | COMPLIANT | 46.46 | 0.06 | 46.57 | 0.02 | 0 | none | RESOLVED (REAL_WAZUH) | resolved | complete |
| TC-10 | Privilege Escalation | 100350 / L14 / T1098 | PB-ACCOUNT-COMPROMISE vs PB-ACCOUNT-COMPROMISE | DISABLE-ACCOUNT→evaluser<br>RESET-CREDENTIAL→evaluser | COMPLIANT | 26.05 | 0.05 | 26.15 | – | 0 | none | ERROR INSUFFICIENT_CRITERIA | open | incomplete |

### 6.3 Recurrence control (TC-01 repeated after the response)

| TC | Attack | Wazuh rule / level / MITRE | Playbook (actual vs expected) | Actions → targets (step order) | Compliance | Inv. s | TTD s | D→R s (ingest) | Verif. s | Retries | Intervention | Verification | Final | Workflow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TC-01 | Brute Force | 5712 / L10 / T1110 | PB-SSH-BRUTEFORCE vs PB-SSH-BRUTEFORCE | BLOCK-SOURCE-IP→172.19.0.6 | COMPLIANT | 21.22 | 0.06 | 21.36 | 0.03 | 0 | none | NOT_RESOLVED (REAL_WAZUH) | investigating | complete |

The `Final` column is the incident status derived from verification (`RESOLVED` only via a stored verification; no AI action changes it). Column `Workflow` = all 11 workflow steps present in the database (§4).

## 7. Evidence Coverage

Deterministic only (no LLM): for each case the audit lists the incident's IOCs, whether every step target is an evidence-linked IOC, an analyst-added IOC or an affected host (the evaluator's rule, recomputed independently from the rows), and the validator's rejection codes for the failed generation calls. Category mapping: `INVENTED_TARGET` = target not evidence-linked / missing IOC; `TARGET_TYPE_MISMATCH` = unsupported target (wrong target type for the action); `INSUFFICIENT_EVIDENCE` = required evidence (e.g. COMMAND_LINE, FILE_HASH) not recorded.

### Clean Run v2

| TC | Expected IOCs found before any correction | IOC support of final step targets | Validator rejection codes (failed calls) | Coverage verdict |
| --- | --- | --- | --- | --- |
| TC-01 | 2/2 | BLOCK-SOURCE-IP: EVIDENCE_LINKED_IOC | – | covered |
| TC-02 | 0/2 — missing hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2…, file:/root/Downloads/Invoice_Q4_2026.xls.exe | ISOLATE-ENDPOINT: AFFECTED_HOST | – | covered (but 2 expected IOC(s) were absent from the incident before correction) |
| TC-03 | 4/4 | no recommendation | INVENTED_TARGET×6, TARGET_TYPE_MISMATCH×1 | NOT COVERED — no validator-passing recommendation (Missing IOC / Unsupported target / Insufficient evidence) |
| TC-04 | 2/2 | DISABLE-ACCOUNT: EVIDENCE_LINKED_IOC<br>BLOCK-SOURCE-IP: EVIDENCE_LINKED_IOC<br>RESET-CREDENTIAL: EVIDENCE_LINKED_IOC<br>REVOKE-SESSION: EVIDENCE_LINKED_IOC | – | covered |
| TC-06 | 1/1 | BLOCK-SOURCE-IP: EVIDENCE_LINKED_IOC | – | covered |
| TC-07 | 3/3 | BLOCK-DESTINATION-IP: EVIDENCE_LINKED_IOC<br>BLOCK-DOMAIN: EVIDENCE_LINKED_IOC<br>BLOCK-URL: EVIDENCE_LINKED_IOC<br>ISOLATE-ENDPOINT: AFFECTED_HOST | – | covered |
| TC-08 | 0/2 — missing process:/tmp/.cache/kworkerd, command:curl -s http://vigix-eval-c2.net:8080/x … | no recommendation | TARGET_TYPE_MISMATCH×10, INSUFFICIENT_EVIDENCE×10 | NOT COVERED — no validator-passing recommendation (Missing IOC / Unsupported target / Insufficient evidence) |
| TC-09 | 3/3 | BLOCK-DESTINATION-IP: EVIDENCE_LINKED_IOC<br>BLOCK-DOMAIN: EVIDENCE_LINKED_IOC<br>ISOLATE-ENDPOINT: AFFECTED_HOST | – | covered |
| TC-10 | 1/1 | DISABLE-ACCOUNT: EVIDENCE_LINKED_IOC<br>RESET-CREDENTIAL: EVIDENCE_LINKED_IOC | – | covered |

### Intervention Run v2

| TC | Expected IOCs found before any correction | IOC support of final step targets | Validator rejection codes (failed calls) | Coverage verdict |
| --- | --- | --- | --- | --- |
| TC-01 | 2/2 | BLOCK-SOURCE-IP: EVIDENCE_LINKED_IOC | – | covered |
| TC-02 | 0/2 — missing hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2…, file:/root/Downloads/Invoice_Q4_2026.xls.exe | ISOLATE-ENDPOINT: AFFECTED_HOST | – | covered (but 2 expected IOC(s) were absent from the incident before correction) |
| TC-03 | 4/4 | QUARANTINE-EMAIL: ANALYST_ADDED_IOC<br>BLOCK-URL: EVIDENCE_LINKED_IOC<br>BLOCK-DOMAIN: EVIDENCE_LINKED_IOC | TARGET_TYPE_MISMATCH×4, INVENTED_TARGET×2 | covered |
| TC-04 | 2/2 | DISABLE-ACCOUNT: EVIDENCE_LINKED_IOC<br>BLOCK-SOURCE-IP: EVIDENCE_LINKED_IOC<br>RESET-CREDENTIAL: EVIDENCE_LINKED_IOC | – | covered |
| TC-06 | 1/1 | BLOCK-SOURCE-IP: EVIDENCE_LINKED_IOC | – | covered |
| TC-07 | 3/3 | BLOCK-DESTINATION-IP: EVIDENCE_LINKED_IOC<br>BLOCK-DOMAIN: EVIDENCE_LINKED_IOC<br>BLOCK-URL: EVIDENCE_LINKED_IOC<br>ISOLATE-ENDPOINT: AFFECTED_HOST | – | covered |
| TC-08 | 0/2 — missing process:/tmp/.cache/kworkerd, command:curl -s http://vigix-eval-c2.net:8080/x … | KILL-PROCESS: ANALYST_ADDED_IOC | TARGET_TYPE_MISMATCH×5, INSUFFICIENT_EVIDENCE×5 | covered (but 2 expected IOC(s) were absent from the incident before correction) |
| TC-09 | 3/3 | BLOCK-DESTINATION-IP: EVIDENCE_LINKED_IOC<br>BLOCK-DOMAIN: EVIDENCE_LINKED_IOC<br>BLOCK-URL: EVIDENCE_LINKED_IOC<br>ISOLATE-ENDPOINT: AFFECTED_HOST | – | covered |
| TC-10 | 1/1 | DISABLE-ACCOUNT: EVIDENCE_LINKED_IOC<br>RESET-CREDENTIAL: EVIDENCE_LINKED_IOC | – | covered |

Failed-call violation totals — Clean: {"INVENTED_TARGET":6,"TARGET_TYPE_MISMATCH":11,"INSUFFICIENT_EVIDENCE":10}; Intervention: {"TARGET_TYPE_MISMATCH":9,"INVENTED_TARGET":2,"INSUFFICIENT_EVIDENCE":5} (one failed generation call can carry several violations; they are counts of violations, not of cases).

Caveats: (1) the membership test cannot tell a *wrong-role* IP from a right one — TC-07's step `ACT-BLOCK-DESTINATION-IP → 172.19.0.5` (the monitored endpoint's own address) is counted as covered; (2) the FIM hash/path (TC-02) and the auditd process/command (TC-08) are present in the alerts but are not extracted as IOCs, so 'expected IOCs found' for those cases measures the extractor, not the AI.

## 8. Verification Audit

| Run | TC | Mode | Index | Searched IOCs (type:value) | Matching events | IOC recurrence | Spread | Contained | Result | Verif. s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| real-clean | TC-01 | REAL_WAZUH | wazuh-alerts-4.x-* | IPV4:172.19.0.6 | 0 | false | false | true | RESOLVED | 0.03 |
| real-clean | TC-02 | REAL_WAZUH (not created) | – | none searchable | – | – | – | – | ERROR INSUFFICIENT_CRITERIA | 0.01 |
| real-clean | TC-04 | REAL_WAZUH | wazuh-alerts-4.x-* | IPV4:172.19.0.6 | 0 | false | false | true | RESOLVED | 0.02 |
| real-clean | TC-06 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:/app/search.php?id=1%20union%20select%…<br>IPV4:172.19.0.6 | 0 | false | false | true | RESOLVED | 0.03 |
| real-clean | TC-07 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:http://vigix-eval-c2.net:8080/gate.php<br>DOMAIN:vigix-eval-c2.net<br>IPV4:172.19.0.8 | 0 | false | false | true | RESOLVED | 0.04 |
| real-clean | TC-09 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:http://vigix-eval-exfil.net:8080/upload<br>DOMAIN:vigix-eval-exfil.net<br>IPV4:172.19.0.8 | 0 | false | false | true | RESOLVED | 0.03 |
| real-clean | TC-10 | REAL_WAZUH (not created) | – | none searchable | – | – | – | – | ERROR INSUFFICIENT_CRITERIA | 0 |
| real-intervention | TC-01 | REAL_WAZUH | wazuh-alerts-4.x-* | IPV4:172.19.0.6 | 0 | false | false | true | RESOLVED | 0.04 |
| real-intervention | TC-02 | REAL_WAZUH (not created) | – | none searchable | – | – | – | – | ERROR INSUFFICIENT_CRITERIA | 0 |
| real-intervention | TC-03 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:http://vigix-eval-phish.net/o365/verif…<br>DOMAIN:vigix-eval-phish.net<br>IPV4:203.0.113.45 | 0 | false | false | true | RESOLVED | 0.03 |
| real-intervention | TC-04 | REAL_WAZUH | wazuh-alerts-4.x-* | IPV4:172.19.0.6 | 0 | false | false | true | RESOLVED | 0.03 |
| real-intervention | TC-06 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:/app/search.php?id=1%20union%20select%…<br>IPV4:172.19.0.6 | 0 | false | false | true | RESOLVED | 0.02 |
| real-intervention | TC-07 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:http://vigix-eval-c2.net:8080/gate.php<br>DOMAIN:vigix-eval-c2.net<br>IPV4:172.19.0.8 | 0 | false | false | true | RESOLVED | 0.02 |
| real-intervention | TC-08 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:http://vigix-eval-c2.net:8080/x<br>DOMAIN:vigix-eval-c2.net | 0 | false | false | true | RESOLVED | 0.03 |
| real-intervention | TC-09 | REAL_WAZUH | wazuh-alerts-4.x-* | URL:http://vigix-eval-exfil.net:8080/upload<br>DOMAIN:vigix-eval-exfil.net<br>IPV4:172.19.0.8 | 0 | false | false | true | RESOLVED | 0.02 |
| real-intervention | TC-10 | REAL_WAZUH (not created) | – | none searchable | – | – | – | – | ERROR INSUFFICIENT_CRITERIA | 0 |
| real-recurrence-control | TC-01 | REAL_WAZUH | wazuh-alerts-4.x-* | IPV4:172.19.0.6 | 29 | true | false | false | NOT_RESOLVED | 0.03 |

Findings of the verification audit:

- **Mode:** every verification in `soar_eval` is `REAL_WAZUH` (`evidenceSource = WAZUH_INDEXER`, index pattern `wazuh-alerts-4.x-*`); none is MOCK or manual entry. The query window of each verification starts at the completion of the (simulated) manual response and the recorded time range is stored with the row.
- **`RESOLVED` evidence:** each RESOLVED row has `matchingEvents = 0`, `iocRecurrence = false`, `spreadDetected = false`, `threatContained = true` and the list of IOCs that were actually searched. The search space is only what VIGIX can query: IP / domain / URL / hash IOCs.
- **Weak verifications:** TC-08 (Intervention) searched only the C2 URL/domain taken from the command line — it does **not** test that the suspicious process stopped; TC-06 searched the request path typed as a URL plus the attacker IP. `RESOLVED` there means 'those indicators did not reappear', not 'the behaviour is gone'.
- **No verification possible:** TC-02 (no hash/file IOC extracted from `syscheck.*`) and TC-10 (username-only IOC) ended in `REHUNT_INSUFFICIENT_CRITERIA`, correctly leaving the incident open (a failed re-hunt proves nothing).
- **Sensitivity control (recurrence), confirmed from PostgreSQL:** matching events = **29**, `iocRecurrence = true`, result = **NOT_RESOLVED**, `threatContained = false`, `spreadDetected = false`; the incident stayed `investigating` and investigations are #1:COMPLETED / #2:ACTIVE; Investigation #2 was opened by Policy RULE-V01 + RULE-V03; no AI action resolved or executed anything.
- **What the control does and does not show:** the re-hunt is *able* to detect a recurring attacker IP (positive control, TC-01, n = 1). There is no negative control across other IOC types (domain/URL/hash), no test of spread detection, and every response was simulated.
- **Verification/Re-hunt time:** computable for all 13 verifications (0.02–0.04 s) from `REHUNT_STARTED` to `verified_at`; split into query vs processing time is **not** possible from stored timestamps.

## 9. Findings

**Audit findings (about the evaluation data and reports)**

- **A1 — MOCK baseline TC-01 is a hybrid.** Real alert + mock verification (older `run-evaluation.ts` picks the latest alert by rule id only). Not modified; flagged in `results/evaluation-summary.md`, `case-results.*` and here.
- **A2 — MOCK timing is not a latency.** The stepwise mock run mixes scripted steps (≈0.05 s) with manual gaps of hours; the only clean MOCK latency is the N=2 repeated single-pass file (verification not exercised there).
- **A3 — The MOCK evaluation scripts were not production-parity** (no `responseSetup`/`compliancePolicy`); Real runs use production-parity wiring, so MOCK and REAL numbers are not like-for-like even apart from mock vs real telemetry.
- **A4 — Retry counts are censored at the harness cap of 5 attempts** for the two Clean-Run cases that never produced a valid recommendation (true retry count ≥ 5).
- **A5 — Time-to-Decision is a scripted API latency** in every Real run; only its *definition* (T_decision − T_recommendation) is validated, not any human behaviour.
- **A6 — Detection-to-Response includes harness artefacts** when measured from the Wazuh alert timestamp (indexer polling before ingest); the ingest-based figure is the defensible one.
- **A7 — `Workflow Completion` does not require `RESOLVED`.** The control case counts as complete (all steps present) while its incident is `investigating`; completion means 'the pipeline ran to a verification', not 'the threat is resolved'.
- **A8 — Evidence Coverage per recommendation is tautological** (validator gate); the per-attempted-case figure is the meaningful one. Both are reported.
- **A9 — No calculation error was found in the existing report:** the audit recomputed every KPI from PostgreSQL and every value agreed with `run.json` (I8). Reported numbers in `results/evaluation-summary.md` are unchanged.

**System findings carried over from the evaluation (unchanged, re-confirmed against the data)**

- F-IOC-1 (TC-03): the sender e-mail is extracted but is not an actionable/evidence-linked IOC → `ACT-QUARANTINE-EMAIL` rejected (`INVENTED_TARGET`/`TARGET_TYPE_MISMATCH`); Clean Run: 5 failed generations, no valid recommendation; needs an analyst IOC confirmation.
- F-IOC-2 (TC-08, TC-02): the IOC extractor does not read `data.audit.*` or `syscheck.*`; `ACT-KILL-PROCESS` (needs COMMAND_LINE) is blocked as designed; TC-02 has no hash IOC → no re-hunt.
- F-VER-1 (TC-02, TC-10): identity/host-only incidents cannot be verified by an IOC re-hunt (`REHUNT_INSUFFICIENT_CRITERIA`).
- F-EVAL-1 (TC-07/TC-09): a step may target the monitored endpoint's own IP and still pass `evidenceSupport`; reported as `SELF_TARGETING_STEP` outside the six criteria.
- F-KB (fixed before the reported run): `PlaybookSelector` tie-break let an AI-inferred technique flip TC-09's playbook; SIEM-asserted techniques now win an equal-count tie (4 unit tests). The Real playbook-alignment figure is post-fix.
- Findings that were **not** reproduced: the MOCK-era KB gaps (PB-C2 / T1071.001, PB-DATA-EXFIL / T1048) did not occur — the Knowledge Base was complete beforehand — and TC-10's T1098 → PB-ACCOUNT-COMPROMISE mapping was documented, not changed, and matched the ground truth.

## 10. Limitations

- **Sample:** 10 predefined test cases (9 attempted; TC-05 needs a Windows endpoint that does not exist) — "Evaluation was conducted on 10 predefined test cases." It is not a sample of SOC situations and supports no statistical inference; there are no confidence intervals and one run per condition.
- **Mock vs Real:** kept separate everywhere; not comparable one-to-one (different alerts, ground truth keyed to different rules, mock TC-01 hybrid, different wiring).
- **Simulated response:** no containment was executed; a Real `RESOLVED` therefore means no recurrence in a short window after a simulated response. Attacks ran once.
- **Scripted humans:** SOC triage, SOC→IR hand-off and IR approval are API calls; the analyst correction is a fixed script; no rejection or manual-decision path was exercised.
- **Environment:** private Docker addresses; TC-03/07/08/09 use harness-generated telemetry; TC-02/07/09/10 detections exist only through custom rules written for the evaluation (stock Wazuh covers TC-01, TC-04, TC-06).
- **LLM:** one model (`google/gemma-4-26b-a4b-it` via OpenRouter; the active provider is inferred from a doubly-defined `LLM_PROVIDER`), one run per condition; repeated-run reliability not tested; Investigation Time includes third-party API latency.
- **ML risk score:** the `risk_scores` table is empty — no ML output exists to evaluate.
- **Production parity:** analysis ran synchronously instead of through the worker queue; `CreateVerification` had no `sendRecommendationToIr` (only relevant to the NOT_RESOLVED round exercised once); the webhook hop was bypassed.

## 11. Paper-ready Metrics

Numbers that can be cited **as they are**, each with its condition. Everything is Real Wazuh, Clean Run v2 unless stated.

| Metric | Value to cite | Condition to state alongside | Status |
| --- | --- | --- | --- |
| Recommendation Compliance | 100% (7/7 evaluated); 77.78% (7/9) of attempted | deterministic six-criterion scorer, no LLM judge; 2 attempted cases produced no valid recommendation; Intervention Run (analyst-assisted): 9/9 | READY_FOR_PAPER |
| Playbook Alignment | 100% (7/7) | measured after the PlaybookSelector tie-break fix; first real run had 1 mismatch (TC-09) | READY_FOR_PAPER |
| Policy Compliance | 100% (7/7) | current Policy implementation as source of truth; no negative test | READY_FOR_PAPER |
| Workflow Completion | 55.56% (5/9 attempted; 50% of 10) Clean; 77.78% (7/9) Intervention | completion = all 11 steps in the DB through a stored verification; does not mean RESOLVED; incomplete = 2 blocked recommendations + 2 un-verifiable re-hunts (Clean) | READY_FOR_PAPER |
| Investigation Time | mean 40.27 s, median 33.79 s, min 22.32 s, max 98.12 s (n=7) | T_recommendation − T_investigation_start; uninterrupted run; includes third-party LLM latency; cases without a recommendation excluded | READY_FOR_PAPER (with caveats) |
| Intervention Rate / Retry Rate | Clean: 0% / 22.22% (retry cases 2/9; total retries 10); Intervention: 22.22% (2/9) / 22.22% (total 6) | retry total is a count; Clean retries are censored at 5; the analyst is scripted | READY_FOR_PAPER (descriptive) |
| Evidence Coverage | 77.78% (7/9 attempted cases) Clean; 100% Intervention | membership definition; blocked cases count as not covered; not semantic | READY_FOR_PAPER (with caveats) |
| Approval Correctness | 100% (7/7) | approve path only; rejection/manual-decision not exercised | NEEDS_MORE_DATA (partial) |
| Verification outcome distribution | Clean: {"RESOLVED":5,"ERROR":2}; Intervention: {"RESOLVED":7,"ERROR":2}; control: NOT_RESOLVED with 29 matching events | report as outcomes of a simulated-response pipeline, never as containment effectiveness | NEEDS_MORE_DATA |
| Verification/Re-hunt Time | mean 0.03 / median 0.03 / min 0.02 / max 0.04 s (n=5) | total time only; tiny index; excludes harness waits | READY_FOR_PAPER (with caveats) |
| Detection-to-Response | mean 40.39 / median 33.9 / min 22.41 / max 98.25 s from VIGIX ingest (n=7) | includes LLM latency and a scripted SOC/IR step; webhook latency not measured | NEEDS_MORE_DATA |

MOCK baseline (cite only as MOCK, with its conditions): compliance 10/10, workflow 10/10, verification 10/10 *completed* (MOCK — NO_MATCH simulated), intervention 4/10, retry cases 4/10 with a total retry count of 43; do not cite its timing (manual gaps) — use the N=2 single-pass figures (mean investigation 53.09 s ± 29.05) if a MOCK latency is needed.

## 12. Metrics Not Available

- **Time-to-Decision as human decision time** — NOT_AVAILABLE: every decision is scripted; no human-in-the-loop timing exists in the data.
- **Verification Effectiveness as a containment claim** — NOT_AVAILABLE: no response was actually executed; a single positive control (n = 1); no negative/other-IOC-type control; no spread-detection test.
- **Approval Correctness for rejected recommendations / manual decision after reject** — NOT_AVAILABLE: 0 rejected decisions in `soar_eval`.
- **Windows / PowerShell (TC-05) on Real Wazuh** — NOT_AVAILABLE: `ENVIRONMENT_UNAVAILABLE`.
- **ML risk score** — NOT_AVAILABLE: `risk_scores` is empty.
- **Repeated-run reliability of the LLM on the Real pipeline** — NOT_AVAILABLE: one run per condition (only the MOCK pipeline has N = 2).
- **Split of Verification Time into Wazuh-query vs processing time** — NOT_AVAILABLE: not stored.
- **VIGIX webhook (`custom-vigix` → backend) latency** — NOT_AVAILABLE: the evaluation ingested through the same use cases but bypassed the HTTP hop.
- **Detection-to-Response and Verification/Re-hunt Time for MOCK** — NOT_APPLICABLE by definition (synthetic alerts, simulated re-hunt).
- **Real-Wazuh results for TC-02 and TC-10 verification** — NOT_AVAILABLE: no searchable IOC; only the recommendation side is measured.

---

### Final classification

- **READY_FOR_PAPER (with the stated caveats):** Recommendation Compliance, Playbook Alignment, Policy Compliance, Workflow Completion, Investigation Time, Verification/Re-hunt Time, Intervention and Retry descriptions, Evidence Coverage (per attempted case).
- **NEEDS_MORE_DATA:** Verification Effectiveness (as anything beyond an outcome distribution), Approval Correctness (reject path), Detection-to-Response, repeated-run reliability.
- **NOT_AVAILABLE:** human Time-to-Decision, ML risk score, TC-05 on Real Wazuh, Verification Time split, webhook latency.

Reproduce: `cd apps/backend && . scripts/eval/eval-env.sh && npx ts-node --transpile-only scripts/eval/audit-evaluation.ts && npx ts-node --transpile-only scripts/eval/build-audit-report.ts` (read-only; needs the Wazuh stack, PostgreSQL and `soar_eval` to be up).