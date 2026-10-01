# VIGIX — Final Evaluation Report (thesis-final)

Generated 2026-10-01 from `soar_final_eval` (PostgreSQL). Every number below is read from the database through
`apps/backend/scripts/eval/final/final-metrics.ts` and independently recomputed in plain SQL
(`final-db-metrics.sql`, output in `final-db-metrics-output.txt`); the two agree (no cross-diffs).
Nothing in this report was estimated or interpolated. Where a value cannot be computed it says `NOT CALCULABLE — <reason>`.

> **Reading rules.** *Measured result* = a value read from the database. *Observation* = something seen in the data that is not itself a KPI.
> *Failure* = a recorded failure. *Limitation* = something this evaluation cannot show. *Infrastructure issue* = failure of a dependency, classified
> separately from model behaviour. The word "accuracy" is not used; the deterministic term is **Recommendation Compliance**.

---

## 1. Environment and integrity

| Item | Value |
|---|---|
| Git | branch `feature/report-period-windows`, commit `cdfcaf7a5e90`; **working tree dirty** (uncommitted code under test; SHA-256 of each file in `pre-run-integrity.json` / `post-run-integrity.json`) |
| Backend / AI orchestrator / frontend | one monorepo (single commit); AI service last commit `ac0a6119b5b1`, frontend last commit `dd03028bc705` |
| Evaluation DB | `soar_final_eval`, cloned from the frozen `soar_eval` dump, row counts equal the frozen manifest, then run-data reset; Knowledge Base (14 actions, 11 playbooks, 36 playbook steps, 29 policies/rules, 17 runbooks, 26 MITRE techniques) checksum-identical to the frozen DB |
| Frozen DB `soar_eval`, development DB `soar_platform` | unchanged (post-run: 31 frozen files unchanged; `soar_platform` 260 alerts / 39 incidents) |
| LLM | `vllm-spark-01/gemma4-26b-uncensored` on a self-hosted OpenAI-compatible vLLM endpoint (the host name is recorded in `pre-run-integrity.json`; remove it before publishing). The endpoint exposes no `/version`. OpenRouter is **not** on this path (see `results/additional-evaluation/CORRECTIONS.md`). |
| Wazuh | manager and agent 4.9.2 (rev 40921); agent `attack-endpoint` (ID 009) active; custom rules 100301/100310/100320/100330/100340/100350 on the manager equal the repo copies |
| Qdrant | 1.19.1, **no collections** → RAG returns no result (`search_failed`/`not_found`). Same as the frozen run, by the owner's decision. |
| MISP (CTI) | container "unhealthy" at run time; CTI provider status `FAILED` where recorded |
| Run | `final-main-real-wazuh-20261001` (2026-10-01 01:36–02:01 UTC), `final-ir-reject-real-wazuh-20261001` (02:01–02:03 UTC), consistency 5×6 (02:03–02:20 UTC). Mode: reactive-analyst intervention run (system gets two attempts, then analyst evidence confirmation). |
| Ground Truth | `groundTruthReal.ts`, file SHA-256 `8f97fa8f…` identical before and after; object hash `ddb18d5d…` identical to the frozen runs and recomputed by the runner |
| DB backup | `backups/db/soar_final_eval-after-final-run-20261001.sql` (SHA-256 `980a1eca…`, git-ignored) |
| Post-run integrity | all checks pass (`post-run-integrity.json`) |

Code-under-test hash differences between the pre-run snapshot (08:33) and the post-run snapshot are limited to `run-real-evaluation.ts`, `additional/common.ts`,
`additional/consistency.ts` (infrastructure-aware retry/classification, edited 08:35–08:36, **before** any run) and the two metric calculators added/edited afterwards
(stage-4 definition, labels). Ground Truth, evaluator, Policy, Playbook, Action, Rule data were not changed.

---

## 2. Final KPI table

| Metric | Result | Unit | N | Source | Notes |
|---|---|---|---|---|---|
| Recommendation Compliance | **100** | % | 9/9 evaluated (9/9 of attempted) | DB | deterministic six-criterion evaluator against the frozen Ground Truth; no LLM judge |
| Investigation Time | **126.106** | s (mean) | 9 | DB | median 84.674, SD 108.013, min 47.002, max 390.723 |
| Time-to-Decision | **0.053** | s (mean) | 9 | DB | median 0.054, SD 0.008, min 0.040, max 0.065. **Scripted IR API call, not human deliberation** |
| Workflow Completion | **77.78** | % | 7/9 | DB | 12 stages + supported final state; TC-02, TC-10 stop at stage 11 (re-hunt) |
| Intervention Rate | **22.22** | % | 2/9 | DB | TC-03 (e-mail/URL/domain/IP IOC confirmation), TC-08 (process + command-line IOC) |
| Recommendation Retry Rate | **22.22** | % | 2/9 | DB | total retry **count** 5 (TC-03: 3, TC-08: 2), all `INVALID_AI_OUTPUT`; infrastructure failures excluded = 0 |
| Mock Verification | 100 | % | 10/10 | archived frozen MOCK run (not re-run) | completion of a **simulated** re-hunt; not evidence of threat removal; never mixed with Real Wazuh |
| Real Wazuh Verification | **77.78** | % | 7/9 | DB | 7 `RESOLVED`, 2 `ERROR` (`REHUNT_INSUFFICIENT_CRITERIA`: TC-02, TC-10) |
| Recommendation Consistency | **96.67** | % | 29/30 | DB evidence snapshots + live LLM (`data/consistency.json`) | 6 cases × 5 repetitions on an identical evidence snapshot; per-case mean 96.67, SD 8.16 |
| Step-set Consistency | **93.33** | % | 28/30 | `data/consistency.json` | the complete validated step set identical (TC-04: 3/5) |
| Negative Validation | **100** | % | 10/10 | controlled validator scenarios (`data/negative.json`) | each scenario has an accepted positive control; **NEG-02 is rejected by the Action-Knowledge/validator layer, not by Policy** |
| Human/Policy Validation | **100** | % | 29/29 | DB governance gates G0–G16 + IR-reject run IRR-01..IRR-12 | no failures recorded |

Prior-run numbers (29/30, 10/10, 17/17, baseline 9/9, 2.78 actions, 0.013 s) were used **only** as a plausibility check. Today's values were computed independently;
several differ (baseline mean 0.018 s vs 0.013 s; Investigation Time mean 126 s, driven by LLM latency) and none was forced to match.

Figures: `figures/figure1_final_kpi_summary`, `figure2_investigation_time`, `figure3_time_to_decision`, `figure4_recommendation_compliance`,
`figure5_recommendation_consistency`, `figure6_workflow_and_verification` (each `.png` and `.pdf`).

---

## 3. Per-test-case table

Final Result vocabulary: PASS / FAIL / ENVIRONMENT_UNAVAILABLE / INCOMPLETE.

| TC | Attack | Alert | Investigation | Recommendation | IR Decision | Response | Verification | Intervention | Retry | Final Result |
|---|---|---|---|---|---|---|---|---|---|---|
| TC-01 | Brute Force | Wazuh 5712 L10 (medium) T1110 | 84.674 s | PB-SSH-BRUTEFORCE: BLOCK-SOURCE-IP, DISABLE-ACCOUNT (COMPLIANT) | approved IR_TEAM (0.065 s) | COMPLETED | RESOLVED (REAL_WAZUH) | none | 0 | PASS |
| TC-02 | Malware | Wazuh 100301 L12 (high) T1204.002 | 73.892 s | PB-MALWARE: ISOLATE-ENDPOINT (COMPLIANT) | approved IR_TEAM (0.061 s) | COMPLETED | ERROR — INSUFFICIENT_CRITERIA | none | 0 | **INCOMPLETE** |
| TC-03 | Phishing | Wazuh 100310 L10 (medium) T1566.002 | 390.723 s | PB-PHISHING: QUARANTINE-EMAIL, BLOCK-URL, BLOCK-DOMAIN (COMPLIANT) | approved IR_TEAM (0.053 s) | COMPLETED | RESOLVED (REAL_WAZUH) | e-mail/URL/domain/IP IOC confirmed by analyst | 3 | PASS |
| TC-04 | Account Compromise | Wazuh 40112 L12 (high) T1078,T1110 | 76.647 s | PB-ACCOUNT-COMPROMISE: DISABLE-ACCOUNT, BLOCK-SOURCE-IP (COMPLIANT) | approved IR_TEAM (0.055 s) | COMPLETED | RESOLVED (REAL_WAZUH) | none | 0 | PASS |
| TC-05 | PowerShell | — | not attempted | not attempted | none | none | not reached | none | 0 | **ENVIRONMENT_UNAVAILABLE** |
| TC-06 | SQL Injection | Wazuh 31103 L7 (medium) T1190 | 47.002 s | PB-SQL-INJECTION: BLOCK-SOURCE-IP (COMPLIANT) | approved IR_TEAM (0.054 s) | COMPLETED | RESOLVED (REAL_WAZUH) | none | 0 | PASS |
| TC-07 | Command & Control | Wazuh 100320 L13 (high) T1071.001 | 93.171 s | PB-C2: BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, ISOLATE-ENDPOINT (COMPLIANT) | approved IR_TEAM (0.056 s) | COMPLETED | RESOLVED (REAL_WAZUH) | none | 0 | PASS |
| TC-08 | Suspicious Process | Wazuh 100330 L10 (medium) T1059.004 | 199.013 s | PB-SUSPICIOUS-PROCESS: KILL-PROCESS (COMPLIANT) | approved IR_TEAM (0.040 s) | COMPLETED | RESOLVED (REAL_WAZUH) | process + command-line IOCs added from alert evidence | 2 | PASS |
| TC-09 | Data Exfiltration | Wazuh 100340 L13 (high) T1048 | 98.565 s | PB-DATA-EXFIL: BLOCK-DESTINATION-IP, BLOCK-DOMAIN, BLOCK-URL, ISOLATE-ENDPOINT (COMPLIANT) | approved IR_TEAM (0.040 s) | COMPLETED | RESOLVED (REAL_WAZUH) | none | 0 | PASS |
| TC-10 | Privilege Escalation | Wazuh 100350 L14 (critical) T1098 | 71.269 s | PB-ACCOUNT-COMPROMISE: DISABLE-ACCOUNT, RESET-CREDENTIAL (COMPLIANT) | approved IR_TEAM (0.051 s) | COMPLETED | ERROR — INSUFFICIENT_CRITERIA | none | 0 | **INCOMPLETE** |

Totals: 10 cases defined, 9 attempted, 9 completed through recommendation, **7 PASS, 0 FAIL, 2 INCOMPLETE, 1 ENVIRONMENT_UNAVAILABLE**. 0 infrastructure failures in the main run.
No case reached 3 re-hunt rounds, so no `ESCALATED` outcome exists (none was induced).

---

## 4. Metric → table → field → calculation

| Metric | Tables / fields | Calculation |
|---|---|---|
| Recommendation Compliance | `recommendations` (latest per incident: playbook_id, steps, status), `actions`, `playbooks`, `playbook_steps`, `policies`, `policy_rules`, `approvals`, `alerts`, frozen Ground Truth | per case six criteria (attack alignment, evidence support, knowledge validity, policy compliance, playbook alignment, approval correctness) all true → COMPLIANT; compliant / evaluated recommendations × 100; recomputed in SQL |
| Investigation Time | `investigations.started_at` (investigation #1), `recommendations.created_at` (recommendation #1) | seconds(T_recommendation − T_investigation_start); N, mean, median, SD, min, max |
| Time-to-Decision | `approvals.created_at`/`decided_at`, `approval_role` | seconds from approval request to the first IR_TEAM decision |
| Workflow Completion | `alerts`, `incidents`, `investigations`, `agent_executions`, `recommendations`, `response_plans`, `approvals`, `verifications`, `audit_logs` | 12 stages true and a supported final state → complete; complete / attempted × 100 |
| Intervention Rate | `threat_intel_iocs` (analyst-added / non-system), `audit_logs` | cases with ≥1 analyst-added or analyst-confirmed IOC / attempted × 100 |
| Retry Rate | `audit_logs` `RECOMMENDATION_GENERATION_FAILED` reasons | cases with ≥1 model/evidence retry / attempted; total retry count reported separately; `AI_UNAVAILABLE` excluded as infrastructure |
| Real Wazuh Verification | `verifications` (mode, result, `matching_events`, `ioc_recurrence`, `spread_detected`, `threat_contained`), `audit_logs` (rehunt errors) | cases with a RESOLVED/… verification result / executed responses; outcome distribution kept; MOCK never mixed |
| Mock Verification | archived frozen MOCK run (`soar_eval`) | completed simulated re-hunts / cases; not re-run |
| Consistency / Step-set | in-memory repetition of `GenerateRecommendationUseCase` on the DB evidence snapshot (hash identical per repetition) | modal validated primary (playbook + action + target type + target) / runs; step-set = complete validated set identical |
| Negative Validation | 10 controlled invalid candidates through `RecommendationValidator`/Policy, each with an accepted positive control | rejected / tested × 100; layer taken from the recorded violation |
| Human/Policy Validation | `approvals`, `response_plans`, `audit_logs`, `step_executions` after gates G0–G16 and IRR-01..IRR-12 | passed checks / total checks |

---

## 5. Re-check of findings from earlier audits

| Earlier finding | Final result |
|---|---|
| TC-03 target for QUARANTINE-EMAIL not evidence-linked | **Persists.** 3 validator-rejected generations (target-type mismatch, two invented/typo'd targets). The IOCs were then confirmed by the analyst (intervention) and the 4th call was validated. Recorded as intervention + retry, not silently corrected. |
| TC-07 isolate vs block variation | **Persists in consistency**: 4/5 identical main action (one run led with ISOLATE-ENDPOINT); the complete step set was identical 5/5 (order differs). Main run: BLOCK-DESTINATION-IP first. |
| TC-08 command line not extracted | **Persists.** 2 rejected generations (host target for KILL-PROCESS, missing COMMAND_LINE / FILE_HASH); resolved by analyst-added PROCESS_NAME + COMMAND_LINE from the alert. |
| TC-09 LLM outage in consistency | **Did not recur**: 0 infrastructure failures in main, reject and consistency runs; TC-09 5/5 consistent. (The earlier outage remains documented as infrastructure.) |
| TC-10 cannot be verified | **Persists.** No searchable IOC (IP/domain/URL/hash only) → `REHUNT_INSUFFICIENT_CRITERIA`; workflow INCOMPLETE. Same for TC-02. |
| TC-04 | New observation: main action 5/5 but step set 3/5 (optional RESET-CREDENTIAL / REVOKE-SESSION added in 2 repetitions). |

---

## 6. Baseline comparison (procedural reference only)

A deterministic playbook-based procedure (no AI, no human decision, no approval) was run on the same 9 evaluable cases: plan created 9/9, four baseline criteria 9/9,
preferred action hit 7/9, 25 plan steps (mean 2.78 per case), procedure time mean 0.018 s (n=9). VIGIX on the same cases: 9/9 compliant, mean 2.22 actions per plan,
mean Investigation Time 126.11 s. **The baseline has no human decision stage and is not an equivalent, faster or better SOC workflow**; it only shows what a fixed
playbook lookup produces for these cases. No human study was run and the MOCK run was not used as a baseline.

---

## 7. IR reject / manual response (supplementary run, TC-06)

12/12 checks passed: SOC, AI_AGENT and admin approval attempts denied; IR_TEAM reject → `PENDING_MANUAL_DECISION`; start blocked; 0 step executions after reject;
incident status unchanged by the reject; no automatic regeneration audit record; re-hunt before completion blocked; manual decision without role/note denied;
IR manual decision → `READY_FOR_EXECUTION`; response then started and completed by the harness, re-hunt on the real indexer = `RESOLVED`. The recorded approvals are
`rejected` then `approved` by `eval-ir` (IR_TEAM). These are scripted API calls.

---

## 8. Principle checks stored in the database (all pass)

Severity equals the Wazuh-rule-level mapping in 9/9 incidents and no severity-change audit exists; no response executed without an approved IR_TEAM decision; no step execution on a
non-approved ticket; no incident marked resolved without a RESOLVED verification and no AI actor closed an incident; every decided approval has role IR_TEAM; timestamps monotonic.

---

## 9. Limitations (what this evaluation cannot show)

1. **Uncommitted code under test** (dirty tree). Commit before making reproducibility claims; hashes are recorded.
2. **RAG not evaluated** — Qdrant has no collection; retrieval returned nothing in every case. CTI (MISP) failed or was unavailable; threat-intel enrichment is not part of the result.
3. **IR/SOC decisions are scripted API calls.** Time-to-Decision (≈0.05 s) measures API latency, not human decision time; it must not be read as SOC speed.
4. **Intervention mode is a reactive analyst simulation** (two system attempts, then evidence-based IOC confirmation); it is not a human study.
5. **TC-05 (PowerShell)** is ENVIRONMENT_UNAVAILABLE (needs a Windows endpoint); nothing was fabricated; it is excluded from all denominators and reported as such.
6. **TC-02 and TC-10 cannot be verified** with the current re-hunt (no searchable IOC) → INCOMPLETE; this is a verification-capability gap, not a model result.
7. **ESCALATED (3 re-hunt rounds) was not exercised**; Real Wazuh verification covers RESOLVED only.
8. **Controlled telemetry**: rules 5712 (TC-01), 40112 (TC-04), 31103 (TC-06) are stock Wazuh; TC-02, 03, 07, 08, 09, 10 use custom rules and simulated activity in an isolated Docker endpoint. RESOLVED means "no IOC recurrence in the re-hunt window", not proof of eradication.
9. **Consistency covers 6 of 9 cases** (TC-03, TC-08, TC-10 excluded by design: they need analyst intervention) and 5 repetitions each; recommendations were not persisted.
10. **Mock verification (10/10)** comes from the archived frozen MOCK run and includes a simulated no-match; it is not detection evidence.
11. Sample size is small (9 cases, one run); no confidence intervals are claimed. A single LLM and single endpoint were used. Investigation Time depends on endpoint latency.
12. The vLLM endpoint host name is stored in `pre-run-integrity.json`.
13. Known unrelated failing test at HEAD: `test/PolicyApprovalWorkflow.test.ts` ("high-impact action on a non-critical asset at MEDIUM"); not touched.

---

## 10. Final Audit Checklist

| # | Check | Status |
|---|---|---|
| 1 | Evaluation DB is `soar_final_eval`; dev DB `soar_platform` untouched (260/39) | PASS |
| 2 | Frozen DB and 31 frozen result files unchanged (post-run integrity) | PASS |
| 3 | Pre-run DB backup restored and verified; post-run backup written | PASS |
| 4 | Git commit/branch, dirty state and code hashes recorded | PASS (dirty — disclosed) |
| 5 | Model, endpoint reachability, Qdrant, Wazuh, MISP versions/states recorded | PASS |
| 6 | Ground Truth hash unchanged and defined before AI output | PASS |
| 7 | Policy / Playbook / Action / Rule / MITRE knowledge identical to the frozen DB | PASS |
| 8 | Database is the Source of Truth; JSON = SQL recomputation (no cross-diffs) | PASS |
| 9 | Compliance computed by the deterministic evaluator, no LLM judge | PASS |
| 10 | Severity comes from Wazuh, never from AI | PASS |
| 11 | AI did not approve, execute a response or close an incident | PASS |
| 12 | IR_TEAM was the only decision authority in all approvals | PASS |
| 13 | IR reject → not executed, not auto-closed, no regeneration, PENDING_MANUAL_DECISION, manual path works | PASS (12/12) |
| 14 | MOCK and REAL_WAZUH verification reported separately | PASS |
| 15 | TC-05 reported ENVIRONMENT_UNAVAILABLE, not fabricated | PASS |
| 16 | Failures recorded as failures (retries, INCOMPLETE, re-hunt ERROR) | PASS |
| 17 | Infrastructure failures separated from model inconsistency (0 occurred; mechanism in place) | PASS |
| 18 | No AI recommendation silently corrected or regenerated to look correct | PASS |
| 19 | Continuous metrics report N, mean, median, SD, min, max; binary report n/N/% | PASS |
| 20 | Baseline not claimed equivalent/faster/better | PASS |
| 21 | NEG-02 not described as a Policy rejection | PASS |
| 22 | Prior numbers used only as comparison, not forced | PASS |
| 23 | No claim of "highly accurate", "better", "faster", "eliminates analysts" or "guarantees security" | PASS |
| 24 | Figures (PNG + PDF), all `final-*.json`, SQL, README produced | PASS |

---

## 11. ผลการทดลองสำหรับวิทยานิพนธ์ (ร่างบทที่ 4)

> ป้ายกำกับ: **[ผลวัด]** ค่าที่อ่านจากฐานข้อมูล · **[ข้อสังเกต]** · **[ความล้มเหลว]** · **[ข้อจำกัด]** · **[ปัญหาโครงสร้างพื้นฐาน]**

### 4.x.1 สภาพแวดล้อมการทดลอง
การทดลองรันบนฐานข้อมูลแยก `soar_final_eval` ซึ่งโคลนจากฐานข้อมูลที่ freeze ไว้ และตรวจสอบแล้วว่าฐานความรู้ (14 Action, 11 Playbook, 29 Policy, 26 MITRE technique) เหมือนเดิมทุกค่า checksum
ระบบใช้ Wazuh 4.9.2 พร้อม agent บน Docker endpoint ที่แยกจากระบบจริง, LLM คือ `vllm-spark-01/gemma4-26b-uncensored` บน vLLM ที่โฮสต์เอง
**[ข้อจำกัด]** โค้ดที่ทดสอบยังไม่ถูก commit (working tree เปลี่ยนแปลง) ฐานข้อมูลเวกเตอร์ Qdrant ไม่มี collection จึงไม่ได้ประเมินขั้น RAG และบริการ MISP ไม่พร้อมใช้งาน

### 4.x.2 ผลการทดสอบทั้ง 10 กรณี
**[ผลวัด]** พยายามทดสอบ 9 กรณี ผ่านครบ 7 กรณี (TC-01, 03, 04, 06, 07, 08, 09) ไม่สมบูรณ์ 2 กรณี (TC-02, TC-10) และไม่มีกรณีที่ล้มเหลว
**[ข้อจำกัด]** TC-05 (PowerShell) ต้องใช้ Windows endpoint จึงรายงานเป็น `ENVIRONMENT_UNAVAILABLE` และไม่ถูกนับในตัวหาร

### 4.x.3 Recommendation Compliance
**[ผลวัด]** 9/9 (100%) ผ่านเกณฑ์ทั้งหกข้อของตัวประเมินแบบกำหนดแน่นอน (ไม่ใช้ LLM เป็นผู้ประเมิน) เทียบกับ Ground Truth ที่กำหนดไว้ก่อนผลลัพธ์ของ AI
**[ข้อสังเกต]** ค่านี้วัดความสอดคล้องกับ Ground Truth ของ 9 กรณีที่ควบคุมไว้เท่านั้น ไม่ใช่ความแม่นยำโดยทั่วไป

### 4.x.4 Investigation Time
**[ผลวัด]** N = 9, ค่าเฉลี่ย 126.11 วินาที, มัธยฐาน 84.67, SD 108.01, ต่ำสุด 47.00 (TC-06), สูงสุด 390.72 (TC-03)
**[ข้อสังเกต]** ค่าสูงสุดเกิดในกรณีที่มีการสร้างคำแนะนำซ้ำและมีการยืนยัน IOC โดยนักวิเคราะห์ เวลาขึ้นกับความหน่วงของ LLM endpoint

### 4.x.5 Time-to-Decision
**[ผลวัด]** N = 9, ค่าเฉลี่ย 0.053 วินาที (มัธยฐาน 0.054, SD 0.008, 0.040–0.065)
**[ข้อจำกัด]** การตัดสินใจของ IR_TEAM เป็นการเรียก API ตามสคริปต์ จึงสะท้อนเวลาของระบบ ไม่ใช่เวลาที่มนุษย์ใช้พิจารณา และห้ามตีความเป็นความเร็วของ SOC

### 4.x.6 Workflow Completion
**[ผลวัด]** 7/9 (77.78%) ครบทั้ง 12 ขั้น
**[ความล้มเหลว]** TC-02 และ TC-10 หยุดที่ขั้น Verification/Re-hunt เพราะไม่มี IOC ประเภท IP/โดเมน/URL/แฮช ที่ค้นซ้ำได้ (`REHUNT_INSUFFICIENT_CRITERIA`) เป็นช่องว่างด้านความสามารถของการตรวจสอบ ไม่ใช่ความผิดพลาดของโมเดล

### 4.x.7 Intervention Rate
**[ผลวัด]** 2/9 (22.22%): TC-03 (ยืนยัน IOC อีเมล/URL/โดเมน/IP) และ TC-08 (เพิ่ม process และ command line จากหลักฐานในการแจ้งเตือน)
**[ข้อสังเกต]** การแทรกแซงจำลองเป็นนักวิเคราะห์แบบตอบสนอง (ระบบพยายาม 2 ครั้งก่อน) ไม่ใช่การศึกษากับมนุษย์

### 4.x.8 Recommendation Retry Rate
**[ผลวัด]** 2/9 (22.22%) จำนวนการลองซ้ำทั้งหมด 5 ครั้ง (TC-03: 3, TC-08: 2) ทั้งหมดเป็นผลลัพธ์ของโมเดลที่ validator ปฏิเสธ (`INVALID_AI_OUTPUT`) เช่น เป้าหมายผิดชนิด หรือเป้าหมายที่ไม่มีหลักฐานรองรับ
**[ปัญหาโครงสร้างพื้นฐาน]** 0 ครั้ง (ไม่มี `AI_UNAVAILABLE`) ระบบไม่แก้ไขหรือสร้างคำแนะนำซ้ำเพื่อให้ถูกต้องโดยอัตโนมัติ

### 4.x.9 Verification / Re-hunt
**[ผลวัด]** Real Wazuh: 7/9 `RESOLVED`, 2/9 `ERROR` (ไม่มี NOT_RESOLVED/ESCALATED) เวลาตรวจสอบ 0.026–0.091 วินาที
**[ผลวัด]** Mock Verification 10/10 มาจากการรันแบบจำลองที่ freeze ไว้ ซึ่งสะท้อนการเสร็จสิ้นของ re-hunt จำลอง ไม่ใช่หลักฐานการกำจัดภัยคุกคาม และไม่ถูกนำมารวมกับ Real Wazuh
**[ข้อจำกัด]** `RESOLVED` หมายถึงไม่พบ IOC กลับมาในช่วงเวลาที่ค้นหา ไม่ได้พิสูจน์การกำจัดภัยคุกคาม ไม่มีกรณีใดถึง 3 รอบ จึงไม่ได้สังเกตสถานะ `ESCALATED`

### 4.x.10 Consistency
**[ผลวัด]** Recommendation Consistency 29/30 (96.67%) บนหลักฐานชุดเดียวกัน (6 กรณี × 5 ครั้ง, hash ของ snapshot เท่ากันทุกครั้ง); Step-set Consistency 28/30 (93.33%)
**[ข้อสังเกต]** TC-07 มี 1 ใน 5 ครั้งที่เริ่มด้วย ISOLATE-ENDPOINT (ชุดขั้นตอนเท่ากัน ลำดับต่าง) และ TC-04 มี 2 ใน 5 ครั้งที่เพิ่มขั้นตอนเสริม (RESET-CREDENTIAL/REVOKE-SESSION)

### 4.x.11 Negative Validation
**[ผลวัด]** 10/10 คำแนะนำที่ไม่ถูกต้องถูกปฏิเสธ โดยทุกสถานการณ์มี positive control ที่ผ่านการยอมรับ
**[ข้อสังเกต]** ชั้น Policy ปฏิเสธ 2 กรณี (บทบาทผู้รับผิดชอบผิด, การข้ามการอนุมัติ) อีก 8 กรณีปฏิเสธโดยชั้น Action Knowledge/validator ซึ่งรวม NEG-02 (หลักฐานที่ Action ต้องการหายไป) ที่**ไม่ใช่**การปฏิเสธโดย Policy

### 4.x.12 Human/Policy Validation
**[ผลวัด]** 29/29 (100%): ประตูควบคุม G0–G16 และการทดสอบ IR reject (IRR-01..12) SOC, AI_AGENT และ admin อนุมัติไม่ได้, การตัดสินใจต้องมีบันทึก, ไม่เริ่มตอบสนองก่อนอนุมัติ, ไม่ re-hunt ก่อนตอบสนองเสร็จ

### 4.x.13 Baseline Comparison
**[ผลวัด]** ขั้นตอนอ้างอิงแบบกำหนดแน่นอน (ไม่มี AI/มนุษย์) สร้างแผน 9/9 กรณี เฉลี่ย 2.78 ขั้นตอนต่อแผน เวลาเฉลี่ย 0.018 วินาที
**[ข้อจำกัด]** baseline ไม่มีขั้นตอนการตัดสินใจของมนุษย์ จึงเป็นเพียงจุดอ้างอิงเชิงกระบวนการ ไม่ใช่ SOC workflow ที่เทียบเท่า เร็วกว่า หรือดีกว่า

### 4.x.14 IR Reject / Manual Response
**[ผลวัด]** เมื่อ IR_TEAM ปฏิเสธ (TC-06): ไม่มีการดำเนินการ, เหตุการณ์ไม่ถูกปิดอัตโนมัติ, ไม่มีการสร้างคำแนะนำใหม่อัตโนมัติ, สถานะ `PENDING_MANUAL_DECISION`; IR ตัดสินใจเอง (Manual Decision) จึงเข้าสู่ `READY_FOR_EXECUTION` แล้วดำเนินการและตรวจสอบต่อได้ (ผ่าน 12/12)

### 4.x.15 ข้อค้นพบและข้อจำกัด
**[ข้อสังเกต]** ในกรอบ 9 กรณีที่ควบคุม ข้อเสนอแนะทั้งหมดผ่านตัวตรวจสอบและ Policy โดย AI ไม่ได้กำหนด severity, ไม่ได้อนุมัติ และไม่ได้ปิดเหตุการณ์ ปัญหาที่พบคือ TC-03/TC-08 ต้องมีการยืนยันหลักฐานโดยนักวิเคราะห์, TC-07 มีความแปรผันของลำดับ, TC-02/TC-10 ตรวจสอบซ้ำไม่ได้
**[ข้อจำกัด]** ตัวอย่างน้อย (9 กรณี, รันครั้งเดียว), LLM เดียว, ไม่ได้ประเมิน RAG/CTI, การตัดสินใจของ IR เป็นสคริปต์, telemetry ส่วนหนึ่งเป็นกฎและกิจกรรมจำลอง, โค้ดยังไม่ commit ผลนี้จึงแสดงความเป็นไปได้ในสภาพแวดล้อมควบคุม ไม่ใช่การรับประกันความปลอดภัยหรือการเปรียบเทียบกับ SOC จริง
