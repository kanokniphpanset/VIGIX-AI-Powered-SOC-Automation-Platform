# VIGIX — Extended Evaluation Report (LOW / False Positive, RAG, ESCALATED, Windows)

Generated 2026-10-01 on `soar_ext_eval` (clone of the frozen Knowledge Base; run data reset). Same rules as the final evaluation: ground truth pinned before the runs
(`ground-truth.sha256`), database as source of truth (JSON built by `build-extended.ts`, cross-checked by `extended-db-metrics.sql`), failures recorded as failures,
infrastructure failures classified separately, nothing estimated. Frozen and final results are unchanged (`ext-integrity.json`: all checks pass).
Verification in this report is always **REAL_WAZUH**; MOCK is not used.

## Summary table

| Part | Result | N | Source | Notes |
|---|---|---|---|---|
| A1. LOW alerts kept out of the SOC workflow | **4/4** | 4 | DB | levels 3, 5, 5, 6 → `low`; no incident / AI execution / recommendation / ticket; SOC cannot escalate or close them |
| A2. MEDIUM false positives closed by SOC triage without incident or AI | **2/2** | 2 | DB | levels 7 (boundary) and 10; audit `ALERT_TRIAGED`; a second decision is refused |
| A3. CRITICAL benign alert (approved change) | auto-incident opened; inbox close refused; recommendation produced; IR rejected; **0 executions**; incident dismissed by a human | 1 | DB | the cost of a false positive on HIGH/CRITICAL is an incident, an AI analysis (69 s) and a containment recommendation (disable `opsadmin`, isolate endpoint) |
| A4. Benign alerts leading to an executed response | **0/7** | 7 | DB | |
| A5. Rule-level False Positive Rate | NOT CALCULABLE — needs a labelled benign event stream (denominator = all benign events); only 3 benign scenarios were run | – | – | |
| A6. AI false-positive detection | NOT CALCULABLE — VIGIX has no false-positive verdict; the AI never triages | – | – | |
| B. RAG retrieval (17-runbook corpus) | primary runbook at rank 1 in **6/9**, in top-3 **6/9**, any relevant runbook in top-3 **8/9**; Precision@3 mean 0.52, Recall@3 mean 0.38, MRR mean 0.76 | 9 | DB (`agent_results`) | misses: TC-04, TC-06, TC-10 (the action-level runbook for the case was not in the top 5) |
| B. RAG effect on recommendations | no effect can be attributed (see §3) | 9 + 9 | DB | A: 6 compliant / 3 no valid recommendation; B: 7 / 2; workflow 5/9 in both |
| C. ESCALATED path | **reached**: 3 × REAL_WAZUH `NOT_RESOLVED` → incident `escalated` at investigation #3 | 1 incident | DB | first attempt INCOMPLETE (LLM endpoint failure, infrastructure) |
| D. Windows endpoint (TC-05) | **ENVIRONMENT_UNAVAILABLE** | – | – | no Windows agent connected yet; nothing simulated or fabricated |

Figures: `figures/figure1_low_false_positive`, `figure2_escalated_path`, `figure3_rag`, `figure4_ip_order_diagnostic` (`.png` + `.pdf`).

---

## 1. LOW severity and False Positive (ground truth: `groundTruthExtended.ts`, rule ids calibrated with `calibrate.ts` before the run)

| Case | Benign scenario | Wazuh rule / level | Severity (DB) | Handling observed | Checks |
|---|---|---|---|---|---|
| LOW-01 | valid SSH login | 5715 / 3 | low | stored, `ALERT_OUTSIDE_SOC_WORKFLOW`, no incident, SOC `NOT_IN_SOC_WORKFLOW` | 8/8 |
| LOW-02 | one mistyped password | 5760 / 5 | low | same | 8/8 |
| LOW-03 | 404 for a missing page | 31101 / 5 | low | same | 8/8 |
| LOW-04 | XSS-looking string (boundary, level 6) | 31105 / 6 | low | same | 8/8 |
| FP-01 | authorised scan, one SQLi-looking request | 31103 / 7 | medium | `ALERT_ROUTED_TO_TRIAGE`, no automatic incident, SOC `FALSE_POSITIVE` → `TRIAGED`/closed, second decision `ALERT_ALREADY_DECIDED`, zero side effects | 10/10 |
| FP-02 | authorised crawler, burst of 4xx | 31151 / 10 | medium | same | 10/10 |
| FP-03 | approved change: `opsadmin` added to `sudo` | 100350 / 14 (custom rule) | critical | incident opened **automatically**; inbox close refused (`ALERT_IN_INCIDENT`); AI analysis + recommendation `PB-ACCOUNT-COMPROMISE` (DISABLE-ACCOUNT→opsadmin, ISOLATE-ENDPOINT→attack-endpoint); IR_TEAM rejected → `PENDING_MANUAL_DECISION`; start refused; 0 step executions; no regeneration; `resolved` refused by hand; incident set to `dismissed` by a human | 13/13 |

Totals: 65/65 database-verified checks. Measured-vs-observation: the 65 checks are conformance checks of designed behaviour; the interesting measurements are the counts above (0/7 executed; a MEDIUM false positive costs no AI work, a CRITICAL one cannot be closed from the inbox and costs an incident + analysis + recommendation).
Observations: (1) the AI analysis of FP-03 lists "Administrative Maintenance" as a hypothesis and says intent is unknown, but the recommendation is still containment — the AI has no false-positive verdict and was not graded on one; (2) after an IR reject the ticket stays `PENDING_MANUAL_DECISION`; no use case closes or cancels it; (3) FP-03 telemetry is identical to TC-10 by construction: VIGIX cannot tell a benign from a malicious privilege change by rule, the human gate does.
Limitations: three benign scenarios, one run each; benign labels are the author's; the SOC/IR actions are scripted API calls; stock rules for LOW/MEDIUM, custom rule for FP-03.

## 2. ESCALATED path (ESC-01, TC-07 telemetry, REAL_WAZUH re-hunt)

| Round | Response step (approved by scripted IR, simulated) | Recurrence | Re-hunt result | Incident afterwards |
|---|---|---|---|---|
| 1 | BLOCK-DESTINATION-IP → 172.19.0.5 | same beacon repeated after completion | NOT_RESOLVED, 3 matching events | investigating, investigation #2 |
| 2 | BLOCK-DESTINATION-IP → 172.19.0.7 | repeated | NOT_RESOLVED, 3 | investigating, investigation #3 |
| 3 | BLOCK-DOMAIN → vigix-eval-c2.net (earlier recommendation; see below) | repeated | NOT_RESOLVED, 3 | **escalated**, still investigation #3 |

Audit trail (DB): `INVESTIGATION_REOPENED` ×2, `INVESTIGATION_ESCALATED` ×1 and `INCIDENT_ESCALATED` ×1 with reason `MAX_INVESTIGATION_ROUNDS_REACHED`, handed to SOC and IR_TEAM; no recommendation, ticket or execution after the third verification; manual `resolved` refused; a fourth verification of the same ticket refused (`ALREADY_VERIFIED`); no AI actor changed the incident status. 15/15 checks. ESCALATED is recorded only because the third round was reached.
Failures and infrastructure: the first attempt (`ext-esc-20261001`) ended **INCOMPLETE** — the LLM endpoint failed DNS resolution (`ConnectError`) during analysis/recommendation; kept as a record, not counted. In the successful run the automatic new-round recommendation failed once with `AI_UNAVAILABLE` (round 1) and once with `NO_NEW_RECOMMENDATION` (rounds 2 and 3: every action+target pair of the playbook was already proposed). The harness then generated the round-2 recommendation by hand (1 attempt) and, in round 3, where 5 model attempts all returned `NO_NEW_RECOMMENDATION`, the "SOC" handed an unexecuted step of the earlier recommendation to IR (recorded as `fallbackToEarlierRecommendation`). So the loop reaches escalation, but a new round does not always have a new recommendation.
Observation: the round-1 response step blocks the endpoint's own address (the IP-role problem, see §4); only the IR gate and the simulated execution prevented harm.
Limitations: one scenario; the recurrence is produced by the harness; the decisions NOT_RESOLVED / reopen / escalate are the product's.

## 3. RAG

Design: the same 10 cases through the same pipeline in `clean` mode (no analyst correction), two conditions on the same code and database: **A** = RAG reachable but the isolated Qdrant empty (retrieval status `not_found`), **B** = the 17 ACTIVE runbooks indexed by the project's own indexer (`indexRunbooksToQdrant.ts`, BGE-small 384-d cosine, isolated Qdrant 1.19.1 on :6335). The orchestrator reached a minimal stand-in for the backend (`search-server.ts`) that mounts the real `KnowledgeSearchController`; every other backend path was unreachable, as in the earlier runs. Relevance labels (`ragGroundTruth.ts`, hash pinned) were written before any retrieval. All runbooks have `sourceType: PLAYBOOK`; the project has no KNOWLEDGE-type documents, so that half of the dual retrieval has no corpus by construction.

Retrieval quality (B, 9 attempted cases, the stored `rag` agent result): primary runbook at rank 1 in 6/9 (TC-01, 02, 03, 07, 08, 09), in the top 3 in 6/9; at least one relevant runbook in the top 3 in 8/9; Precision@3 mean 0.52 (SD 0.34), Recall@3 mean 0.38 (SD 0.19), MRR mean 0.76 (SD 0.38). Misses: TC-04 and TC-10 (RB-DISABLE-ACCOUNT not in the top 5; attack-level runbooks for brute force / phishing / malware outrank it) and TC-06 (RB-BLOCK-SOURCE-IP not in the top 5). With 17 short runbooks this is an easy corpus; no claim about a larger knowledge base.

Pipeline outcome (one run per case per arm):

| | A: empty corpus | B: 17 runbooks |
|---|---|---|
| Recommendations COMPLIANT / evaluated | 6/6 | 7/7 |
| Attempted cases with no valid recommendation | 3 (TC-02, TC-03, TC-08) | 2 (TC-03, TC-08) |
| Cases needing a retry / total retries | 4 / 17 | 2 / 10 |
| Workflow completed | 5/9 | 5/9 |
| Investigation time, mean (n) | 79.33 s (6) | 72.84 s (7) |

**No effect of RAG can be attributed.** One run per arm sits inside the run-to-run variation measured earlier (consistency 29/30); TC-02 differs (A: no valid recommendation, B: valid, but the case then stops at the re-hunt), and TC-03/TC-08 fail in both arms without analyst intervention (as in the earlier clean runs). Retries and investigation times differ, but with different n and LLM latency swings they are not comparable.
Repeated generation on the same evidence (TC-07, TC-09; 5 repetitions each, no persistence; infrastructure failures excluded and repeated): consistency 10/10 with the corpus and 10/10 without it; the first BLOCK-DESTINATION-IP step targeted the destination IP in all 20; 4/10 recommendations in each arm additionally listed a destination-IP step aimed at the endpoint.
Limitations: n = 9; the author's relevance labels; one corpus; RAG text also enters the recommendation prompt (PLAYBOOK top-3) so its effect cannot be separated from LLM variance; the earlier final evaluation ran with RAG unreachable ("unavailable"), which differs slightly from condition A ("no relevant runbook").

## 4. Diagnostic that changed an earlier conclusion — IP role

While comparing arms, BLOCK-DESTINATION-IP pointed at the endpoint's own IP (the traffic's *source*) in the final-evaluation TC-07/TC-09 and in arm A, but at the real destination in arm B — which first looked like a RAG effect. It is not. The recommendation contexts of the two situations differ **only in the order** of the IP candidates (`[.5 source, .7 destination]` vs `[.7, .5]`); the context carries no role. Reversing only the order for the same evidence (5 runs × 2 incidents × 2 orders, `data/order-experiment.json`): destination-first → the first destination-IP step was correct in 9/10 runs (1 without such a step); source-first → 0/10 (8 source IPs, 2 without). The model takes the first listed IP. The final report has been corrected accordingly (`results/final-evaluation/CORRECTIONS-final.md`). The Recommendation Compliance criterion does not check IP role.

## 5. Windows endpoint (TC-05 PowerShell)

**ENVIRONMENT_UNAVAILABLE.** Docker here is in Linux mode and no Windows VM is available to the harness. The chosen route is an existing Windows machine/VM with a Wazuh agent 4.9.2 pointed at the manager (ports 1514/1515) and PowerShell Script Block Logging enabled (`Microsoft-Windows-PowerShell/Operational` collected). Once it is connected: calibrate which rule fires for a benign encoded PowerShell command (`apps/backend/scripts/eval/extended/windows/simulate-tc05.ps1`, run on that machine), freeze a new ground truth `TC-05W` (the frozen `groundTruthReal.ts` is not edited), run the standard pipeline and report it as REAL_WAZUH. Until then TC-05 stays unavailable in every table.

## 6. Limitations (whole extended evaluation)

1. n is small everywhere (7 + 1 + 9 cases, one run per condition); no significance claims.
2. Scripted SOC/IR actions; the harness plays the humans.
3. Controlled lab telemetry; FP-03 and ESC-01 use custom rule 100350 / 100320; benign labels and relevance labels are the author's.
4. The LLM endpoint was unstable during parts of the session (DNS failures); every such event is classified infrastructure and was not counted as a model result; the affected unit was repeated (ESC-01) or the call retried.
5. RAG: 17-runbook corpus, PLAYBOOK side only; a stand-in search server replaced the full backend.
6. Rule-level false-positive rate, AI false-positive detection and Windows results are NOT CALCULABLE / UNAVAILABLE as stated.
7. Dev database, frozen evaluation and final evaluation are untouched; the isolated Qdrant container `vigix-eval-qdrant` and the second orchestrator remain running unless stopped.

## 7. ผลการทดลองเพิ่มเติม (ร่างสำหรับวิทยานิพนธ์)

**[ผลวัด] LOW และ False Positive.** แจ้งเตือนระดับต่ำ (level 3, 5, 5, 6) ถูกจัดเป็น `low` และเก็บไว้เฉพาะบันทึก ไม่เปิด incident ไม่เรียก AI ไม่สร้างคำแนะนำ และ SOC ยกระดับหรือปิดไม่ได้ (4/4) แจ้งเตือน MEDIUM ที่เป็นเหตุปกติ (level 7 และ 10) ไม่เปิด incident อัตโนมัติ SOC ปิดเป็น `FALSE_POSITIVE` ได้โดยไม่เกิดงานของ AI (2/2) แจ้งเตือน CRITICAL ที่เกิดจากการเปลี่ยนแปลงที่ได้รับอนุมัติเปิด incident อัตโนมัติและปิดจาก inbox ไม่ได้ ระบบสร้างคำแนะนำควบคุม (ปิดบัญชี, แยกเครื่อง) IR_TEAM ปฏิเสธ จึงไม่มีการดำเนินการใด (0/7 กรณีเหตุปกติที่นำไปสู่การตอบสนอง) แล้วมนุษย์ตั้งสถานะ incident เป็น `dismissed`
**[ข้อสังเกต]** AI ไม่มีคำตัดสิน false positive และไม่ได้ถูกประเมินด้านนี้ ต้นทุนของ false positive ระดับสูงคือ incident, การวิเคราะห์ และคำแนะนำที่ต้องให้ IR ปฏิเสธ
**[ข้อจำกัด]** อัตรา false positive ระดับกฎ NOT CALCULABLE (ต้องมีสตรีมเหตุปกติที่ติดป้ายครบ) มีเพียง 3 สถานการณ์เหตุปกติ

**[ผลวัด] เส้นทาง ESCALATED.** re-hunt จริงพบการกลับมาของ IOC ครบ 3 รอบ (NOT_RESOLVED ×3, 3 เหตุการณ์ต่อรอบ) incident เปลี่ยนเป็น `escalated` ที่ investigation ที่ 3 โดยไม่ปิดและไม่ resolved มี audit INVESTIGATION_REOPENED ×2 และ INVESTIGATION_ESCALATED/INCIDENT_ESCALATED พร้อมเหตุผล MAX_INVESTIGATION_ROUNDS_REACHED ไม่มีการสร้างคำแนะนำหรือดำเนินการอัตโนมัติหลัง escalate (15/15)
**[ความล้มเหลว]** การลองครั้งแรกไม่สมบูรณ์เพราะ LLM endpoint ล่ม (ปัญหาโครงสร้างพื้นฐาน) และการสร้างคำแนะนำรอบใหม่ล้มเหลว (`AI_UNAVAILABLE` 1 ครั้ง, `NO_NEW_RECOMMENDATION` ในรอบ 2–3) เพราะคู่ action+target ของ playbook ถูกเสนอไปหมดแล้ว **[ข้อจำกัด]** ทดสอบเพียงสถานการณ์เดียว การโจมตีซ้ำถูกจำลองโดยสคริปต์

**[ผลวัด] RAG.** คลังคือ runbook 17 รายการ runbook หลักอยู่อันดับ 1 ใน 6/9 กรณี อยู่ใน top-3 ใน 6/9 มี runbook ที่เกี่ยวข้องใน top-3 ใน 8/9 Precision@3 เฉลี่ย 0.52, Recall@3 เฉลี่ย 0.38, MRR เฉลี่ย 0.76 (พลาด TC-04, TC-06, TC-10) การเปรียบเทียบแบบมี/ไม่มีคลังบน pipeline เดียวกัน: compliant 7/7 เทียบ 6/6, ไม่มีคำแนะนำที่ใช้ได้ 2 เทียบ 3 กรณี, workflow สำเร็จ 5/9 ทั้งสองแบบ
**[ข้อสังเกต/ข้อจำกัด]** รันกรณีละครั้งต่อเงื่อนไข ความต่างอยู่ในช่วงความแปรปรวนของ LLM จึง**ไม่สามารถสรุปว่า RAG ทำให้ดีขึ้น** คลังเล็กและง่าย และไม่มีเอกสารประเภท KNOWLEDGE

**[ข้อค้นพบสำคัญ] บทบาทของ IP.** ขั้น BLOCK-DESTINATION-IP ชี้ไปที่ IP ของ endpoint เอง (ต้นทาง) เมื่อ context ลำดับ IP เป็น [ต้นทาง, ปลายทาง] และชี้ถูกเมื่อลำดับกลับกัน (ถูก 9/10 เทียบ 0/10 เมื่อสลับเฉพาะลำดับ) โมเดลเลือก IP ตัวแรกที่ระบุ และ context ไม่มีข้อมูลบทบาท ตัวประเมิน Compliance ไม่ตรวจเรื่องนี้ จึงให้ผ่าน

**Windows endpoint.** ยังเป็น ENVIRONMENT_UNAVAILABLE รอเครื่อง Windows ที่ติดตั้ง Wazuh agent
