# B. รายการ KEEP / UPDATE / ADD / DEPRECATE

รายละเอียด id→id ต่อรายการอยู่ใน [../migration-map.yaml](../migration-map.yaml) (ตรวจว่า id ปลายทางมีอยู่จริงโดย `tools/validate.mjs`).
**ไม่มีไฟล์ runtime เดิมถูกแก้ในงานนี้** — "UPDATE/DEPRECATE" ในที่นี้คือสถานะของ knowledge ใน layer ใหม่และแนวทางที่ runtime ควรทำตาม; ข้อมูลเดิมคงอยู่เพื่อ history/snapshot.

## ADD (ใหม่ทั้งหมด)
| ชนิด | จำนวน | รายการ |
|---|---|---|
| Subtype playbook | 50 | `PBK-<subtype>` ครบทุก subtype ใน reference (+51 scenario) |
| Action | 49 | 47 ตาม RB ใน reference (1:1) + `ACT-QUARANTINE-FILE-OBJECT` + `ACT-INVESTIGATE-MISSING-EVIDENCE` (ทั้งสองเป็นส่วนเสริมที่ **ไม่อยู่ใน reference** — derive จาก §7/§7.2: quarantine ที่ต้องมี file identity, และขั้นตอนตรวจสอบเมื่อไม่มี containment ผ่าน) |
| Runbook | 49 | RB id ตาม reference 47 ตัว (รักษา id) + `RB-QUARANTINE-FILE-OBJECT`, `RB-INVESTIGATE-MISSING-EVIDENCE` |
| Policy rule | 65 | 52 ACTION_GATE · 3 BRANCH_GATE · 8 CLASSIFICATION_RULE · 1 GLOBAL_PROHIBITION (12 prohibitions) · 1 OUTPUT_CONSTRAINT (12 checks) |
| Evidence catalog | 63 | สถานะแยก attempted/delivered/clicked/submitted/executed/unauthorized success/active damage/confirmed transfer |
| Target type | 37 | identity fields ต่อ action (ไม่บังคับ field เดียวกันทุกที่; MAL-MEMORY ไม่ต้องมี file/hash) |
| Field dictionary | 1 | namespaces ปิด + 6 operators + 3-valued null semantics + 31 capabilities + 6 authorities + 42 scope flags |
| Recommendation output contract + 6 ตัวอย่าง | — | ดู `recommendation/` |
| Validation cases | 42 | 8 หมวด; + 265 policy self-tests |
| RAG chunks + metadata | 213 | gate-complete invariant |

## UPDATE
- **DB playbooks `PB-*` (10)** → แตกเป็น subtype playbooks; ของเดิมคงเป็น incident-level container (ไม่ลบ)
- **YAML procedures** (`PB-STC-001/procedures/*`): โครง 7-phase คงเดิม; `RANSOMWARE` ย้ายเป็น MAL-RANSOM; `SUSPICIOUS_PROCESS_EXECUTION` → family key `SUSPICIOUS_PROCESS`; `containment.yaml` ควรชี้ action id ใหม่และเปลี่ยน `condition` ข้อความเป็น predicate (งานเชื่อม runtime — ยังไม่ทำ)
- **Action Catalog เดิม 15 ตัว** (ยกเว้น ACT-007/008): เปลี่ยนสถานะเป็น "primitive operation" ที่ถูกอ้างจาก `legacy_action_refs`; ไม่ถูกเสนอเป็นมาตรการเดี่ยวใน flow ใหม่
- **Runbook เดิม 14 action-level**: เนื้อหา 5 ข้อถูกขยายเป็น step ผูก target/condition/verify/rollback ใน runbook subtype ใหม่
- **Policy `POL-A02/A03` + `ActionKnowledge.analystConfirmed`**: เงื่อนไขข้อความ → evidence/target/scope predicate

## KEEP
- Workflow policies (priority/assignment/approval/intake/triage SLA/verification: `POL-001..007`, `RULE-A/P/I/T/V*`, `POL-A01`) — orthogonal กับ evidence gate
- โครง 7 phases ของ `PB-STC-001`, convention `CHECK/ACTION/MANUAL` ใน YAML steps
- `ACT-007 Collect Evidence`, `ACT-008 Re-hunt IOC` (investigation/verification)
- Asset criticality catalog (ใช้เป็นแหล่ง `context.asset_criticality`)
- `LATERAL_MOVEMENT` ที่ยัง PLANNED (reference ไม่ครอบคลุม — ดู GAP-05)

## DEPRECATE (ไม่เลือกใน flow subtype ใหม่; ไม่ลบ)
- `ACT-BLOCK-SOURCE-IP` (standalone), `ACT-BLOCK-HASH` (OS binary risk)
- `RB-BRUTEFORCE-001`, `RB-MALWARE-001`, `RB-PHISHING-001`, `RB-NETWORK-001`, `RB-BLOCK-SOURCE-IP`, `RB-BLOCK-HASH` (generic/incident-level)
- `procedures/WEB_ATTACK` (PLANNED) — ซ้อนกับ PROC-CHAIN / SQ-*
