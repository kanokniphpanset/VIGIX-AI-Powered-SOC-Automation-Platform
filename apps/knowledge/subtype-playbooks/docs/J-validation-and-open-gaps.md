# J. Validation cases, reference integrity และช่องว่างที่ยังค้าง

## 1) สิ่งที่ตรวจแล้ว (รันได้ซ้ำด้วย `node tools/validate.mjs` — ผลล่าสุด: 0 errors, 0 warnings)

| ตรวจอะไร | วิธี | ผล |
|---|---|---|
| ทุก subtype ใน reference (50) มี Playbook · RB id ตรงตาม reference · Action · ACTION_GATE ที่ครอบ subtype นั้น · playbook สั่ง action นั้นจริง | `reference/reference-registry.yaml` เทียบกับ `families/*` | ผ่าน |
| ทุก action มี policy และ runbook; runbook ↔ action อ้างถึงกันครบ (สองทาง) | validate | ผ่าน (49/49) |
| ทุก reference ชี้ id ที่มีอยู่ (action, runbook, policy, subtype branch, gate_policy, include_runbook, fallback_action, variant, capability, authority, target type, evidence) | validate | ผ่าน |
| ไม่มี cyclic dependency ใน `depends_on` | DFS ต่อ scenario | ผ่าน |
| ทุก predicate อ้าง field ที่นิยามใน dictionary; operator ถูกต้อง; ไม่มี `confidence`/retrieval score | `checkPred` | ผ่าน |
| ทุก placeholder `{{type.field}}` ชี้ target type/field ที่มี และเป็น required target หรืออยู่หลัง `condition` ที่ตรวจ target นั้น | validate | ผ่าน |
| ทุก policy item ของ reference (49) และ global principle (12) มี rule ที่ `covers` | [coverage-matrix.md](../coverage-matrix.md) | ผ่าน (0 uncovered) |
| ทุก prohibition ใน ACTION_GATE/GLOBAL ยิงจริง; ทุก policy ไปถึง ELIGIBLE ได้; ลบ target/authority แล้วไม่ ELIGIBLE; `authorization_gate` AUTHORIZED→PROHIBITED, UNKNOWN→NEEDS_EVIDENCE | self-tests สร้างอัตโนมัติ | ผ่าน (265 tests) |
| ทุก subtype: ใส่ classification+gate facts แล้ว action หลัก ELIGIBLE และถูกจัดลำดับ; ใส่ classification evidence อย่างเดียวแล้ว **ไม่** ELIGIBLE (GL-1) และมี investigation fallback | smoke tests สร้างอัตโนมัติ | ผ่าน (100 tests) |
| ลำดับ/การเปิด branch/ตัด step ตามเงื่อนไข ใน 8 หมวดที่ขอ | `validation/cases.yaml` | ผ่าน (42/42): evidence_complete 9 · evidence_insufficient 10 · target_incomplete 6 · authorized_benign 5 · multiple_branches 3 · critical_workload 3 · unsupported_capability 3 · missing_authority 3 |
| RAG chunk ของ action/runbook ไม่หลุดจาก gate (evidence/targets/prohibitions/authority/dependencies/capability) | `checkChunkInvariant` | ผ่าน (213 chunks) |
| migration-map: id ปลายทางมีอยู่จริง | validate | ผ่าน |
| validator ไม่ผ่านเปล่า | mutation test 8 แบบ (ลบ coverage, ref ขาด, field `confidence`, cycle, placeholder ผิด, "ดำเนินการตาม RB-", ลบ authorization_gate, พลิก prohibition) | จับได้ทั้ง 8 |

### Acceptance §7.2 (Scheduled Task Hijack) — ผลจริงจาก `render.mjs`
| ข้อกำหนด | Case | ผล |
|---|---|---|
| หลักฐานครบ → หยุด Task → หยุด running instance → ยุติ payload+children (process identity) → จำกัด outbound แบบ granular + ตัด connection ที่ค้าง → quarantine | VC-06 → [scheduled-task-hijack-full](../recommendation/examples/scheduled-task-hijack-full.md) | ตรงตามลำดับ; Disable ≠ หยุด instance (แยกเป็นสองข้อ) |
| ไม่มี process identity → ไม่แสดงคำสั่ง terminate | VC-20 → [no-process-identity](../recommendation/examples/scheduled-task-hijack-no-process-identity.md) | ไม่มี step terminate; ระบุ target ที่ขาด |
| ไม่มีหลักฐาน outbound ที่เป็นอันตราย → ไม่เพิ่ม network deny | VC-22 | `absent_actions: ACT-WEB-C2-CONTAIN, ACT-CUSTOM-CHANNEL-CONTAIN` |
| ไม่มี file identity → ไม่ quarantine | VC-21 → [no-file-identity](../recommendation/examples/scheduled-task-hijack-no-file-identity.md) | `ACT-QUARANTINE-FILE-OBJECT: NEEDS_TARGET` |
| approved task change → ไม่เปิด malicious containment | VC-26 → [approved-change](../recommendation/examples/scheduled-task-approved-change.md) | `PROHIBITED` → แสดงเฉพาะ "ยืนยัน change record" |

## 2) ข้อจำกัดของสิ่งที่ "ตรวจแล้ว" (อ่านก่อนอ้างว่า validated)
- ตรวจ **ความสอดคล้องภายในของ knowledge + semantics ของ evaluator ต้นแบบ** ไม่ได้ตรวจกับ alert จริงหรือ LLM จริง; `target_values` ในตัวอย่างเป็นค่าสังเคราะห์ (ชื่อ `.test`, IP ช่วง RFC 5737)
- `covers[]` เป็นการประกาศ mapping + self-test ว่า prohibition ยิงจริง; ข้อที่บังคับได้เฉพาะตอน **render ข้อความ** (AC-P2 ไม่แสดง secret, EXF-P4/P5, SQ-P6, GL-7, GL-12) ยังเป็น `OUTPUT_CONSTRAINT` ที่ **ยังไม่มีตัวตรวจ runtime** (render.mjs ทำตามบางส่วน: ไม่แสดง ID/placeholder, ไม่อ้างว่าสำเร็จ)
- `CLASSIFICATION_RULE` (8 ข้อ) เป็นข้อความอธิบาย; ผลจริงมาจาก `classification_evidence` + ACTION_GATE ที่ถูก test

## 3) ช่องว่างที่ยังค้าง (unresolved)
| # | เรื่อง | ผลกระทบ / ต้องทำ |
|---|---|---|
| GAP-01 | ORGANIZATION_CONTEXT ส่วนเครื่องมือ **MISSING** (firewall/WAF/EDR/IdP/mail/DNS/cloud/secret manager/DB) | ทุก runbook เป็น platform-neutral + `TOOL_MAPPING_REQUIRED`; ไม่มีชื่อเมนู/คำสั่ง/API; เติม `tool_variants` ต่อ capability เมื่อรู้เครื่องมือ |
| GAP-02 | รายการที่ policy ต้องใช้แต่ไม่มีข้อมูล: approved management/IR access list, approved automation/RMM inventory, emergency IR authority, DBA / asset owner / change approval ผู้รับผิดชอบจริง | `authority.*` เป็น UNKNOWN → action ที่ต้องใช้ (เช่น SQ-* ต้อง `change_approval`) จะเป็น NEEDS_AUTHORIZATION จนกว่าจะกำหนด |
| GAP-03 | **(แก้แล้วในส่วน backend — ดู README; ยังไม่ทดสอบ live)** เดิม: Runtime ยังไม่เชื่อม: evidence extractor, target resolver (คำนวณ `targets.*.validated` + 42 `scope.*` flags), policy evaluator ใน backend, orderer/step selector, composer, output validator, audit writer, loader/DB mapping, vector index | รายการและ port path ใน [RAG-and-runtime.md](RAG-and-runtime.md); `tools/*.mjs` เป็น semantics อ้างอิง ไม่ใช่โค้ด production |
| GAP-04 | evidence จำนวนมากต้องการแหล่งข้อมูลที่ Wazuh อย่างเดียวไม่มี (mail gateway, IdP, cloud audit, EDR process GUID/lineage, DB query log) | ต้องมี enrichment/integration ก่อนที่ evidence เหล่านั้นจะเป็น PRESENT ได้จริง |
| GAP-05 | reference ไม่ครอบคลุม **LATERAL_MOVEMENT**, ransomware ในฐาน family, และ "scheduled task hijack" ที่ไม่ใช่ PowerShell/privileged | ทำ scenario `SC-PS-PERSIST-TASK-HIJACK` / `SC-PE-SERVICE-TASK-HIJACK` เท่านั้น; ไม่แต่ง subtype ใหม่นอก reference |
| GAP-06 | **(แก้แล้ว: planner ทำ instance ต่อ action+target identity)** เดิม: 1 instance ต่อ action_id: ถ้ามี target หลายชุดของ action เดียวกัน (เช่น บัญชีที่ถูกยึด 2 บัญชี) planner ยังไม่ทำ "instance ต่อ target" | ต้องเพิ่ม per-target fan-out ใน planner (field `parallel_allowed` มีแต่ยังไม่ถูกตีความ) |
| GAP-07 | **(แก้แล้ว: step มี `title` ภาษาไทยชัดเจน, validator บังคับ; ยังรอ SOC รีวิวถ้อยคำ)** เดิม: ชื่อหัวข้อของ step สร้างอัตโนมัติจากประโยคแรก; precheck ที่ fold รวมยาว | ควรเขียน `title` ชัดเจนต่อ step สำหรับ UI/ข้อความสุดท้าย |
| GAP-08 | ภาษาไทยยังไม่ผ่านการรีวิวโดย SOC analyst ผู้ใช้จริง (ตั้งใจใช้ Disable/Revoke/Quarantine เป็นอังกฤษ) | รีวิวถ้อยคำ/ผลกระทบ/ตรวจผล |
| GAP-09 | การเรียงลำดับ **ภายใน** runbook เป็นการออกแบบของงานนี้ที่ reference ไม่ได้ระบุตรงๆ: (ก) ปิด trigger ก่อนยุติ process (กัน relaunch) ใน MAL-BACKDOOR/PS-PERSIST/PE-SERVICE (ข) session revoke ก่อน reset ใน AC-PASSWORD (ค) ตัด write sessions ก่อน isolate ใน MAL-RANSOM (ง) ผู้มีอำนาจ hold ก่อนตัด mailbox ใน PH-BEC | ต้องให้ IR/SOC lead รีวิวเหตุผล; แต่ละข้อมี `order_reason` ใน playbook |
| GAP-10 | capability UNKNOWN ในโหมด platform-neutral ถือว่า "step ใช้ได้" (พร้อม flag) | อาจ render step ที่องค์กรทำไม่ได้จริง; strict mode เปลี่ยนเป็น UNSUPPORTED |
| GAP-11 | ตัวอย่างที่ render ยังไม่ได้ผ่าน LLM; ไม่ได้ทดสอบ retrieval จริง (embedding/Qdrant) | ต้อง evaluate end-to-end กับ TC-01..TC-10 หลังเชื่อม runtime |
| GAP-12 | ไม่ได้แก้ไฟล์ runtime/seed เดิม (migration เป็นแผน + แผนที่ id) | งาน seed/loader/Prisma ทำแยก (ดู worktree + Prisma pitfalls ในโปรเจกต์) |
| GAP-13 | **Evidence Contract v2** (`docs/architecture/evidence-contract-v2.md`, extractor `apps/backend/src/domain/investigation/evidenceV2/`, flag `EVIDENCE_CONTRACT_V2`) เป็นงานคู่ขนานที่อยู่ในรีโปแล้ว — **ไม่ได้อ่านละเอียดในงานนี้** | `evidence_record` (§3.1: status/authorization_status/lineage) ต้อง reconcile กับ contract v2 (provenance, process/network/account fields) แทนการสร้าง extractor ซ้ำ; ตรวจว่า field ที่ target resolver ต้องใช้ (process guid/start time, destination role) มีใน v2 หรือไม่ |
| GAP-14 | Wazuh correlation alert (เช่น rule 40112 "หลาย failure แล้วสำเร็จ") ไม่มีจำนวน failure ต่อ event; runtime สร้าง evidence brute-force จากจำนวนที่นับได้ตาม threshold ของ VIGIX เท่านั้น จึงไม่เสนอ action (FN ใน GT-R1-05) | ตัดสินใจว่าจะรับ correlation rule เป็นหลักฐานโดยตรง (ต้องมี semantic ของ rule ที่ IR ยืนยัน) หรือไม่ — ยังไม่แก้ |
| GAP-15 | step ปฏิบัติการ 19 จาก 144 (ORG_INPUT_REQUIRED 15, IR_REVIEW_REQUIRED 4) ยังไม่มี method; เป็น "ข้อมูลที่ต้องตรวจเพิ่ม" จนกว่าองค์กร/IR จะให้ข้อมูล | ดู `method_requires` ของแต่ละ step และ `tools/methods.json` |
