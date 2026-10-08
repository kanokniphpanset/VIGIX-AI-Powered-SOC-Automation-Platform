# subtype-playbooks — Subtype-level Playbook / Policy / Runbook / Recommendation knowledge (v2.0.0)

Knowledge layer ใหม่ที่เชื่อม **Playbook ↔ Policy ↔ Runbook ↔ Recommendation** ด้วย contract เดียวกัน ตาม REFERENCE_PATTERN 10 attack families (50 subtypes)
ข้อมูลเป็น YAML ล้วน (ไม่ execute) — ไม่ได้ลบ/แทน runtime เดิม — ต่อเข้าเป็น path เสริม (`apps/knowledge/playbooks/PB-STC-001`, Prisma seeds, `actionKnowledge.ts`) ID เดิมยังใช้ได้; ดู [migration-map.yaml](migration-map.yaml)

> สถานะ: knowledge + validator เสร็จและตรวจผ่าน · **backend runtime เชื่อมแล้ว** (`apps/backend/src/domain/subtype`, `application/subtype`, `GenerateRecommendationUseCase`) โดยค่าเริ่มต้นเป็นโหมด **shadow** (คำแนะนำเดิมยังเป็นผลที่ผู้ใช้เห็น, ผล subtype เก็บเป็น audit แยก) · โหมด `enforce` ใช้ได้เมื่อ IR รีวิวครบหรือตั้ง `SUBTYPE_ALLOW_UNREVIEWED` · **ยังไม่ได้ทดสอบกับ LLM จริง / alert จริง / DB migration ยังไม่ apply** — ดู [docs/RAG-and-runtime.md](docs/RAG-and-runtime.md), [docs/J-validation-and-open-gaps.md](docs/J-validation-and-open-gaps.md), [contracts/review-register.yaml](contracts/review-register.yaml)

## รันตรวจ

```bash
node apps/knowledge/subtype-playbooks/tools/validate.mjs                 # reference integrity + coverage + 42 cases + 265 policy self-tests + 100 per-subtype smoke tests + RAG-chunk invariant
node apps/knowledge/subtype-playbooks/tools/validate.mjs --write-matrix  # เขียน coverage-matrix.md
node apps/knowledge/subtype-playbooks/tools/render.mjs VC-06 --audit     # ข้อความที่ผู้ใช้เห็น + internal audit record ของ case
node apps/knowledge/subtype-playbooks/tools/render.mjs --write-examples  # เขียน recommendation/examples/*.md
node apps/knowledge/subtype-playbooks/tools/build-chunks.mjs --write     # เขียน rag/chunks.jsonl (213 chunks)
```
ใช้ `js-yaml` จาก `node_modules` ของรีโป (Node ≥ 18). ผลล่าสุด: **0 errors, 0 warnings**

## ผลลัพธ์ตามหัวข้อที่ขอ (A–J)

| | หัวข้อ | ที่อยู่ |
|---|---|---|
| A | Gap Analysis | [docs/A-gap-analysis.md](docs/A-gap-analysis.md) |
| B | KEEP / UPDATE / ADD / DEPRECATE | [docs/B-change-list.md](docs/B-change-list.md) |
| C | Shared schemas + field dictionary | [contracts/schemas.yaml](contracts/schemas.yaml) · [contracts/field-dictionary.yaml](contracts/field-dictionary.yaml) · [contracts/target-types.yaml](contracts/target-types.yaml) · [contracts/organization-context.yaml](contracts/organization-context.yaml) |
| D | Playbook (50 subtypes, 51 scenarios) | `families/*.yaml` → `playbooks:` |
| E | Structured Policy rules (65 rules / 107 prohibitions) | `families/*.yaml` → `policies:` (+ `families/_global.yaml`) |
| F | Runbook (49 runbooks, 259 steps) | `families/*.yaml` → `runbooks:` |
| G | Recommendation template + ตัวอย่าง | [recommendation/output-contract.yaml](recommendation/output-contract.yaml) · [recommendation/examples/](recommendation/examples/) |
| H | Subtype coverage matrix | [coverage-matrix.md](coverage-matrix.md) (generated) |
| I | Migration mapping | [migration-map.yaml](migration-map.yaml) |
| J | Validation cases + unresolved gaps | [validation/cases.yaml](validation/cases.yaml) · [docs/J-validation-and-open-gaps.md](docs/J-validation-and-open-gaps.md) |
| §9 | RAG metadata / chunking / retrieval flow | [rag/retrieval-metadata.yaml](rag/retrieval-metadata.yaml) · [docs/RAG-and-runtime.md](docs/RAG-and-runtime.md) · `rag/chunks.jsonl` |

## โครงสร้าง

```
subtype-playbooks/
├── reference/reference-registry.yaml   REFERENCE_PATTERN ถอดแบบ 1:1 (50 subtypes, RB ids, 49 policy items, 12 global principles) = provenance anchor
├── contracts/                          schemas, field dictionary (closed namespaces), 37 target types, org-context status
├── families/                           _global + 10 families: evidence · actions · playbooks · policies · runbooks (ต่อ family ในไฟล์เดียว)
├── recommendation/                     output contract + ตัวอย่างที่ render จาก validation cases
├── validation/cases.yaml               42 executable cases (8 หมวดตามที่ขอ)
├── rag/                                retrieval metadata + chunks.jsonl
├── tools/                              lib (predicate/policy evaluator/planner), validate, render, build-chunks
├── migration-map.yaml · coverage-matrix.md · docs/
```

## หลักการที่ถูก enforce ด้วยโค้ด (ไม่ใช่แค่ข้อความ)

1. **Policy เป็น predicate** บน field ที่นิยามไว้ปิด (`evidence.* / targets.* / scope.* / authority.* / capability.* / context.*`) — field นอก dictionary (เช่น `confidence`) ถูกปฏิเสธ
2. **UNKNOWN ไม่เท่ากับผ่าน** (3-valued logic): requirement ผ่านเฉพาะ TRUE; prohibition ยิงเฉพาะ TRUE
3. **ผล policy 6 แบบ** ELIGIBLE / NEEDS_EVIDENCE / NEEDS_TARGET / NEEDS_AUTHORIZATION / UNSUPPORTED / PROHIBITED และเก็บ reasons ทั้งหมด; มีเฉพาะ ELIGIBLE ที่กลายเป็น step ลงมือ
4. **แยก classification ออกจาก authorization**: `classification_evidence` เลือก subtype เท่านั้น; ทุก action ต้องผ่าน ACTION_GATE ของตัวเอง
5. **AUTHORIZED/benign** (`authorization_gate`) → PROHIBITED (approved task change, approved RMM, approved automation)
6. **Placeholder ที่เติมไม่ได้ → step ถูกตัดทิ้ง** (ไม่แสดง `{{…}}`) และรายงาน target ที่ขาด; ไม่มี process identity → ไม่มีคำสั่ง terminate; ไม่มี file identity → ไม่มี quarantine
7. **ลำดับ**: `depends_on` + containment_stage (STOP_ACTIVE < CLOSE_PATH < IDENTITY_EXPOSURE < CLEANUP_OBJECT), tie-break ด้วย action_id; ไม่มีลำดับตายตัวต่อ incident
8. **ทุก prohibition ใน reference ถูก map** (`covers[]`) และทุก rule ถูก self-test ว่ายิงจริง (265 tests) และทุก subtype ถูก smoke-test 2 ทาง (100 tests); mutation test 8 แบบถูกจับได้ (drop coverage, dangling ref, field นอก dictionary, cycle, placeholder ผิด, "ดำเนินการตาม RB-", ลบ authorization_gate, flip prohibition)

## ORGANIZATION_CONTEXT (input C) — PARTIAL

รู้จากรีโป: role SOC/IR_TEAM, IR_TEAM ตัดสินใจและ execute เอง (n8n แจ้งเตือนเท่านั้น), Wazuh เป็น sensor, asset criticality catalog.
**MISSING** (ไม่ได้สมมติ): firewall/WAF/EDR/IdP/mail gateway/DNS/cloud IAM/secret manager/DB platform, approved-management/IR access list, approved automation/RMM inventory, emergency IR authority, DBA/asset owner/change approval, tenant IDs.
ผล: ทุก runbook เป็น **platform-neutral** (`TOOL_MAPPING_REQUIRED`) ไม่มีชื่อเมนู/คำสั่ง/API ที่แต่งขึ้น; capability ที่ไม่ทราบ → ELIGIBLE พร้อม flag (หรือ UNSUPPORTED ใน strict mode). ดู [contracts/organization-context.yaml](contracts/organization-context.yaml)

## ตั้งค่า runtime (backend)
| Env | ความหมาย |
|---|---|
| `SUBTYPE_KNOWLEDGE_MODE` | `off` / `shadow` (ค่าเริ่มต้น) / `enforce` |
| `SUBTYPE_ALLOW_UNREVIEWED` | `true` = อนุญาต enforce ทั้งที่ review_status ยังไม่เป็น IR_REVIEWED (ต้องเป็นการตัดสินใจขององค์กรเท่านั้น) |
| `SUBTYPE_STRICT_CAPABILITIES` | `true` = capability ที่ยังเป็น UNKNOWN ให้ผลเป็น UNSUPPORTED แทน TOOL_MAPPING_REQUIRED |
| `SUBTYPE_LLM_NARRATION` | `true` = ให้ LLM เรียบเรียงเฉพาะ summary (ถูกตรวจแล้วจึงใช้; เพิ่ม action/target/scope ไม่ได้) |
| `VIGIX_ORG_CONTEXT_FILE` | path ของ organization context (ค่าเริ่มต้น `organization/organization-context.yaml` — ช่องที่ไม่รู้ต้องเป็น `null`) |
| `VIGIX_SUBTYPE_KNOWLEDGE_DIR` | path ของ knowledge นี้ |

ก่อนใช้ `enforce`: apply migration `recommendation_audits`, รัน `npm run subtype:seed` (catalog Action/Runbook), กรอก organization context, ให้ IR รีวิว (`review-register.yaml`).

## ฟิลด์ของ step ที่ใช้เรียบเรียงคำแนะนำ (runbook `ordered_steps`)
| ฟิลด์ | ความหมาย |
|---|---|
| `title` | หัวข้อภาษาไทยของขั้นตอน (บังคับสำหรับ step ที่แสดงเป็นข้อ) |
| `instruction` | ข้อความสั่งงาน; step แบบ `fold: true` ถูกแสดงเป็น "ก่อนลงมือ" ของ step ถัดไป (เป็นคำสั่งให้ตรวจ/บันทึก ไม่ใช่คำยืนยันว่ามีอยู่แล้ว) |
| `method` | วิธีลงมือแบบ platform-neutral เขียนจากข้อมูลที่ step/runbook มีเท่านั้น (ตัวระบุจากหลักฐาน + ชนิด control + guard ขอบเขต + สถานะที่ต้องตรวจก่อน/หลัง) ไม่มีชื่อเมนู/API/คำสั่ง; แสดงเป็น "วิธีลงมือ:" |
| `method_basis` | แหล่งของ method: `EXISTING` / `NEUTRAL_DERIVED` (พร้อมใช้) หรือ `ORG_INPUT_REQUIRED` / `IR_REVIEW_REQUIRED` (ไม่มี method และ**ไม่เป็นคำสั่งปฏิบัติ** จนกว่าข้อมูลองค์กร/IR จะมี; ต้องระบุ `method_requires`) บังคับกับ step ปฏิบัติการเท่านั้น (folded pre-check, verify-only, include_runbook ใช้ข้อกำหนดตามชนิด) |
| `requires_org: [approved_access]` | method ต้องคงช่องทาง IR/management ไว้ จึงพร้อมเมื่อองค์กรกรอก `approved_access` แล้วเท่านั้น |
| `needs_prior: [Sx]` | ขั้นก่อนหน้าที่ต้องพร้อมก่อน (เช่น ตัด connection หลังตั้ง deny) ถ้าไม่พร้อม ขั้นนี้ไม่พร้อมด้วย |
| `requires_confirmed_tool: true` | ขั้นตอนจะแสดงว่าพร้อมลงมือก็ต่อเมื่อ capability ใน `condition` ถูกระบุว่ารองรับจริง; ถ้า unknown/false จะย้ายไป "ข้อมูลที่ต้องตรวจเพิ่ม" (ใช้กับการตัด session/connection; validator บังคับให้มี `method`) |
| `impact` / `verify` / `rollback` | แสดงเป็น *ผลกระทบ* / *ตรวจผล* / ย้อนกลับ เฉพาะที่มีข้อมูลรองรับ |

องค์กรกรอกผู้ติดต่อของผู้มีอำนาจได้ที่ `authority_contacts` ใน `organization/organization-context.yaml` (แสดงเฉพาะที่กรอก; ไม่เดาชื่อ)

## Eligibility ของ action ≠ ความพร้อมของ step
Policy ตัดสินว่า action เปิดได้หรือไม่ (6 ผล) แต่ละ step ยังต้อง "พร้อม" (มี method, ข้อมูลองค์กรครบ, tool ที่จำเป็นยืนยันแล้ว, ขั้นก่อนหน้าพร้อม) จึงถูกส่งเป็นคำสั่งใน Ticket ได้ step ที่ไม่พร้อมไปอยู่ใน "ข้อมูลที่ต้องตรวจเพิ่ม" และบันทึกเหตุผลใน audit (`stepReadiness`, `omittedSteps`) การประเมินคุณภาพทำได้ด้วย [validation/eval](validation/eval/README.md)
