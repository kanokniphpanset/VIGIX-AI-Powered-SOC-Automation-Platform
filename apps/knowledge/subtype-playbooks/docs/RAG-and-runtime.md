# §9 RAG: การจัด knowledge, retrieval flow และสิ่งที่ต้องเพิ่มใน runtime

รายละเอียดเชิงข้อมูล (metadata fields, chunking rules, flow 8 ขั้น, hard rule) อยู่ใน [../rag/retrieval-metadata.yaml](../rag/retrieval-metadata.yaml); ตัวอย่างจริง: `../rag/chunks.jsonl` (213 chunks).

## หลักการ
1. **Retrieval เลือก "ข้อความที่จะแสดง" — ไม่ใช่ "สิ่งที่อนุญาต"** Policy evaluator ตัดสิน action จาก structured facts; similarity/confidence ไม่ใช่ input (GL-4)
2. **Action chunk ต้องพก gate ไปด้วยเสมอ**: required evidence, targets, prohibitions, authority, capability, criticality, dependencies (จากทุก scenario ที่สั่ง action นั้น) — `checkChunkInvariant` ล้ม build ถ้าขาด
3. **Filter ด้วย metadata ก่อน** (`status=ACTIVE`, `subtype_id`, `action_id`, `tools`) แล้วจึงให้ similarity เรียงเฉพาะภายใน; subtype ต้องผ่าน `classification_evidence` TRUE เสมอ
4. **Global rule chunks** (prohibitions, output constraints, branch gates) ถูกแนบทุกครั้งที่ retrieve action
5. ภาษา: chunk เป็นไทย (id/field เป็นอังกฤษ); `language` อยู่ใน metadata สำหรับการแยกดัชนีภายหลัง

## ส่วนไหนเป็น knowledge update / ส่วนไหนเป็น runtime ของ RAG agent
| ส่วน | สถานะ | ที่อยู่ |
|---|---|---|
| Playbook / Policy / Runbook / Evidence / Target / Dictionary / Output contract | **knowledge — เสร็จ** | `families/`, `contracts/`, `recommendation/` |
| Evaluator, planner, step selector, composer (semantics อ้างอิง) | **ต้นแบบ JS — ตรวจแล้ว** แต่ยังไม่ใช่ production | `tools/lib.mjs`, `tools/render.mjs` |
| Incident fact builder / evidence extractor | runtime — **ทำแล้ว (ทดสอบด้วย recorded alert)** | ต้องแปลง Wazuh alert + enrichment → `evidence_record`; ควรต่อยอด Evidence Contract v2 (`domain/investigation/evidenceV2/`) แทนสร้างใหม่ (GAP-13) |
| Target resolver (+ role detection + `scope.*` flags) | runtime — **ทำแล้ว** (`domain/subtype/targets.ts`) | เกี่ยวกับ defect "role หายก่อนถึง LLM" ที่มีอยู่แล้ว |
| Policy evaluator ใน backend (TS) | runtime — **ทำแล้ว** (`domain/subtype/policyEngine.ts`) | port `evaluateAction/evaluateBranchGate` ไว้ข้าง `application/policy/` |
| Dependency orderer + step selector | runtime — **ทำแล้ว** (`planner.ts`, `steps.ts`, `composer.ts`) | port `planIncident/selectSteps` ไว้ข้าง `application/recommendation/` |
| Output validator + audit record writer | runtime — **ทำแล้ว** (`outputValidator.ts`, ตาราง `RecommendationAudit`; ตรวจครบทุกข้อของ OUTPUT_CONSTRAINT หรือไม่ ยังไม่ได้ทวนทีละข้อ) | ต่อ `RecommendationValidator` เดิม |
| Loader/Seed/Prisma | runtime — **ทำแล้วแต่ยังไม่ apply** (loader + `subtype:seed` + migration; revisioning แบบ playbook revision ยังไม่ทำ) | เทียบแนว playbook revision (`PublishPlaybookRevision`) |
| Vector index | runtime — **ยังไม่ทำ** | `scripts/indexRunbooksToQdrant.ts` + chunks.jsonl |

## ข้อควรระวังในการ port
- ใช้ **3-valued logic** (TRUE/FALSE/UNKNOWN) — อย่าแปลง UNKNOWN เป็น false แล้ว `not_equals` จะผ่านโดยบังเอิญ
- scenario `when` ห้ามเขียนเป็น "ไม่มี X" (UNKNOWN ≠ ไม่เกิด); ใช้ scenario ที่ทำงานเมื่อมีหลักฐานของสถานะนั้น (เจอใน PH-ATTACH ระหว่างพัฒนา)
- tie-break ลำดับด้วย `action_id` ไม่ใช่ลำดับไฟล์/retrieval
- dedupe ต้องไม่ทำให้ scope กว้างขึ้น; ตอนนี้ dedupe เฉพาะ "ยุติ process identity เดียวกัน" และ `skip_if_eligible`
