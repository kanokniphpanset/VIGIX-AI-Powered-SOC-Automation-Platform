# ตัวอย่าง scheduled-task-approved-change — Approved scheduled-task change — evidence AUTHORIZED: no malicious containment (acceptance)

> สร้างจาก validation case `VC-26` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.

---

**คำแนะนำเพื่อยับยั้ง Incident**

ยังไม่มีมาตรการ containment ที่ผ่านเงื่อนไขหลักฐานและ target จึงให้ตรวจสอบสิ่งต่อไปนี้ก่อน:

1. หลักฐานระบุว่ากิจกรรมที่ตรวจพบได้รับอนุมัติ (approved) จึงไม่เปิดมาตรการ containment — ให้ยืนยันกับ change record/เจ้าของงานก่อน หากพบว่าไม่ได้รับอนุมัติจริงจึงประเมินใหม่

---

**สิ่งที่ตรวจในเคสนี้:** approved task change (AUTHORIZED) → ไม่เปิด malicious containment; แสดงเฉพาะขั้นตอนตรวจสอบ
