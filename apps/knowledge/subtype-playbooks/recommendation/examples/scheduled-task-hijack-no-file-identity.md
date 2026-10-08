# ตัวอย่าง scheduled-task-hijack-no-file-identity — Scheduled task hijack — payload linked but NO file identity: no quarantine (acceptance)

> สร้างจาก validation case `VC-21` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.

---

**คำแนะนำเพื่อยับยั้ง Incident**

1. **Disable \Maintenance\SyncReport (scheduled_task) บน WKS-FIN-07**
   เฉพาะรายการนี้ (ไม่ลบ ไม่ปิด scheduler/service manager ทั้งเครื่อง) — ตรวจก่อนลงมือ: ยืนยัน artifact ที่ต้อง disable เป็นรายการเดียว (เทียบ evidence ref และ change record) / มี snapshot สำหรับ forensic/rollback (snapshot เก็บใน incident record)
   *ผลกระทบ: งานตามรอบของ artifact นี้ไม่ทำงาน*
   *ตรวจผล: สถานะ artifact เป็น disabled และรอบ trigger ถัดไปไม่ทำงาน*

2. **หยุด instance ของ \Maintenance\SyncReport ที่กำลังรันอยู่ (การ disable ไม่ได้หยุด instance ที่ทำงานแล้ว)**
   *ตรวจผล: สถานะ artifact ไม่เป็น running*

3. **ยุติ payload process process_guid=PG-7F3A21 บน WKS-FIN-07**
   เฉพาะที่ยังรันอยู่ (ระบุด้วย process identity ไม่ใช้ PID อย่างเดียว; หากการหยุด instance ข้างต้นยุติ payload ไปแล้วให้ตรวจและยุติเฉพาะที่ยังเหลือ)
   *ตรวจผล: process identity ไม่อยู่ใน process list*

ข้อมูลที่ต้องตรวจเพิ่ม: ไฟล์/object ที่จะ quarantine (host + path/object id): ต้องระบุ host_id, object_locator; child process ที่มี lineage กับ payload: ต้องระบุ host_id, parent_process_identity, child_process_identities

**ตรวจผลรวมหลังดำเนินการ**
- ตรวจหลังรอบ trigger ถัดไปว่า \Maintenance\SyncReport ไม่ relaunch payload และไม่มี process ใหม่จาก artifact นี้

---

**สิ่งที่ตรวจในเคสนี้:** ไม่มี file identity → ไม่มี quarantine; ไม่มีหลักฐาน outbound → ไม่มี network deny
