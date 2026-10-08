# ตัวอย่าง scheduled-task-hijack-no-process-identity — Scheduled task hijack — NO process identity: trigger disabled, but no terminate command is rendered (acceptance)

> สร้างจาก validation case `VC-20` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.

---

**คำแนะนำเพื่อยับยั้ง Incident**

1. **Disable \Maintenance\SyncReport (scheduled_task) บน WKS-FIN-07**
   เฉพาะรายการนี้ (ไม่ลบ ไม่ปิด scheduler/service manager ทั้งเครื่อง) — ตรวจก่อนลงมือ: ยืนยัน artifact ที่ต้อง disable เป็นรายการเดียว (เทียบ evidence ref และ change record) / มี snapshot สำหรับ forensic/rollback (snapshot เก็บใน incident record)
   *ผลกระทบ: งานตามรอบของ artifact นี้ไม่ทำงาน*
   *ตรวจผล: สถานะ artifact เป็น disabled และรอบ trigger ถัดไปไม่ทำงาน*

2. **หยุด instance ของ \Maintenance\SyncReport ที่กำลังรันอยู่ (การ disable ไม่ได้หยุด instance ที่ทำงานแล้ว)**
   *ตรวจผล: สถานะ artifact ไม่เป็น running*

ข้อมูลที่ต้องตรวจเพิ่ม: ยืนยันว่ามี process/execution/event ที่โหลดหรือรันไฟล์นี้จริง และพฤติกรรมนั้นเป็นอันตราย ไม่ใช่เพียงพบไฟล์ (เพื่อเปิดมาตรการ: Quarantine identified file/object); process ของ payload (host + process identity): ต้องระบุ host_id, process_identity; child process ที่มี lineage กับ payload: ต้องระบุ host_id, parent_process_identity, child_process_identities

**ตรวจผลรวมหลังดำเนินการ**
- ตรวจหลังรอบ trigger ถัดไปว่า \Maintenance\SyncReport ไม่ relaunch payload และไม่มี process ใหม่จาก artifact นี้

---

**สิ่งที่ตรวจในเคสนี้:** ไม่มี process identity → ไม่แสดงคำสั่งยุติ process; แสดง disable task + หยุด instance และระบุข้อมูลที่ต้องตรวจเพิ่ม (process identity, file identity)
