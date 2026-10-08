# ตัวอย่าง scheduled-task-hijack-full — Scheduled-task hijack (acceptance §7.2) — all evidence, targets and file identity present: trigger -> instance/payload -> channel -> quarantine

> สร้างจาก validation case `VC-06` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.

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

4. **ยุติ child process process_guid=PG-7F3A22 ของ payload**
   เฉพาะรายการที่มี lineage เชื่อมโยงกับ process_guid=PG-7F3A21 (ไม่ยุติ child ที่ไม่มีหลักฐาน)
   *ตรวจผล: children ไม่อยู่ใน process list*

5. **ตัด update-cdn.example-bad.test/api/v2/poll ที่ระดับ URL path**
   ด้วย egress/web/DNS control (หากเป็น shared cloud/CDN ให้ใช้ rule ระดับ path/domain/SNI ที่รองรับ ไม่ block ทั้ง provider) — ตรวจก่อนลงมือ: destination ถูกต้องและไม่ชนปลายทางที่อนุมัติ (เทียบกับ evidence ref และรายการ approved destinations) / มี snapshot (snapshot ใน incident record)
   *ผลกระทบ: ผู้ใช้อื่นที่ใช้ปลายทางเดียวกันอาจเข้าไม่ได้หาก block ระดับกว้าง*
   *ตรวจผล: connection attempt ถูกปฏิเสธตาม log*

6. **ตัด connections เดิมของ WKS-FIN-07 → 203.0.113.45 (TCP/443)**
   เพราะ deny rule ไม่ตัด connection ที่ established แล้ว
   *ตรวจผล: connection table ไม่แสดง flow*

7. **Quarantine C:\Users\Public\upd.exe บน WKS-FIN-07**
   ด้วย quarantine function ของเครื่องมือ endpoint (ย้ายเข้าที่เก็บ quarantine ไม่ลบ) — ตรวจก่อนลงมือ: identity ของไฟล์ตรงกับ evidence (locator/hash ตรงกับ evidence ref) / มีสำเนา metadata สำหรับ audit/restore (มี metadata ใน incident record)
   *ตรวจผล: ไม่พบไฟล์ที่ path เดิม และมี record ใน quarantine store*

**ตรวจผลรวมหลังดำเนินการ**
- ตรวจหลังรอบ trigger ถัดไปว่า \Maintenance\SyncReport ไม่ relaunch payload และไม่มี process ใหม่จาก artifact นี้
- ตรวจว่าไม่มี connection ใหม่ไป update-cdn.example-bad.test/api/v2/poll และ process ไม่กลับมา

---

**สิ่งที่ตรวจในเคสนี้:** ลำดับ: หยุด Task → หยุด running instance → ยุติ payload+children ด้วย process identity → จำกัด outbound ที่ผูกกับ payload (granular) + ตัด connection ที่ค้าง → quarantine ไฟล์ที่มี identity; Disable Task ไม่ถือว่าหยุด instance; ไม่ลบ task ทั้งชุด
