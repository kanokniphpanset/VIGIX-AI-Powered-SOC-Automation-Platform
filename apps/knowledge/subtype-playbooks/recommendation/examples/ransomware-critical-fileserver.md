# ตัวอย่าง ransomware-critical-fileserver — Ransomware on a CRITICAL file server: alternative (non-isolating) containment variant, damage not delayed

> สร้างจาก validation case `VC-34` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.

---

**คำแนะนำเพื่อยับยั้ง Incident**

1. **ตัด write sessions SMB-3391, SMB-3392 ของบัญชี svc_backup2 ต่อ share Finance บน FILESRV-02**
   ตรวจก่อนลงมือ: มีเหตุผลสำหรับมาตรการเร่งด่วนตาม IR authority (ดูอัตรา file modification ล่าสุด)
   *ผลกระทบ: ผู้ใช้ที่ใช้ share นี้เขียนไฟล์ไม่ได้ชั่วคราว*
   *ตรวจผล: ไม่มี write ใหม่จาก session ที่ตัด*

2. **ยุติ process process_guid=PG-AA5510 บน FILESRV-02 (ระบุด้วย process identity ไม่ใช้ PID อย่างเดียว)**
   *ตรวจผล: process identity ไม่อยู่ใน process list และไม่มี file modification ใหม่*

3. **จำกัดเฉพาะการเขียนไป share ที่ถูกโจมตีและ outbound/east-west ที่ไม่จำเป็น**
   เนื่องจาก FILESRV-02 เป็น workload สำคัญ — โดยคง dependency ที่ระบุไว้ แทนการ isolate ทั้งเครื่อง และแจ้ง asset owner
   *ตรวจผล: file modification บน share หยุด และ dependency ที่จำเป็นยังใช้งานได้*

4. **เก็บ snapshot ของ memory/process list ของ FILESRV-02 ก่อนปิดหรือ reboot เครื่อง (ทำหลังหยุด damage แล้วเท่านั้น)**
   *ตรวจผล: snapshot ถูกเก็บใน evidence store*

ข้อมูลที่ต้องตรวจเพิ่ม: ยืนยันว่ามี process/execution/event ที่โหลดหรือรันไฟล์นี้จริง และพฤติกรรมนั้นเป็นอันตราย ไม่ใช่เพียงพบไฟล์ (เพื่อเปิดมาตรการ: Quarantine identified file/object)

---

**สิ่งที่ตรวจในเคสนี้:** Active damage ใช้ขั้นเร่งด่วน (ตัด write sessions → ยุติ process) ไม่ถูกถ่วงด้วยการเก็บหลักฐาน; critical workload ใช้ variant ไม่ isolate ทั้งเครื่อง
