# ตัวอย่าง brute-force-confirmed-success — Brute force with CONFIRMED unauthorized success: source restrict, then session revoke, then credential containment

> สร้างจาก validation case `VC-31` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.

---

**คำแนะนำเพื่อยับยั้ง Incident**

1. **ตั้ง deny หรือ rate-limit เฉพาะ 198.51.100.23 → SSH (22/TCP) บน SRV-VPN-01 ที่ perimeter firewall FW-EDGE-1 (ไม่ใช่ global block; คงการเข้าถึงของ approved management)**
   ตรวจก่อนลงมือ: source role เป็น attacker_source และไม่ชนกับ approved access (เทียบกับ event และรายการ approved management access) / มี snapshot สำหรับ rollback (snapshot เก็บใน incident record)
   *ผลกระทบ: จำกัดเฉพาะบริการนี้ ผู้ใช้อื่นไม่ถูกตัด*
   *ตรวจผล: เห็น attempts จาก source ถูก deny/limit ที่จุดบังคับ และ management access ยังใช้ได้*

2. **ตัด sessions/connections ที่ค้างของ 198.51.100.23 บน SSH (22/TCP)**
   หาก control รองรับ
   *ตรวจผล: connection table ไม่แสดง source*

3. **Revoke session/token family session_family=SF-9921 ที่ corp-idp สำหรับ VPN portal**
   ตรวจก่อนลงมือ: ได้ชุด session ที่ถูกต้อง (เทียบกับ evidence ref)
   *ผลกระทบ: ผู้ใช้ต้อง sign-in ใหม่*
   *ตรวจผล: request ที่ใช้ session id นั้นถูกปฏิเสธ (401/forced re-auth) ตาม log*

4. **จำกัดการ sign-in ของ somchai.k (restrict หรือ disable ตาม identity scope ที่อนุมัติ)**
   เพื่อไม่ให้ผู้โจมตีกลับเข้ามา — ตรวจก่อนลงมือ: ยืนยัน identity scope และไม่ชนบัญชีที่ต้องรักษา (เทียบ account กับ evidence ref และรายการ approved/break-glass accounts)
   *ผลกระทบ: เจ้าของบัญชีใช้งานไม่ได้ชั่วคราว*
   *ตรวจผล: ทดสอบด้วย sign-in log: attempt ถูกปฏิเสธ*

5. **Reset credential ของ somchai.k ผ่านช่องทางที่ยืนยันตัวตนเจ้าของ (ไม่ส่ง password ทางบัญชีที่ถูกยึด)**
   แล้วค่อยปลดการจำกัดการ sign-in ที่ตั้งไว้
   *ตรวจผล: authentication ด้วย credential เดิมถูกปฏิเสธ*

**ตรวจผลรวมหลังดำเนินการ**
- ตรวจ log ว่าไม่มี request ใหม่ที่ใช้ session id เดิมใน VPN portal
- ตรวจ sign-in log ของ somchai.k หลังดำเนินการ: ไม่มี authentication สำเร็จจาก source/อุปกรณ์ที่ไม่ได้รับอนุญาต และไม่มี session active ที่ไม่รู้จัก

---

**สิ่งที่ตรวจในเคสนี้:** failed login ไม่เปิด reset แต่เมื่อมี unauthorized success จึงเพิ่ม revoke session ก่อน แล้วค่อยจัดการ credential; session อ้างด้วย ID ไม่แสดง token
