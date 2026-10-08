# Playbook และ policy สำหรับหยุดการแพร่กระจายหลัง re-hunt

เป้าหมาย: ใช้ Playbook ตาม attack type เพื่อสร้าง recommendation ที่หยุดกิจกรรมบนจุดที่พบเพิ่มจาก re-hunt โดยอ้างอิงหลักฐานของ investigation รอบใหม่ และส่งให้ IR ตัดสินใจก่อนลงมือ

## เส้นทางการทำงาน

1. SOC ยืนยัน attack type หรือระบบเลือกจาก MITRE ที่บันทึกไว้ แล้วเลือก Playbook ฉบับเผยแพร่
2. Recommendation รอบแรกใช้กลยุทธ์ของ Playbook, procedure ตาม attack และ runbook ของแต่ละ action
3. IR APPROVE/REJECT และบันทึกผลการทำ response
4. Re-hunt ตรวจ host และ IOC หลัง containment พร้อมเทียบ host ที่พบกับขอบเขตเดิม
5. `RULE-V02` เปิด investigation ใหม่เมื่อพบการแพร่กระจายและร้องขอ recommendation ใหม่; ขีดจำกัดจำนวนรอบและการ escalation เดิมยังทำงาน
6. Policy `SPREAD-<INCIDENT-TYPE>` ให้กลยุทธ์สำหรับ attack นั้นเมื่อ `spreadDetected=true` และ `verificationResult=NOT_RESOLVED`
7. Recommendation ใช้ evidence/IOC ของรอบใหม่ ต้องครอบคลุม host ใหม่ที่มี action รองรับ แล้วส่งให้ IR ตัดสินใจอีกครั้ง

## วิธีรับมือแต่ละ attack

ทุก action ในตารางเป็นตัวเลือกที่ต้องผ่านหลักฐานและ policy ก่อน ไม่ใช่รายการที่ต้อง execute ทั้งหมด

| Playbook | Policy เมื่อแพร่กระจาย | วิธีหยุด/ยับยั้งตามหลักฐาน |
|---|---|---|
| PB-SSH-BRUTEFORCE | SPREAD-SSH-BRUTE-FORCE | Block/rate-limit source ที่โจมตีบริการ SSH เพิ่ม; revoke session, disable account หรือ reset credential เมื่อยืนยันการเข้าถึงที่ไม่ได้รับอนุญาต |
| PB-MALWARE | SPREAD-MALWARE | Isolate endpoint ที่ติดเพิ่ม, kill process, quarantine payload; block hash และช่องทาง delivery/C2 ที่บันทึกไว้ |
| PB-SQL-INJECTION | SPREAD-SQL-INJECTION | Block/rate-limit source ที่ web service ที่ได้รับผลเพิ่ม; revoke session/reset credential เมื่อยืนยัน identity compromise |
| PB-ACCOUNT-COMPROMISE | SPREAD-ACCOUNT-COMPROMISE | Revoke session, disable/reset identity ที่ถูกใช้ผิด; block source และ isolate host เมื่อยืนยัน malicious use |
| PB-POWERSHELL | SPREAD-POWERSHELL | Isolate endpoint ที่พบ malicious execution เพิ่ม; kill process, quarantine script/payload, block delivery IOC; disable identity เมื่อยืนยัน abuse |
| PB-PHISHING | SPREAD-PHISHING | Quarantine email จากผู้รับที่พบเพิ่ม, block sender/URL/domain/hash; revoke/reset เฉพาะผู้ที่มีหลักฐาน interaction/credential theft; isolate เมื่อยืนยัน compromise |
| PB-C2 | SPREAD-COMMAND-AND-CONTROL | Block destination IP/domain/URL ของ C2 และ isolate endpoint ที่ beacon เพิ่ม; block hash เมื่อมีข้อมูล payload |
| PB-DATA-EXFIL | SPREAD-DATA-EXFILTRATION | Block destination ของ transfer, isolate source endpoint ที่พบเพิ่ม; revoke/disable identity ที่เกี่ยวข้องตามหลักฐาน |
| PB-PRIV-ESC | SPREAD-PRIVILEGE-ESCALATION | Remove unauthorized privilege, revoke/disable identity ที่ abuse, kill elevated process และ isolate endpoint ตามหลักฐาน |
| PB-SUSPICIOUS-PROCESS | SPREAD-SUSPICIOUS-PROCESS-EXECUTION | Kill process ที่ระบุตัวได้, quarantine payload, block hash; isolate endpoint เมื่อยืนยัน compromise |

## เงื่อนไขที่ระบบบังคับ

- อ่าน re-hunt ของ investigation ก่อนหน้าทันทีและ tenant เดียวกัน ผ่านเลขรอบที่ backend บันทึกใน verification; ข้อมูลเก่าที่ไม่มีเลขรอบไม่ถูกเดาว่าเป็นรอบปัจจุบัน
- ใช้ `WAZUH_INDEXER` หรือ `MOCK_REHUNT` ที่ระบุชัดเจน; manual verification ไม่เปิด spread response อัตโนมัติ และ mock ไม่ถูกแสดงว่าเป็นผลจาก SIEM จริง
- Host ใหม่ = host ที่พบใน re-hunt และไม่อยู่ในขอบเขตก่อน response; ไม่มี baseline จะไม่เดาว่า host ใดเป็น host ใหม่
- Allowed actions เป็น intersection ของ published Playbook, SOC guidance และ spread policy; policy ไม่เพิ่ม action นอก Playbook
- สำหรับ host ใหม่ที่มี eligible action ต้องเสนอ action บน host นั้น หรือบน IOC ที่เชื่อมกับ evidence ของ host นั้น หากใช้ IOC ร่วม คำสั่งต้องระบุ host ใหม่ที่ control นี้ป้องกัน
- Host ที่ยังไม่มี action ผ่านหลักฐานถูกระบุเป็น `uncoveredHosts` และ prompt สั่งให้ตรวจเพิ่ม; ระบบไม่สร้าง target, account, process หรือ payload ขึ้นเอง การมี recommendation ไม่ได้แปลว่าครอบคลุมทุก host แล้ว
- IOC เดิมอาจถูกเสนออีกในขอบเขต host ใหม่ที่ re-hunt ยืนยัน แต่ยังห้ามเสนอคู่ action/target เดิมซ้ำภายใน investigation รอบเดียวกัน
- ผลค้นหาแบบ truncated ไม่พิสูจน์ขอบเขตทั้งหมดหรือ containment สำเร็จ; ต้องตรวจต่อและ re-hunt หลัง response
- Snapshot เก็บ verification id, ขอบเขต host, matched spread policies และคำแนะนำที่ใช้ในรอบนั้น เพื่อย้อนตรวจได้

## ตัวอย่าง

Malware เริ่มที่ `HOST-A` และ IR isolate แล้ว แต่ re-hunt พบ IOC เดียวกันที่ `HOST-B` และ `HOST-C`: เปิด investigation ใหม่และเก็บ events/IOC ที่พบในรอบใหม่ จากนั้น `SPREAD-MALWARE` แนะนำ containment ที่ `HOST-B`/`HOST-C` ตามหลักฐาน พร้อม block ช่องทางหรือ hash ที่มีข้อมูลจริง คำแนะนำที่ดูแลเฉพาะ `HOST-A` จะไม่ผ่าน validator หากมี eligible action สำหรับ host ใหม่ หลัง IR ตัดสินใจและทำ response ต้อง re-hunt ทั้งขอบเขตเดิมและใหม่อีกครั้ง

## การติดตั้งข้อมูล

จาก repository root ดูรายการที่จะเพิ่ม:

```bash
npm run policies:spread:seed --workspace=apps/backend
```

เพิ่มเฉพาะ policy ที่ยังไม่มี โดยเก็บ policy เดิมไว้และเขียน audit:

```bash
npm run policies:spread:seed --workspace=apps/backend -- --apply
```

หากมีหลาย tenant ให้ส่ง tenant ID ต่อท้าย command ไม่ต้องเปลี่ยน schema ฐานข้อมูล กลไกใหม่ใช้กับ re-hunt ที่เกิดหลัง backend โหลดโค้ดนี้แล้ว ไม่แก้ผล verification เก่า

Full seed รวม spread policies ด้วย แต่ยังมีพฤติกรรมเขียน rules ของ policy อื่นใหม่ทั้งหมดตาม seed จึงใช้ command เฉพาะด้านบนสำหรับฐานข้อมูลที่ตั้งค่าไว้แล้ว

Playbook seed สำหรับข้อมูลใหม่อ้าง `spreadResponsePolicyCode` ใน triggerConditions แต่คงสร้างเป็น DRAFT และรักษากระบวนการ submit → approve → publish โดยคน Playbook ที่มีอยู่ยังผูก policy ผ่าน incidentType ได้โดยไม่เขียนทับ published revision

แหล่งข้อมูลหลัก: `apps/backend/src/domain/knowledge/spreadResponse.ts`, `prisma/seeds/policy.seed.ts`, `prisma/seeds/playbook.seed.ts` และ procedure/runbook เดิมใน `apps/knowledge`
