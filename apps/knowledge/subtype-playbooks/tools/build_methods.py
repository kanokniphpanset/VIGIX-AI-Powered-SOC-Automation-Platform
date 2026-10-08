"""Authoring source for step `method` (how to perform), `method_basis`, ordering (`needs_prior`) and organization requirements.

Rules (also enforced by tools/validate.mjs):
  * method_basis EXISTING            - the knowledge already carried a method (not touched here except ordering).
  * method_basis NEUTRAL_DERIVED     - platform-neutral method written ONLY from what the step/runbook already says: the evidenced identifiers,
                                       a generic control class, a guard on scope, the state to check before/after. No product, menu, command or API.
  * method_basis ORG_INPUT_REQUIRED  - the method depends on an organization-specific procedure/capability/data; no method is written;
                                       `method_requires` states exactly what the organization must supply. Never shown as a ready step.
  * method_basis IR_REVIEW_REQUIRED  - the choice is a policy decision for IR (level of restriction, change-controlled configuration);
                                       no method is written; `method_requires` states the decision needed. Never shown as a ready step.
  * requires_org: [approved_access]  - the method keeps IR/management access open; ready only when the organization listed that access.
Run from apps/knowledge/subtype-playbooks:  python tools/build_methods.py   (idempotent)
"""
import json, re, sys
NL = chr(10)

T1 = "ตรวจก่อนว่า process ตามตัวระบุ Process ข้างต้นยังรันอยู่บน {{process.host_id}} ถ้ายังรันจึงยุติเฉพาะ process นั้นด้วยตัวระบุ Process (ไม่ใช้ PID หรือชื่อ process อย่างเดียว) แล้วตรวจว่าไม่ถูกสร้างขึ้นใหม่ ถ้าไม่พบแล้วให้บันทึกผลการตรวจและไม่ยุติซ้ำ"
T2 = "ยุติเฉพาะ child process ตามตัวระบุ Process ลูกข้างต้นที่มีหลักฐาน lineage เชื่อมกับ process หลัก และตรวจก่อนว่ายังรันอยู่ ไม่ยุติ process อื่นที่ไม่มีหลักฐาน แล้วตรวจว่าไม่มี child ใหม่จาก process หลัก"
APPROVE = "ส่งคำขออนุมัติให้ asset owner ของ {{process.host_id}} พร้อมตัวระบุ Process ข้างต้น เหตุผล และผลกระทบต่อบริการ ห้ามยุติ process จนกว่าจะได้รับอนุมัติ ระหว่างรอให้คงการจำกัดที่ตั้งไว้แล้ว เมื่ออนุมัติแล้วจึงยุติตามขั้นยุติ process (ตรวจก่อนยุติ ไม่ยุติซ้ำ)"
def flow(s, d, p, o):
    return "ตั้ง deny เฉพาะ flow จาก {{%s}} ไป {{%s}} ({{%s}}/{{%s}}) ที่จุดบังคับเครือข่ายซึ่งเห็น flow นี้จริง (ไม่ใช่ rule กว้างทั้งปลายทางหรือพอร์ต) บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่า attempt ใหม่ถูกปฏิเสธ" % (s, d, p, o)
NF = ("network_flow.source_host_id", "network_flow.destination", "network_flow.protocol", "network_flow.port")
SESSIONS_REVOKE = "ใช้เครื่องมือจัดการ identity ของ {{account_identity.provider}} แสดงรายการ session และ refresh token ของ {{account_identity.account_id}} แล้ว revoke ทุกรายการ บันทึกรายการก่อน revoke เพื่อใช้เทียบ และทำก่อนการเปลี่ยน credential เสมอ (session ใหม่ของเจ้าของที่ยืนยันตัวตนแล้วหลังขั้นตอนนี้ไม่ต้อง revoke)"
def webrule(c, r, p, extra=""):
    return ("เพิ่ม targeted rule ที่ {{%s}} เฉพาะ {{%s}} / {{%s}} %sเริ่มในโหมด detect/log เทียบกับ traffic ปกติ แล้วเปลี่ยนเป็น block หลังผ่านการตรวจและได้รับอนุมัติตามที่องค์กรกำหนด ตรวจว่า log แสดงการจำกัดตาม pattern และอัตรา error ของ route ปกติไม่เพิ่ม") % (c, r, p, extra)
MSG_QUARANTINE = "ใน mail system ค้นหาข้อความด้วยเกณฑ์ของ {{message_set.message_ids_or_campaign_id}} ในขอบเขต {{message_set.mailbox_scope}} (รวมข้อความที่ถึง inbox แล้ว) แล้วย้ายเข้า quarantine โดยไม่ลบ เก็บรายการข้อความที่ย้ายไว้ใน incident record และค้นหาซ้ำด้วยเกณฑ์เดิมเพื่อตรวจว่าไม่เหลือข้อความ active"
HOST_ISOLATE = "แยก {{%s}} ออกจากเครือข่ายด้วยเครื่องมือ isolate ของ endpoint หรือเครือข่าย โดยคงเฉพาะช่องทาง IR/management ที่ระบุไว้ใน approved access ขององค์กร (ตรวจรายการก่อนลงมือ) ตรวจว่า connection ออกถูกตัด ยกเว้นช่องทางที่คงไว้"
PERSIST_DISABLE = "ใช้เครื่องมือจัดการ task/service ของเครื่อง {{persistence_artifact.host_id}} สั่ง disable เฉพาะ {{persistence_artifact.artifact_locator}} (ไม่ลบรายการ และไม่ปิด scheduler/service manager ทั้งเครื่อง) แล้วตรวจสถานะว่าเป็น disabled"
PERSIST_STOP = "ตรวจสถานะของ {{persistence_artifact.artifact_locator}} ก่อน ถ้ายังเป็น running ให้ใช้เครื่องมือจัดการ task/service หยุดเฉพาะ instance นั้น (การ disable ไม่หยุด instance ที่ทำงานอยู่แล้ว)"
EGRESS_PATH = "ตั้งการจำกัดที่ web proxy หรือ egress control ที่ตัดได้ตรงระดับ {{destination_endpoint.granularity}} สำหรับ {{destination_endpoint.destination}} (ถ้าเป็น shared cloud/CDN ห้าม block ทั้ง provider; ระดับ URL path ต้องใช้เครื่องมือที่เห็น URL path และ DNS control ตัดได้เพียงระดับ domain) บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่า request ถูกปฏิเสธ ถ้าตัดได้เพียงระดับกว้างกว่าให้แจ้ง IR ก่อนลงมือ"
ENTITLE = "ถอน entry {{entitlement_grant.entitlement_entry}} ของ {{entitlement_grant.principal_id}} เฉพาะรายการนี้ ด้วยเครื่องมือจัดการสิทธิ์ของระบบนั้น (ไม่ถอนสิทธิ์ผู้ดูแลทั้งระบบ) บันทึก entry เดิมก่อนถอน แล้วทดสอบว่า elevation ของ principal ถูกปฏิเสธและผู้ดูแลที่อนุมัติยังใช้งานได้"

N = "NEUTRAL_DERIVED"
def n(method, **kw): return dict(basis=N, method=method, **kw)
def org(req): return dict(basis="ORG_INPUT_REQUIRED", requires=req)
def ir(req): return dict(basis="IR_REVIEW_REQUIRED", requires=req)

M = {
 # --- ACCOUNT_COMPROMISE
 "RB-IDENTITY-CREDENTIAL-CONTAIN|S2": n(SESSIONS_REVOKE),
 "RB-IDENTITY-CREDENTIAL-CONTAIN|S3": ir("IR ต้องกำหนดระดับการจำกัดการ sign-in (restrict หรือ disable) ตาม identity scope ที่องค์กรอนุมัติ"),
 "RB-IDENTITY-CREDENTIAL-CONTAIN|S4": org("ขั้นตอนยืนยันตัวตนเจ้าของบัญชีและช่องทางส่ง credential ใหม่ที่องค์กรอนุมัติ"),
 "RB-SESSION-REVOKE|S2": n("ใช้เครื่องมือของ {{session.provider}} หรือแอปที่ออก session revoke session/token family {{session.session_ids_or_family}} ใน {{session.application_scope}} เฉพาะรายการที่ระบุ ไม่ revoke session ของบัญชีอื่น บันทึกรายการก่อน revoke แล้วตรวจจาก log ว่า request ที่ใช้ session นั้นถูกปฏิเสธหรือถูกบังคับ re-authentication"),
 "RB-SESSION-REVOKE|S3": org("วิธี access restriction หรือการบังคับ re-authentication ที่ identity provider/แอปนี้รองรับ เมื่อ revoke ทันทีไม่ได้"),
 "RB-SERVICE-SECRET-CONTAIN|S2": org("กลไกจำกัดการใช้ credential ตามชนิดของ platform และรายการ dependents ที่รู้จัก"),
 "RB-SERVICE-SECRET-CONTAIN|S3": n("สร้าง credential ใหม่ใน secret management ขององค์กรเป็นค่าใหม่ที่สุ่มสร้างเอง (ไม่คำนวณจากค่าเดิมและไม่นำค่าเดิมกลับมาใช้) บันทึกเฉพาะตัวระบุของ credential ใหม่ใน incident record ไม่บันทึกค่าลับ แล้วตรวจว่าตัวระบุใหม่ต่างจาก {{secret_credential.credential_id}}"),
 "RB-SERVICE-SECRET-CONTAIN|S4": n("ส่งมอบ credential ใหม่ให้ {{secret_credential.dependent_services}} ทีละ service ตามลำดับที่วางไว้ผ่านช่องทางของ secret management (ไม่ส่งค่าลับทางแชตหรืออีเมล) ตรวจ health check ของแต่ละ service ก่อนไป service ถัดไป หยุดและแจ้ง IR ถ้ามี service ที่ไม่ผ่าน", needs_prior=["S3"]),
 "RB-SERVICE-SECRET-CONTAIN|S5": n("เมื่อ dependents ทุกตัวใช้ credential ใหม่และ health check ผ่านแล้ว จึง revoke {{secret_credential.credential_id}} เดิมใน secret management แล้วตรวจจาก log ว่าการใช้ค่าเดิมถูกปฏิเสธ (ห้ามทดสอบด้วยค่าจริง)", needs_prior=["S4"]),
 "RB-MFA-RECOVERY-CONTAIN|S2": n("ใช้เครื่องมือจัดการ MFA/identity ของบัญชี {{mfa_factor.account_id}} แสดงรายการ factor และ recovery entry แล้วถอนเฉพาะ {{mfa_factor.factor_or_recovery_id}} (ไม่ถอน factor หรือ recovery path ที่เจ้าของใช้อย่างถูกต้อง) บันทึกรายการก่อนถอน แล้วตรวจรายการอีกครั้งว่าไม่มีรายการดังกล่าว"),
 # --- BRUTE_FORCE
 "RB-AUTH-CAMPAIGN-RESTRICT|S3": n("ตั้ง throttling หรือ risk challenge ที่ {{auth_campaign_scope.control_point}} ให้ครอบคลุม {{auth_campaign_scope.authentication_scope}} ของ {{auth_campaign_scope.application}} ทุก source ใน campaign (ไม่ block IP เดียวและไม่ lockout บัญชีทั้งกลุ่ม) เริ่มจากระดับ challenge/throttle ก่อน แล้วเทียบอัตรา failed attempts กับอัตรา login สำเร็จของผู้ใช้ปกติก่อนเพิ่มความเข้ม"),
 "RB-LOGIN-AUTOMATION-RESTRICT|S2": n("ตั้ง bot/risk control ที่ {{login_endpoint.control_point}} เฉพาะ {{login_endpoint.route}} สำหรับ client scope {{login_endpoint.client_scope}} เริ่มที่ challenge ก่อน block บันทึกค่าเดิมก่อนแก้ แล้วเทียบอัตรา login ของ client scope กับผู้ใช้ปกติ"),
 "RB-LOGIN-AUTOMATION-RESTRICT|S3": org("runbook ของแอปพลิเคชันสำหรับจำกัด session ที่เกิดจาก client scope นี้"),
 "RB-AUTH-SOURCE-RESTRICT|S4": dict(needs_prior=["S3"]),
 # --- CREDENTIAL MATERIAL
 "RB-CREDENTIAL-MATERIAL-CONTAIN|S1": n(T1),
 "RB-CREDENTIAL-MATERIAL-CONTAIN|S1c": n("จำกัด access ของ workload บน {{credential_material.host_id}} ต่อ {{credential_material.store_locator}} และ network egress ก่อน (ยังไม่ยุติ process) แล้วขออนุมัติ asset owner ก่อนยุติ process ตรวจว่า access ต่อที่เก็บถูกปฏิเสธและ dependency ที่ asset owner ระบุยังทำงาน"),
 "RB-CREDENTIAL-MATERIAL-CONTAIN|S2": n("ถอนสิทธิ์ของ {{credential_material.accessor_identity}} ต่อ {{credential_material.store_locator}} เฉพาะคู่ identity/ที่เก็บนี้ ด้วยเครื่องมือจัดการสิทธิ์ของที่เก็บนั้น บันทึกสิทธิ์เดิมก่อนถอน แล้วทดสอบด้วย access check ว่าถูกปฏิเสธ"),
 "RB-CREDENTIAL-MATERIAL-CONTAIN|S3": n("ทำรายการบัญชีที่ปรากฏใน material ({{credential_material.exposed_account_set}}) พร้อมอ้างอิงหลักฐานต่อรายการ คัดเฉพาะบัญชีที่มี unauthorized success หรือเสี่ยงตาม evidence แล้วส่งแต่ละบัญชีเข้าขั้นตอนจัดการ credential แยกกัน (ไม่ reset ทั้งชุด)"),
 # --- COMMAND_AND_CONTROL
 "RB-WEB-C2-CONTAIN|S4": dict(needs_prior=["S3"]),
 "RB-WEB-C2-CONTAIN|S5": n(T1),
 "RB-WEB-C2-CONTAIN|S5c": n(APPROVE),
 "RB-DNS-CHANNEL-CONTAIN|S3": n("ตั้งการบล็อกหรือ sinkhole ที่ DNS control เฉพาะ domain ใน {{dns_channel.domains}} (ไม่บล็อก zone ทั้งหมดและคง approved DNS) บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก DNS log ว่า query ไปยัง domain เหล่านั้นถูกปฏิเสธหรือ sinkhole"),
 "RB-DNS-CHANNEL-CONTAIN|S4": org("รายการ approved resolver ขององค์กรและจุดบังคับ DNS egress ของเครื่องต้นทาง"),
 "RB-DNS-CHANNEL-CONTAIN|S5": n(T1),
 "RB-DNS-CHANNEL-CONTAIN|S5c": n(APPROVE),
 "RB-CUSTOM-CHANNEL-CONTAIN|S3": n(flow(*NF)),
 "RB-CUSTOM-CHANNEL-CONTAIN|S4": dict(needs_prior=["S3"]),
 "RB-CUSTOM-CHANNEL-CONTAIN|S5": n(T1),
 "RB-CUSTOM-CHANNEL-CONTAIN|S5c": n(APPROVE),
 "RB-RMM-ACCESS-CONTAIN|S2": n("ใช้ console ของ {{rmm_registration.tool}} หา session {{rmm_registration.registration_or_session_id}} ของ {{rmm_registration.host_id}} แล้วสั่ง terminate เฉพาะ session นั้น (ไม่แตะ registration ที่ได้รับอนุมัติ) ตรวจจากรายการ active ว่า session หายไป"),
 "RB-RMM-ACCESS-CONTAIN|S3": n("ใน console ของ tenant {{rmm_registration.tenant_or_console}} เพิกถอนเฉพาะ registration หรือ access {{rmm_registration.registration_or_session_id}} (ไม่ลบ tenant หรือ registration อื่น) บันทึกสถานะก่อนถอน แล้วตรวจว่าสถานะเป็น revoked"),
 "RB-RMM-ACCESS-CONTAIN|S4": n("บน {{rmm_registration.host_id}} ปิด (disable) เฉพาะ service {{rmm_registration.service_name}} ของ tool ด้วยเครื่องมือจัดการ service ของเครื่อง หลังยืนยันว่าการถอน registration ที่ console ไม่เพียงพอ ตรวจว่า service เป็น disabled และไม่มี connection ไปยังเซิร์ฟเวอร์ของ tool"),
 # --- DATA_EXFILTRATION
 "RB-WEB-TRANSFER-CONTAIN|S2": n(EGRESS_PATH),
 "RB-WEB-TRANSFER-CONTAIN|S3": n("หยุด transfer session {{transfer_session.job_or_session_id}} ที่เครื่องมือหรือระบบที่รัน transfer นั้น แล้วยุติ process ที่ทำ upload โดยตรวจก่อนว่ายังรันอยู่บน {{process.host_id}} และยุติเฉพาะ process ตามตัวระบุ Process ข้างต้น (ไม่ใช้ PID อย่างเดียว) ตรวจว่าไม่มี outbound ต่อ ถ้าไม่พบแล้วให้บันทึกผลการตรวจและไม่ยุติซ้ำ"),
 "RB-WEB-TRANSFER-CONTAIN|S4": n("ใช้ egress control จำกัด outbound ของ {{host_workload.host_id}} ทั้งเครื่อง เว้นเฉพาะช่องทาง IR/management ที่ระบุไว้ใน approved access ขององค์กร (ตรวจรายการก่อนลงมือ) ทำต่อเมื่อการจำกัด destination และการยุติ session/process ไม่พอ ตรวจว่า outbound ถูกจำกัดและช่องทาง IR ยังใช้ได้", requires_org=["approved_access"]),
 "RB-WEB-TRANSFER-CONTAIN|S4c": n("จำกัดเฉพาะ outbound ไปยัง destination ที่ระบุจากหลักฐาน ไม่จำกัด outbound ทั้งเครื่อง แล้วแจ้ง asset owner ของ {{host_workload.host_id}} พร้อมผลกระทบ ตรวจว่าไม่มี outbound ไป destination เดิมและ dependency ที่ asset owner ระบุยังใช้ได้"),
 "RB-CLOUD-DATA-ACCESS-CONTAIN|S3": n("ใน console หรือเครื่องมือจัดการของ cloud account ที่เกี่ยวข้อง ยกเลิกเฉพาะ {{cloud_object_share.exposure_objects}} (link/ACL/grant) ของ {{cloud_object_share.object_id}} โดยไม่ลบ object บันทึก ACL เดิมก่อนแก้ แล้วตรวจจาก audit ว่าการเข้าถึงด้วย link/principal นั้นถูกปฏิเสธ"),
 "RB-CLOUD-DATA-ACCESS-CONTAIN|S4": n("จำกัดสิทธิ์ของ principal {{cloud_object_share.principal_id}} ต่อ {{cloud_object_share.object_id}} เฉพาะคู่นี้ ด้วย ACL/policy ระดับ object (ไม่แก้ policy ทั้ง account) บันทึกค่าเดิมก่อนแก้ แล้วตรวจจาก audit ว่าถูกปฏิเสธ"),
 "RB-CLOUD-DATA-ACCESS-CONTAIN|S5": n("ตรวจสถานะ copy job {{cloud_object_share.copy_job_id}} ก่อน ถ้ายังทำงานจึงสั่งหยุด (cancel) เฉพาะ job นี้ แล้วตรวจว่าเป็น stopped/cancelled และไม่มีการคัดลอกต่อ"),
 "RB-FILE-TRANSFER-CONTAIN|S2": n("ใช้เครื่องมือจัดการ transfer หยุด job/session {{transfer_session.job_or_session_id}} และ pause ตารางรันกับการ retry ของ job นั้น (ไม่ลบ job) บันทึกการตั้งค่าก่อน แล้วตรวจว่าสถานะ stopped และไม่มี session ใหม่"),
 "RB-FILE-TRANSFER-CONTAIN|S3": n("จำกัดสิทธิ์ transfer ของ {{transfer_session.account_id}} เฉพาะ path/destination ที่เกี่ยวข้องตามหลักฐาน (ไม่ disable บัญชีทั้งบัญชีถ้ายังไม่มีหลักฐานว่าถูกยึด) บันทึกสิทธิ์เดิมก่อน แล้วทดสอบว่า transfer ไป destination นั้นถูกปฏิเสธ"),
 "RB-FILE-TRANSFER-CONTAIN|S4": n("ตั้ง deny จากต้นทางของ job ไปยัง {{transfer_session.destination}} เฉพาะ destination นี้ ที่จุดบังคับเครือข่ายซึ่งเห็นต้นทางจริง บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่าถูกปฏิเสธ"),
 "RB-MAIL-EXFIL-CONTAIN|S2": n("ใน mail system ของ identity {{mail_path.identity_account_id}} ปิด (disable) เฉพาะ {{mail_path.path_objects}} ที่ไม่ได้รับอนุญาต (forwarding rule/delegate) ไม่ลบข้อความ บันทึกรายการก่อนแก้ แล้วตรวจรายการอีกครั้งว่าไม่มีรายการดังกล่าว"),
 "RB-MAIL-EXFIL-CONTAIN|S3": n("สั่ง hold queue {{mail_path.queue_id}} ที่รอส่งต่อ โดยไม่ลบข้อความ บันทึกจำนวนข้อความใน queue ก่อน แล้วตรวจว่าสถานะเป็น held และไม่มีข้อความออก"),
 "RB-MAIL-EXFIL-CONTAIN|S4": ir("IR ต้องกำหนดระดับการจำกัด identity ที่ถูกใช้ส่งต่อตาม identity scope ที่องค์กรอนุมัติ (และใช้ขั้นตอน Account Compromise หากมีหลักฐาน unauthorized authentication)"),
 # --- MALWARE
 "RB-ACTIVE-DAMAGE-CONTAIN|S2": n("บน {{share_session.file_server_host_id}} ใช้เครื่องมือจัดการ file server ตัดเฉพาะ write session {{share_session.session_ids}} ของ {{share_session.source_account_id}} ต่อ share {{share_session.share_name}} (ไม่ปิด share และไม่ตัด session อ่านของผู้อื่น) บันทึกรายการ session ก่อน แล้วตรวจว่าไม่มี write ใหม่จาก session ที่ตัด"),
 "RB-ACTIVE-DAMAGE-CONTAIN|S3": n(T1),
 "RB-ACTIVE-DAMAGE-CONTAIN|S4": n(HOST_ISOLATE % "host_workload.host_id" + " ทำหลังยุติ session/process ที่เขียนแล้วไม่ได้ผล หรือเมื่อความเสียหายยังดำเนินอยู่", requires_org=["approved_access"]),
 "RB-ACTIVE-DAMAGE-CONTAIN|S4c": n("จำกัดเฉพาะการเขียนไปยัง share ที่ถูกโจมตีและ outbound/east-west ที่ไม่จำเป็น โดยคง dependency ที่ asset owner ระบุ ไม่ isolate ทั้งเครื่อง แล้วแจ้ง asset owner ของ {{host_workload.host_id}} ตรวจว่า file modification บน share หยุดและ dependency ยังใช้ได้"),
 "RB-ACTIVE-DAMAGE-CONTAIN|S5": org("เครื่องมือหรือขั้นตอน forensic ขององค์กรสำหรับเก็บ memory และ process list รวมถึงที่เก็บหลักฐาน"),
 "RB-PROPAGATION-PATH-RESTRICT|S3": n("ตั้ง restriction เฉพาะ {{network_flow.protocol}}/{{network_flow.port}} จาก {{network_flow.source_host_id}} ไป {{network_flow.destination}} ที่จุดบังคับเครือข่ายซึ่งเห็น path นี้ (ไม่ใช่ rule ทั้ง segment) โดยคง management/IR access ตาม approved access ขององค์กร (ตรวจรายการก่อน) บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่า attempt ผ่าน path นี้ถูกปฏิเสธ", requires_org=["approved_access"]),
 "RB-PROPAGATION-PATH-RESTRICT|S4": dict(needs_prior=["S3"]),
 "RB-PROPAGATION-PATH-RESTRICT|S5": n(HOST_ISOLATE % "host_workload.host_id", requires_org=["approved_access"]),
 "RB-PROPAGATION-PATH-RESTRICT|S5c": n("จำกัดเฉพาะ east-west service ที่ worm ใช้และ outbound ที่ไม่จำเป็น ไม่ isolate ทั้งเครื่อง แล้วแจ้ง asset owner ของ {{host_workload.host_id}} ตรวจว่าไม่มี connection ผ่าน path และ dependency ที่จำเป็นยังใช้ได้"),
 "RB-BACKDOOR-CONTAIN|S3c": n("จำกัด outbound/channel ของ process ตามตัวระบุ Process ข้างต้นบน {{process.host_id}} ก่อน (ตัด channel ตามขั้นตอนถัดไป) แล้วส่งคำขออนุมัติ asset owner ก่อนยุติ process ห้ามยุติจนกว่าจะได้รับอนุมัติ"),
 "RB-BACKDOOR-CONTAIN|S3": n(T1 + " และตรวจ remote session ที่ผูกกับ process นั้น ยุติเฉพาะ session ที่ผูกกับ process นั้นเท่านั้น"),
 "RB-BACKDOOR-CONTAIN|S4": n("ตั้ง deny เฉพาะ flow {{network_flow.source_host_id}} → {{network_flow.destination}} ({{network_flow.protocol}}/{{network_flow.port}}) ที่จุดบังคับเครือข่ายซึ่งเห็น flow นี้ บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่า attempt ใหม่ถูกปฏิเสธ ถ้า flow เดิมยัง established อยู่ การตัด connection ต้องใช้เครื่องมือที่ระบุ connection ได้ ซึ่งแยกเป็นอีกขั้นตอน — ถ้ายังไม่ระบุเครื่องมือนั้น การตัดนี้ป้องกันได้เฉพาะ flow ใหม่"),
 "RB-STEALER-CONTAIN|S2": n(T1),
 "RB-STEALER-CONTAIN|S2c": n("จำกัด outbound ของ process ตามตัวระบุ Process ข้างต้นและ access ต่อข้อมูลที่ถูกเก็บบน {{host_workload.host_id}} ก่อน แล้วขออนุมัติ asset owner ก่อนยุติ process ห้ามยุติจนกว่าจะได้รับอนุมัติ"),
 "RB-STEALER-CONTAIN|S3": n(HOST_ISOLATE % "host_workload.host_id" + " เพื่อกันการส่งข้อมูลออกต่อ", requires_org=["approved_access"]),
 "RB-STEALER-CONTAIN|S4": n(flow(*NF)),
 "RB-STEALER-CONTAIN|S7": org("ขั้นตอนยืนยันตัวตนเจ้าของบัญชีและช่องทางส่ง credential ใหม่ที่องค์กรอนุมัติ"),
 "RB-MEMORY-EXECUTION-CONTAIN|S3": n(HOST_ISOLATE % "host_workload.host_id" + " เพื่อตัด channel ของ execution นี้", requires_org=["approved_access"]),
 "RB-MEMORY-EXECUTION-CONTAIN|S3c": n("ตัดเฉพาะ channel ที่ผูกกับ execution ไปยัง {{network_flow.destination}} และจำกัด outbound ที่ไม่จำเป็น ไม่ isolate ทั้งเครื่อง แล้วแจ้ง asset owner ของ {{host_workload.host_id}} ตรวจว่าไม่มี connection ไปยังปลายทางเดิม"),
 "RB-MEMORY-EXECUTION-CONTAIN|S4": n(T1),
 "RB-MEMORY-EXECUTION-CONTAIN|S5": n(flow(*NF)),
 # --- PHISHING
 "RB-MAIL-CAMPAIGN-QUARANTINE|S2": n(MSG_QUARANTINE),
 "RB-MAIL-CAMPAIGN-QUARANTINE|S3": org("ความสามารถของ mail gateway/endpoint control ในการ block ตามตัวตนของ attachment (เช่น hash ชื่อ หรือชนิด) และข้อมูลที่ใช้ระบุ attachment"),
 "RB-MAIL-CAMPAIGN-QUARANTINE|S4": n("ใช้ telemetry ที่มี (เช่น mail log และ endpoint log) ของ campaign {{message_set.message_ids_or_campaign_id}} หาผู้รับที่เปิด ดาวน์โหลด หรือรัน attachment แล้วประเมินแยกเป็นรายเครื่อง โดยอ้างอิงหลักฐานต่อรายการ ไม่ isolate ผู้รับทุกคน ผลคือรายชื่อพร้อม source ref เพื่อส่งต่อขั้นตอนของเครื่องหรือบัญชีที่ validated"),
 "RB-PHISHING-LINK-RESTRICT|S2": n("ตั้ง block ที่ mail/web control ตามระดับ {{url_object.granularity}} ของ {{url_object.url_or_domain}} (ถ้าเป็น shared cloud/CDN ห้าม block ทั้ง provider; ระดับ path ต้องใช้เครื่องมือที่เห็น path และ DNS ตัดได้เพียงระดับ domain) บันทึก rule เดิมก่อนแก้ แล้วทดสอบด้วย URL ว่าถูกบล็อกตาม log"),
 "RB-PHISHING-LINK-RESTRICT|S3": n("ใน mail system ค้นหาข้อความที่มี link นี้ในขอบเขต {{message_set.mailbox_scope}} ({{message_set.message_ids_or_campaign_id}}) แล้วย้ายเข้า quarantine โดยไม่ลบ เก็บรายการข้อความที่ย้ายไว้ใน incident record และค้นหาซ้ำเพื่อตรวจว่าไม่เหลือข้อความ active"),
 "RB-HARVESTING-CONTAIN|S1": n("ตั้ง block ที่ mail/web control ตามระดับ {{url_object.granularity}} ของ {{url_object.url_or_domain}} (ถ้าเป็น shared cloud/CDN ห้าม block ทั้ง provider; ระดับ path ต้องใช้เครื่องมือที่เห็น path และ DNS ตัดได้เพียงระดับ domain) บันทึก rule เดิมก่อนแก้ แล้วทดสอบด้วย URL ว่าถูกบล็อกตาม log"),
 "RB-HARVESTING-CONTAIN|S2": n("ใน mail system ค้นหาข้อความที่นำไปสู่หน้านี้ในขอบเขต {{message_set.mailbox_scope}} ({{message_set.message_ids_or_campaign_id}}) แล้วย้ายเข้า quarantine โดยไม่ลบ เก็บรายการที่ย้ายไว้ใน incident record และค้นหาซ้ำเพื่อตรวจว่าไม่เหลือข้อความ active"),
 "RB-HARVESTING-CONTAIN|S3": n(SESSIONS_REVOKE),
 "RB-HARVESTING-CONTAIN|S4": org("ขั้นตอนยืนยันตัวตนเจ้าของบัญชีและช่องทางส่ง credential ใหม่ที่องค์กรอนุมัติ"),
 "RB-OAUTH-GRANT-CONTAIN|S2": n("ในส่วนจัดการของ {{oauth_grant.provider}} หา grant {{oauth_grant.grant_id}} ของ client {{oauth_grant.client_id}} สำหรับ principal {{oauth_grant.principal_id}} แล้วถอนเฉพาะ grant นั้น (ไม่ถอน grant อื่นของ client หรือ principal) บันทึก grant ก่อนถอน แล้วตรวจว่าไม่อยู่ในรายการ consent ของ principal"),
 "RB-OAUTH-GRANT-CONTAIN|S3": org("ความสามารถของ provider ในการ revoke access/refresh token ที่ออกแล้วและวิธี invalidate token family"),
 "RB-OAUTH-GRANT-CONTAIN|S4": org("access restriction ที่ provider รองรับสำหรับ resource/principal/client นี้ จนกว่า token จะหมดอายุ"),
 "RB-BEC-CONTAIN|S1": org("ผู้มีอำนาจของรายการธุรกิจและช่องทางติดต่อคู่ค้าที่องค์กรยืนยันแล้ว"),
 "RB-BEC-CONTAIN|S3": n("ใน mailbox {{mailbox_access.mailbox_id}} ปิด (disable) เฉพาะ {{mailbox_access.abused_objects}} ที่ยืนยันแล้วว่าไม่ได้รับอนุญาต (forwarding rule/delegate) บันทึกรายการก่อนแก้ แล้วตรวจรายการอีกครั้งว่าไม่มีรายการดังกล่าว"),
 # --- POWERSHELL
 "RB-SCRIPT-EXECUTION-CONTAIN|S2": n(T1),
 "RB-SCRIPT-EXECUTION-CONTAIN|S3": n(T2),
 "RB-SCRIPT-EXECUTION-CONTAIN|S4": n(flow(*NF)),
 "RB-DOWNLOAD-EXECUTION-CONTAIN|S2": n(EGRESS_PATH.replace("web proxy หรือ egress control", "web/DNS/egress control")),
 "RB-DOWNLOAD-EXECUTION-CONTAIN|S3": n(T1),
 "RB-DOWNLOAD-EXECUTION-CONTAIN|S3b": n(T2),
 "RB-REMOTE-SESSION-CONTAIN|S2": n("ใช้เครื่องมือจัดการ remote session ของ {{remote_session.destination_host_id}} หา session {{remote_session.session_id}} แล้วยุติเฉพาะ session นั้น บันทึกรายละเอียดก่อนยุติ แล้วตรวจว่าไม่อยู่ในรายการ session ที่ active"),
 "RB-REMOTE-SESSION-CONTAIN|S3": n("จำกัดเฉพาะ management path {{remote_session.protocol}} จาก {{remote_session.source_host_id}} ไป {{remote_session.destination_host_id}} ที่จุดบังคับเครือข่าย (ไม่ปิด remoting ทั้งองค์กร) โดยคง approved management/IR access ตามรายการขององค์กร (ตรวจรายการก่อน) บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่า attempt ใหม่ถูกปฏิเสธ", requires_org=["approved_access"]),
 "RB-REMOTE-SESSION-CONTAIN|S4": n(T1 + " (เฉพาะ process ที่ถูกสร้างจาก session นี้)"),
 "RB-PERSISTENCE-TRIGGER-DISABLE|S6": n(T2),
 "RB-PERSISTENCE-TRIGGER-DISABLE|S4": dict(needs_prior=["S3"]),
 # --- PRIVILEGE_ESCALATION
 "RB-ELEVATED-EXECUTION-CONTAIN|S2": n("แยก/จำกัด {{host_workload.host_id}} ผ่านเครือข่ายเพื่อหยุดการใช้ privileged context โดยคงเฉพาะช่องทาง IR และ admin ที่ระบุไว้ใน approved access ขององค์กร (ตรวจรายการก่อนลงมือ) ตรวจว่า inbound/outbound ถูกจำกัดยกเว้นช่องทางที่คงไว้", requires_org=["approved_access"]),
 "RB-ELEVATED-EXECUTION-CONTAIN|S2c": n("จำกัด entry path ที่ใช้ context นี้ก่อน แล้วยุติเฉพาะ privileged context {{privileged_context.context_identity}} บน {{privileged_context.host_id}} (ตรวจก่อนว่ายัง active) ไม่ isolate ทั้งเครื่อง แล้วแจ้ง asset owner ตรวจว่า context ไม่ active"),
 "RB-ELEVATED-EXECUTION-CONTAIN|S3": n(T1 + " (เฉพาะ process ที่ทำงานใน privileged context)"),
 "RB-ELEVATED-EXECUTION-CONTAIN|S4": n("จำกัดเฉพาะการเข้าถึง {{service_endpoint.service}} บน {{service_endpoint.host_id}} ที่ใช้ exploit ที่ {{service_endpoint.enforcement_point}} (ไม่ปิดบริการทั้งหมด; patch เป็น remediation แยก) บันทึก rule เดิมก่อนแก้ แล้วตรวจจาก log ว่า attempt ใหม่ถูกปฏิเสธ"),
 "RB-LOCAL-ELEVATION-CONTAIN|S3": n(ENTITLE),
 "RB-LOCAL-ELEVATION-CONTAIN|S4": n("หลังถอน entry แล้ว ตรวจว่า privileged session ของ context {{privileged_context.context_identity}} บน {{privileged_context.host_id}} ยัง active อยู่หรือไม่ ถ้ายังจึงยุติเฉพาะ session ที่ใช้ entry นั้น แล้วตรวจว่า context ไม่ active", needs_prior=["S3"]),
 "RB-PRIVILEGED-TRIGGER-CONTAIN|S3": n(PERSIST_DISABLE),
 "RB-PRIVILEGED-TRIGGER-CONTAIN|S4": n(PERSIST_STOP, needs_prior=["S3"]),
 "RB-PRIVILEGED-TRIGGER-CONTAIN|S5": n(T1),
 "RB-PRIVILEGED-TRIGGER-CONTAIN|S6": n(T2),
 "RB-PRIVILEGED-TRIGGER-CONTAIN|S7": org("baseline ACL และรายชื่อ principal ที่องค์กรอนุมัติให้เขียนได้"),
 "RB-PRIVILEGED-TRIGGER-CONTAIN|S8": org("trusted approved configuration (baseline ที่อนุมัติ) และการยืนยันจาก IR ว่าเป็น false positive หรือพร้อมคืนค่า"),
 "RB-PRIVILEGED-CONTEXT-CONTAIN|S2": n(T1 + " (เฉพาะ process ที่ถือ privileged context)"),
 "RB-PRIVILEGED-CONTEXT-CONTAIN|S4": n("ถอน privilege ต้นทาง {{entitlement_grant.entitlement_entry}} ของ {{entitlement_grant.principal_id}} ที่ทำให้ impersonate ได้ เฉพาะรายการนี้ บันทึก entry เดิมก่อนถอน แล้วทดสอบว่า impersonation ถูกปฏิเสธ"),
 "RB-PRIVILEGED-GRANT-CONTAIN|S3": n(ENTITLE),
 "RB-PRIVILEGED-GRANT-CONTAIN|S5": ir("IR ต้องกำหนดระดับการจำกัด actor ที่เปลี่ยน entitlement ตาม identity scope ที่องค์กรอนุมัติ (และใช้ขั้นตอน Account Compromise หากมีหลักฐาน unauthorized authentication)"),
 "RB-CLOUD-PRIVILEGE-CONTAIN|S3": n("จำกัด trust/grant {{cloud_trust.trust_or_policy_ref}} เฉพาะส่วนที่มีหลักฐานต่อ {{cloud_trust.resources}} (ไม่ปรับ policy ทั้ง account) บันทึก policy เดิมก่อนแก้ แล้วตรวจจาก cloud audit ว่า assume/use ใหม่ถูกปฏิเสธ"),
 # --- SQL_INJECTION
 "RB-WEB-REQUEST-RESTRICT|S3": n(webrule("web_route.control_point", "web_route.route", "web_route.parameter", "ให้ตรวจ pattern UNION injection ")),
 "RB-WEB-REQUEST-RESTRICT|S4": n("ตั้ง rate-limit เฉพาะ {{web_route.route}} สำหรับ source scope {{web_route.source_scope}} ตามที่พบในหลักฐาน (ไม่ใช่ทั้งแอป) ที่ web control ที่ใช้ได้ บันทึกค่าเดิมก่อนแก้ แล้วตรวจจาก log ว่า request rate จาก scope ลดลง"),
 "RB-DB-ERROR-EXPOSURE-CONTAIN|S2": n("แก้ response handler {{response_handler.handler_or_path}} ให้ส่งข้อความผิดพลาดทั่วไปออกภายนอก โดยคง internal error logging ไว้เต็มรูปแบบ ทำผ่าน change control ขององค์กรและทดสอบก่อน แล้วทดสอบ request เดิมว่า response ภายนอกเป็นข้อความทั่วไปและ internal log ยังบันทึก error"),
 "RB-DB-ERROR-EXPOSURE-CONTAIN|S3": n(webrule("web_route.control_point", "web_route.route", "web_route.parameter", "เพื่อจำกัด request ที่ probing ")),
 "RB-SQLI-PROBING-RESTRICT|S2": n(webrule("web_route.control_point", "web_route.route", "web_route.parameter", "เพื่อจำกัด input path ที่ถูกสำรวจ ")),
 "RB-SQLI-PROBING-RESTRICT|S3": n("ตั้ง throttling เฉพาะ {{web_route.route}} ให้ครอบคลุมทุก source ใน campaign scope {{web_route.source_scope}} (ไม่ block IP เดียว) บันทึกค่าเดิมก่อนแก้ แล้วตรวจจาก log ว่า request rate ของ scope ลดลง"),
 "RB-SQLI-TIMING-CONTAIN|S2": n("จำกัด request path {{web_route.route}} / {{web_route.parameter}} ด้วย targeted rule หรือ rate-limit ที่ {{web_route.control_point}} เพื่อไม่ให้ query ใหม่ถูกสร้าง บันทึกค่าเดิมก่อนแก้ แล้วตรวจจาก log ว่ามีการจำกัดและไม่มี query ใหม่"),
 "RB-SQLI-TIMING-CONTAIN|S3": n("ส่งให้ DBA ของ {{db_query_job.platform}}: ตัวระบุ query/session {{db_query_job.query_or_session_id}} ฐานข้อมูล {{db_query_job.database}} เวลาที่พบ และหลักฐานอ้างอิง ให้ DBA ยืนยันว่าตัวระบุตรงกับ query ที่ผิดปกติก่อน แล้ว cancel เฉพาะรายการนั้น (ไม่ cancel slow query อื่น) และแจ้งผลกลับ IR เพื่อบันทึกใน incident record"),
 "RB-DB-EGRESS-CONTAIN|S3": n(flow("db_egress.db_host_id", "db_egress.destination", "db_egress.protocol", "db_egress.protocol").replace("({{db_egress.protocol}}/{{db_egress.protocol}})", "({{db_egress.protocol}})").replace("ไม่ใช่ rule กว้างทั้งปลายทางหรือพอร์ต", "ไม่ isolate DB ทั้งเครื่อง")),
 "RB-DB-EGRESS-CONTAIN|S4": dict(needs_prior=["S3"]),
 "RB-DB-EGRESS-CONTAIN|S5": n(webrule("web_route.control_point", "web_route.route", "web_route.parameter", "เพื่อปิดเส้นทางที่ถูก inject ")),
 "RB-STORED-PAYLOAD-CONTAIN|S2": n("สั่ง pause consumer/job {{stored_record_pipeline.consumer_or_job_id}} และ retry/ตารางรันของมัน (เฉพาะตัวนี้) บันทึกสถานะก่อน แล้วตรวจว่าไม่มีการรัน"),
 "RB-STORED-PAYLOAD-CONTAIN|S3": n("แยก records {{stored_record_pipeline.record_ids}} และสำเนาใน queue ({{stored_record_pipeline.queued_copies_locator}}) ออกจากการประมวลผลด้วยเครื่องมือของ queue โดยเก็บต้นฉบับไว้เพื่อ forensic (ไม่ลบ) แล้วตรวจว่า queue ไม่มีสำเนา active และต้นฉบับยังอยู่", needs_prior=["S2"]),
 "RB-STORED-PAYLOAD-CONTAIN|S4": n("resume consumer/job {{stored_record_pipeline.consumer_or_job_id}} หลังยืนยันว่า records ที่ถูกกันถูกยกเว้นแล้ว ตรวจว่า job ทำงานและไม่ประมวลผล records ที่ hold", needs_prior=["S3"]),
 "RB-BATCH-QUERY-CONTAIN|S2": n("ตั้ง targeted rule ที่ control ของแอปพลิเคชันเฉพาะ source path {{db_driver_path.route}} ให้จำกัด statement ซ้อน เริ่มในโหมด detect/log เทียบกับ traffic ปกติก่อน block บันทึกค่าเดิมก่อนแก้ แล้วตรวจจาก log ว่ามีการจำกัดและไม่มี statement ซ้อนผ่าน"),
 "RB-BATCH-QUERY-CONTAIN|S3": ir("IR ต้องยืนยันว่า driver รองรับการปิด multi-statement และได้รับอนุมัติ change ตามขั้นตอนขององค์กร"),
 # --- SUSPICIOUS_PROCESS
 "RB-TRUSTED-BINARY-ABUSE-CONTAIN|S2": n(T1 + " (ไม่ลบหรือ block hash ของ binary ระบบ)"),
 "RB-TRUSTED-BINARY-ABUSE-CONTAIN|S2c": n("จำกัดผลของ instance ตามตัวระบุ Process ข้างต้นบน {{process.host_id}} ด้วย behavior control หรือ channel restriction ก่อน แล้วส่งคำขออนุมัติ asset owner ก่อนยุติ ห้ามยุติจนกว่าจะได้รับอนุมัติ"),
 "RB-TRUSTED-BINARY-ABUSE-CONTAIN|S3": n(T2),
 "RB-TRUSTED-BINARY-ABUSE-CONTAIN|S4": org("ความสามารถ behavior control ขององค์กรและรูปแบบ arguments/effects ที่เป็น abuse ซึ่งระบุได้จากหลักฐาน"),
 "RB-TRUSTED-BINARY-ABUSE-CONTAIN|S5": n(flow(*NF) + " (flow ที่ผูกกับ instance นี้)"),
 "RB-IMPOSTOR-PROCESS-CONTAIN|S2": n(T1),
 "RB-INJECTED-PROCESS-CONTAIN|S2": n(HOST_ISOLATE % "host_workload.host_id" + " เพื่อตัด channel ของ injected execution", requires_org=["approved_access"]),
 "RB-INJECTED-PROCESS-CONTAIN|S2c": n("จำกัดเฉพาะ channel ที่ผูกกับ injected process ไปยัง {{network_flow.destination}} บน {{process.host_id}} ไม่ isolate ทั้งเครื่อง แล้วแจ้ง asset owner ตรวจว่าไม่มี connection ไปยังปลายทางเดิม"),
 "RB-INJECTED-PROCESS-CONTAIN|S3": n(flow(*NF)),
 "RB-INJECTED-PROCESS-CONTAIN|S4": n(T1 + " ส่วน target process ที่ถูก inject ให้ยุติหลังได้รับอนุมัติตาม criticality ของ target เท่านั้น"),
 "RB-EXECUTION-CHAIN-CONTAIN|S2": n(T1 + " (ไม่ปิด application หลัก)"),
 "RB-EXECUTION-CHAIN-CONTAIN|S2c": n("จำกัด entry path ตามขั้นตอนถัดไปก่อน แล้วส่งคำขออนุมัติ asset owner ของ {{process.host_id}} ก่อนยุติ child ตามตัวระบุ Process ข้างต้น ห้ามยุติจนกว่าจะได้รับอนุมัติ"),
 "RB-EXECUTION-CHAIN-CONTAIN|S3": n(T2),
 "RB-EXECUTION-CHAIN-CONTAIN|S4": n(webrule("web_route.control_point", "web_route.route", "web_route.parameter", "ของ {{web_route.application}} เพื่อจำกัดเส้นทางเข้าที่ใช้สั่งคำสั่งบนเครื่อง (OS command injection จัดการที่ขั้นตอนนี้ ไม่ใช่ขั้นตอน SQLi) ")),
 "RB-INVESTIGATE-MISSING-EVIDENCE|I2": n("ค้นหา target ที่ขาด ({{missing.target_list}}) จาก event และ asset inventory ที่อ้างอิงได้ โดยบันทึกแหล่งที่มาต่อค่า ไม่เดาหรือเติมค่าที่ไม่มีหลักฐาน แล้วส่งค่าที่ยืนยันกลับเข้าการประเมิน"),
}

def main():
    json.dump(M, open("tools/methods.json", "w", encoding="utf8"), ensure_ascii=False, indent=1)
    import glob
    seen = set(); touched = 0
    for f in sorted(glob.glob("families/*.yaml")):
        lines = open(f, encoding="utf8", newline="").read().split(NL)
        res = []; rb = None; sid = None; i = 0
        while i < len(lines):
            ln = lines[i]; res.append(ln)
            m = re.match(r"^  - runbook_id: (\S+)", ln)
            if m: rb = m.group(1); sid = None
            m = re.match(r"^      - step_id: (\S+)", ln)
            if m: sid = m.group(1)
            if rb and sid and re.match(r"^        instruction: ", ln):
                j = i + 1; rest = []
                while j < len(lines) and re.match(r"^        \S|^          ", lines[j]): rest.append(lines[j]); j += 1
                block = NL.join(rest)
                key = f"{rb}|{sid}"; e = M.get(key); add = []
                has_method = re.search(r"^        method: ", block, re.M) is not None
                if e: seen.add(key)
                if e and e.get("basis") == "NEUTRAL_DERIVED" and not has_method:
                    add.append("        method: " + json.dumps(e["method"], ensure_ascii=False)); has_method = True; basis = "NEUTRAL_DERIVED"
                elif e and e.get("basis") in ("ORG_INPUT_REQUIRED", "IR_REVIEW_REQUIRED"):
                    basis = e["basis"]
                else:
                    basis = "EXISTING" if has_method else None
                if basis and "method_basis:" not in block:
                    add.append("        method_basis: " + basis)
                if e and e.get("requires") and "method_requires:" not in block:
                    add.append("        method_requires: " + json.dumps(e["requires"], ensure_ascii=False))
                if e and e.get("requires_org") and "requires_org:" not in block:
                    add.append("        requires_org: [" + ", ".join(e["requires_org"]) + "]")
                if e and e.get("needs_prior") and "needs_prior:" not in block:
                    add.append("        needs_prior: [" + ", ".join(e["needs_prior"]) + "]")
                if add: touched += 1
                res.extend(add)
            i += 1
        open(f, "w", encoding="utf8", newline="").write(NL.join(res))
    print("steps touched:", touched, "| authored entries:", len(M), "| entries not matched to a step:", sorted(set(M) - seen))

main()
