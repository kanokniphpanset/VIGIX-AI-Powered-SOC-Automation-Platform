import { test } from 'node:test'
import assert from 'node:assert/strict'
import { notificationText, notificationType, timelineText } from './systemText.ts'
import { setLocale } from '../i18n/locale.ts'

const SUBJECT = 'sshd: brute force trying to get access to the system. Non existent user.'

test('Thai: notification titles are rebuilt per event type; the subject (Wazuh text) is kept exactly', () => {
  setLocale('th')
  assert.equal(notificationText({ eventType: 'NEW_INCIDENT', title: `New incident (MEDIUM): ${SUBJECT}`, body: null }).title, `Incident ใหม่ (Medium): ${SUBJECT}`)
  assert.equal(notificationText({ eventType: 'APPROVAL_APPROVED', title: `IR APPROVED — response can be executed: ${SUBJECT}`, body: 'Verified in the evidence.' }).title, `IR อนุมัติ — ลงมือได้: ${SUBJECT}`)
  assert.equal(notificationText({ eventType: 'RESPONSE_ASSIGNED', title: 'Response Ticket awaiting IR decision — Block Source IP on 198.51.100.77', body: null }).title, 'Response Ticket รอ IR ตัดสินใจ — Block Source IP on 198.51.100.77')
  assert.equal(notificationText({ eventType: 'INVESTIGATION_REOPENED', title: `Investigation #2 opened after re-hunt — ${SUBJECT}`, body: null }).title, `เปิดการสืบสวน #2 หลัง Re-hunt — ${SUBJECT}`)
  assert.equal(notificationText({ eventType: 'INCIDENT_RESOLVED', title: 'Incident RESOLVED — re-hunt found no recurrence (round 1)', body: null }).title, 'Incident แก้ไขแล้ว — Re-hunt ไม่พบภัยซ้ำ (รอบ 1)')
  assert.equal(notificationText({ eventType: 'IR_NOTIFIED', title: 'Email to IR_TEAM: [VIGIX] Investigation update: INC-4A4E20AC', body: null }).title, 'อีเมลถึง IR Team: [VIGIX] Investigation update: INC-4A4E20AC')
})

test('Thai: known bodies are translated; a user note is never changed', () => {
  setLocale('th')
  const created = notificationText({ eventType: 'NEW_INCIDENT', title: 'x', body: 'Created by 5464fe1e-3208-460c-a073-bb32da61d35b from 1 alert(s). AI analysis queued.' })
  assert.equal(created.body, 'สร้างโดย 5464fe1e-3208-460c-a073-bb32da61d35b จาก 1 Alert · เข้าคิว AI Analysis แล้ว')
  assert.equal(notificationText({ eventType: 'INCIDENT_ESCALATED', title: 'x', body: 'MAX_INVESTIGATION_ROUNDS_REACHED' }).body, 'Re-hunt ครบจำนวนรอบสูงสุดแล้วยังพบภัย')
  const note = 'Verified in the Wazuh evidence: repeated sshd failures; approved.'
  assert.equal(notificationText({ eventType: 'APPROVAL_APPROVED', title: 'x', body: note }).body, note)
})

test('unknown templates and English stay exactly as the backend wrote them', () => {
  setLocale('th')
  assert.deepEqual(notificationText({ eventType: 'SOMETHING_NEW', title: 'Brand new wording', body: 'b' }), { title: 'Brand new wording', body: 'b' })
  setLocale('en')
  const n = { eventType: 'NEW_INCIDENT', title: `New incident (HIGH): ${SUBJECT}`, body: 'Created by x from 2 alert(s). AI analysis queued.' }
  assert.deepEqual(notificationText(n), { title: n.title, body: n.body })
  assert.equal(notificationType('NEW_INCIDENT'), 'new incident')
})

test('Thai: incident timeline descriptions are rebuilt; the SOC reason is kept as written', () => {
  setLocale('th')
  assert.equal(timelineText('created', 'Incident created manually from 1 alert(s): Real sshd brute force - investigate'), 'SOC สร้าง Incident จาก 1 Alert: Real sshd brute force - investigate')
  assert.equal(
    timelineText('created', 'Incident opened automatically: HIGH Wazuh alert (rule 87105, level 12) — Policy RULE-A03, RULE-P02.'),
    'เปิด Incident อัตโนมัติจาก Alert High ของ Wazuh (rule 87105, level 12) — Policy RULE-A03, RULE-P02',
  )
  assert.equal(timelineText('ai_analysis_complete', 'AI pipeline completed: decision=human_approval (advisory). Severity stays the Wazuh severity (medium).'), 'AI pipeline เสร็จแล้ว — ผลเป็นคำแนะนำ ความรุนแรงยังเป็นของ Wazuh (Medium)')
  assert.equal(timelineText('SEVERITY_VALIDATED', 'Severity changed MEDIUM -> HIGH by SOC (Wazuh severity MEDIUM): lateral movement seen'), 'SOC Analyst เปลี่ยนความรุนแรง Medium → High (ความรุนแรงจาก Wazuh Medium): lateral movement seen')
  assert.equal(timelineText('created', 'Some future wording'), 'Some future wording')
  setLocale('en')
  assert.equal(timelineText('created', 'Incident created manually from 1 alert(s): x'), 'Incident created manually from 1 alert(s): x')
})
