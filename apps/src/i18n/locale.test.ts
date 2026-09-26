import { test } from 'node:test'
import assert from 'node:assert/strict'
import { currentLang, labelMap, setLocale, tr } from './locale.ts'
import { AREAS } from './catalog.ts'
import { en, th } from './messages.ts'
import { statusLabel, timeAgo } from '../utils/vigix.ts'
import { auditLabel, auditOutcome, TICKET_TABS } from '../utils/workspace.ts'
import { workflowError } from '../utils/workflow.ts'
import { ticketStatusLabel, STAGE_LABEL } from '../utils/ticket.ts'
import { STATUS_TABS } from '../utils/triage.ts'
import { approvalSummary } from '../utils/incidentWorkflow.ts'

test('no message key is defined twice (across catalog areas or the core dictionary)', () => {
  const seen = new Map<string, string>()
  for (const [area, pairs] of Object.entries(AREAS)) {
    for (const k of Object.keys(pairs)) {
      assert.ok(!seen.has(k), `${k} defined in ${seen.get(k)} and ${area}`)
      seen.set(k, area)
    }
  }
  assert.equal(Object.keys(th).length, Object.keys(en).length)
})

test('Thai is the default; every system label follows the chosen language', () => {
  assert.equal(currentLang(), 'th')
  assert.equal(statusLabel('investigating'), 'กำลังสืบสวน')
  assert.equal(auditLabel('APPROVAL_REJECTED'), 'IR ปฏิเสธ')
  assert.equal(workflowError({ code: 'NOTE_REQUIRED' }), 'ใส่เหตุผลการตัดสินใจก่อนบันทึก (จำเป็นทั้ง APPROVE และ REJECT)')
  assert.equal(ticketStatusLabel('PENDING_IR_DECISION'), 'รอ IR ตัดสินใจ')
  assert.equal(STAGE_LABEL.AWAITING_REHUNT, 'รอ Re-hunt')
  assert.equal(TICKET_TABS[0].label, 'งานของฉัน')
  assert.deepEqual(STATUS_TABS[1], ['needs-review', 'รอตรวจ'])
  assert.equal(approvalSummary(null), 'ยังไม่มี Response Ticket')
  assert.equal(auditOutcome({ status: 'approved', approvalRole: 'IR_TEAM' }), 'สถานะ: อนุมัติแล้ว · บทบาท: IR Team')
  assert.equal(timeAgo(new Date(Date.now() - 5 * 60_000).toISOString()), '5 นาทีที่แล้ว')

  setLocale('en')
  assert.equal(statusLabel('investigating'), 'Investigating')
  assert.equal(auditLabel('APPROVAL_REJECTED'), 'IR rejected')
  assert.equal(workflowError({ code: 'NOTE_REQUIRED' }), 'Write the decision note before saving (required for APPROVE and REJECT).')
  assert.equal(STAGE_LABEL.AWAITING_REHUNT, 'Awaiting re-hunt')
  assert.equal(TICKET_TABS[0].label, 'My Work')
  assert.deepEqual(STATUS_TABS[1], ['needs-review', 'Needs review'])
  assert.equal(timeAgo(new Date(Date.now() - 5 * 60_000).toISOString()), '5 min ago')
  setLocale('th')
})

test('an unknown backend value or code is still shown (never blank)', () => {
  setLocale('th')
  assert.equal(statusLabel('brand_new_state'), 'Brand new state')
  assert.equal(auditLabel('SOMETHING_ELSE'), 'Something else')
  assert.equal(ticketStatusLabel('DRAFT_X'), 'DRAFT_X')
  assert.equal(workflowError({ code: 'NOT_A_KNOWN_CODE' }), tr('err.generic'))
})

test('labelMap values are read in the language current at read time', () => {
  const map = labelMap({ a: 'st.open' })
  setLocale('th')
  assert.equal(map.a, 'เปิดอยู่')
  setLocale('en')
  assert.equal(map.a, 'Open')
  assert.deepEqual(Object.entries(map), [['a', 'Open']])
  setLocale('th')
})
