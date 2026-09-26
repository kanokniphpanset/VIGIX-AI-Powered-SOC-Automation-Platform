import { test } from 'node:test'
import assert from 'node:assert/strict'
import { feedback, rehuntKind } from './feedback.ts'

test('every message says what happened AND what comes next', () => {
  const f = feedback('sentToIr')
  assert.equal(f.title, 'ส่งให้ IR แล้ว')
  assert.match(f.message, /^ขั้นต่อไป: /)
  assert.deepEqual(f.link, { label: 'กลับไปงานของฉัน', to: '/dashboard' })
})

test('the link points where the next step happens, filled from the result', () => {
  assert.deepEqual(feedback('rhNotResolved', 'th', { inc: 'INC-1', n: 2, incidentId: 'abc' }).link?.to, '/incidents/abc')
  assert.equal(feedback('rhNotResolved', 'th', { inc: 'INC-1', n: 2, incidentId: 'abc' }).title, 'ยังพบภัย — INC-1 เริ่มสืบสวนรอบที่ 2')
  assert.equal(feedback('alertClosed').link?.to, '/alerts?status=needs-review')
  assert.equal(feedback('approved').link, null) // next step (Start) is on the same screen
})

test('English follows the language switch; a backend detail is kept in front of the next step', () => {
  const f = feedback('aiFailed', 'en', {}, 'Orchestrator unreachable.')
  assert.equal(f.type, 'error')
  assert.equal(f.title, 'AI analysis did not run')
  assert.match(f.message, /^Orchestrator unreachable\. · Next: /)
})

test('re-hunt verdict picks the right message', () => {
  assert.equal(rehuntKind('RESOLVED', 'resolved'), 'rhResolved')
  assert.equal(rehuntKind('NOT_RESOLVED', 'escalated'), 'rhEscalated')
  assert.equal(rehuntKind('NOT_RESOLVED', 'investigating'), 'rhNotResolved')
})
