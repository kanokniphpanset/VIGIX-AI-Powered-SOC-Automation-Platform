import { test } from 'node:test'
import assert from 'node:assert/strict'
import { approvalSummary, latestTicket, rehuntRounds, type SummaryTicket } from './incidentWorkflow.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

const ticket = (o: Partial<SummaryTicket> = {}): SummaryTicket => ({
  id: 't1', stage: 'READY_FOR_EXECUTION', status: 'READY_FOR_EXECUTION', approvalStatus: 'NOT_REQUIRED', actionName: 'Block IP', target: '1.2.3.4',
  assignedRole: 'IR_TEAM', updatedAt: '2026-09-25T10:00:00Z', approvals: [], ...o,
})

test('re-hunt history keeps every round, oldest first', () => {
  const rounds = rehuntRounds([
    { id: 'v2', responseId: 'r2', result: 'RESOLVED', matchingEvents: 0, spreadDetected: false, verifiedAt: '2026-09-25T12:00:00Z', verifiedBy: 'ir-1' },
    { id: 'v1', responseId: 'r1', result: 'NOT_RESOLVED', matchingEvents: 4, spreadDetected: false, verifiedAt: '2026-09-25T09:00:00Z', afterState: { evidenceSource: 'WAZUH' } },
  ])
  assert.deepEqual(rounds.map((r) => [r.round, r.id, r.result]), [[1, 'v1', 'NOT_RESOLVED'], [2, 'v2', 'RESOLVED']])
  assert.equal(rounds[0].source, 'WAZUH')
})

test('latest ticket = most recently updated', () => {
  assert.equal(latestTicket([ticket({ id: 'a', updatedAt: '2026-09-25T08:00:00Z' }), ticket({ id: 'b', updatedAt: '2026-09-25T11:00:00Z' })])?.id, 'b')
  assert.equal(latestTicket([]), null)
})

test('approval status in words', () => {
  assert.equal(approvalSummary(null), 'No response ticket yet')
  assert.equal(approvalSummary(ticket()), 'No IR decision recorded (legacy ticket)')
  const pending = [{ role: 'IR_TEAM', status: 'pending', stepOrder: 1, decidedBy: null, decidedAt: null }]
  assert.equal(approvalSummary(ticket({ approvalStatus: 'PENDING', approvals: pending })), 'Waiting for the IR decision')
  assert.equal(approvalSummary(ticket({ approvalStatus: 'APPROVED', approvals: pending.map((a) => ({ ...a, status: 'approved' })) })), 'Approved by IR')
  assert.equal(approvalSummary(ticket({ approvalStatus: 'REJECTED', approvals: pending.map((a) => ({ ...a, status: 'rejected' })) })), 'Rejected by IR')
  for (const t of [ticket(), ticket({ approvals: pending })]) assert.doesNotMatch(approvalSummary(t), /manager/i)
})
