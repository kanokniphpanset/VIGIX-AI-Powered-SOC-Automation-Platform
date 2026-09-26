import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nextStep, type NextStepFacts } from './nextStep.ts'

const base: NextStepFacts = {
  role: 'SOC',
  incidentId: 'inc-1',
  incidentStatus: 'investigating',
  investigationNumber: 1,
  severityConfirmed: false,
  hasAiAnalysis: false,
  recommendation: null,
  unsentSteps: 0,
  ticketStatuses: [],
  awaitingRehunt: false,
}
const at = (over: Partial<NextStepFacts>) => nextStep({ ...base, ...over })

test('SOC path in order: confirm severity → run AI → create recommendation → send to IR, one action each', () => {
  assert.deepEqual([at({}).key, at({}).action], ['soc-severity', { kind: 'tab', tab: 'overview', anchor: 'severity' }])
  assert.deepEqual([at({ severityConfirmed: true }).key, at({ severityConfirmed: true }).action], ['soc-ai', { kind: 'run-ai' }])
  const s3 = at({ severityConfirmed: true, hasAiAnalysis: true })
  assert.deepEqual([s3.key, s3.action, s3.position], ['soc-recommend', { kind: 'generate' }, 3])
  const s4 = at({ severityConfirmed: true, hasAiAnalysis: true, recommendation: { status: 'VALIDATED' }, unsentSteps: 2 })
  assert.deepEqual([s4.key, s4.params, s4.mine, s4.tone], ['soc-send', { n: 2 }, true, 'action'])
})

test('a recommendation that failed validation must be regenerated, never sent', () => {
  assert.equal(at({ severityConfirmed: true, hasAiAnalysis: true, recommendation: { status: 'INVALID' }, unsentSteps: 2 }).key, 'soc-regenerate')
})

test("IR's turn follows the ticket: decide → start → complete → re-hunt, each linking to this incident's queue", () => {
  const ir = { role: 'IR_TEAM', severityConfirmed: true, hasAiAnalysis: true, recommendation: { status: 'VALIDATED' } }
  const d = at({ ...ir, ticketStatuses: ['PENDING_IR_DECISION'] })
  assert.deepEqual([d.key, d.turn, d.mine, d.action], ['ir-decide', 'IR', true, { kind: 'route', to: '/tickets?queue=awaiting-decision&incident=inc-1' }])
  assert.equal(at({ ...ir, ticketStatuses: ['PENDING_APPROVAL'] }).key, 'ir-decide') // legacy status
  assert.equal(at({ ...ir, ticketStatuses: ['READY_FOR_EXECUTION'] }).key, 'ir-start')
  assert.equal(at({ ...ir, ticketStatuses: ['IN_PROGRESS'] }).key, 'ir-complete')
  assert.equal(at({ ...ir, ticketStatuses: ['COMPLETED'], awaitingRehunt: true }).key, 'ir-rehunt')
})

test('the other role sees whose turn it is but gets no button (waiting)', () => {
  const s = at({ role: 'SOC', ticketStatuses: ['PENDING_IR_DECISION'] })
  assert.deepEqual([s.turn, s.mine, s.tone], ['IR', false, 'waiting'])
  const admin = at({ role: 'admin' })
  assert.deepEqual([admin.turn, admin.mine], ['SOC', false])
})

test('rejected or failed tickets send the case back to the SOC for review', () => {
  const back = { severityConfirmed: true, hasAiAnalysis: true, recommendation: { status: 'VALIDATED' }, unsentSteps: 1 }
  assert.deepEqual([at({ ...back, ticketStatuses: ['REJECTED'] }).key, at({ ...back, ticketStatuses: ['REJECTED'] }).tone], ['soc-rejected', 'problem'])
  assert.equal(at({ ...back, ticketStatuses: ['FAILED'] }).key, 'soc-failed')
  // another ticket of the same case is still with IR → IR's turn first
  assert.equal(at({ ...back, ticketStatuses: ['REJECTED', 'IN_PROGRESS'] }).key, 'ir-complete')
})

test('a new investigation round after a re-hunt MATCH is announced to the SOC', () => {
  const s = at({ investigationNumber: 2, severityConfirmed: true })
  assert.deepEqual([s.key, s.newCycle], ['soc-ai', 2])
})

test('ended cases: resolved / dismissed have no one to act; escalated needs IR', () => {
  assert.deepEqual([at({ incidentStatus: 'resolved' }).turn, at({ incidentStatus: 'resolved' }).tone, at({ incidentStatus: 'resolved' }).position], ['NONE', 'done', null])
  assert.equal(at({ incidentStatus: 'dismissed' }).key, 'dismissed')
  const e = at({ incidentStatus: 'escalated', role: 'IR_TEAM', ticketStatuses: ['COMPLETED'] })
  assert.deepEqual([e.key, e.turn, e.mine, e.tone], ['escalated', 'IR', true, 'problem'])
})
