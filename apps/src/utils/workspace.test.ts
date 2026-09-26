import { test } from 'node:test'
import assert from 'node:assert/strict'
import { actorName, auditGroup, auditLabel, auditOutcome, lifecycle, navFor, type LifecycleFacts } from './workspace.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

const keys = (role: string | null) => navFor(role).map((i) => i.key)

test('two operational roles, each with its own workspace navigation', () => {
  assert.deepEqual(keys('SOC'), ['dashboard', 'alerts', 'incidents', 'reports', 'knowledge', 'settings'])
  assert.deepEqual(keys('IR_TEAM'), ['dashboard', 'incidents', 'tickets', 'verification', 'reports', 'knowledge', 'settings'])
  assert.ok(keys('admin').includes('settings'))
  // A retired MANAGER account gets only the minimal read-only fallback — there is no Manager workspace.
  assert.deepEqual(keys('MANAGER'), keys(null))
  assert.deepEqual(keys(null), ['dashboard', 'incidents', 'knowledge', 'settings'])
})

test('no Manager / approval-queue screen; IR decides on the Response Ticket; SOC works alerts and incidents only', () => {
  for (const role of ['SOC', 'IR_TEAM', 'admin']) {
    assert.ok(!keys(role).includes('approvals' as never), role)
    assert.ok(!keys(role).includes('critical' as never), role)
  }
  for (const role of ['IR_TEAM', 'admin']) assert.ok(keys(role).includes('tickets'), role)
  assert.ok(!keys('SOC').includes('tickets'))
  assert.ok(!keys('IR_TEAM').includes('alerts'))
})

const base: LifecycleFacts = {
  hasAlert: true, incidentStatus: 'investigating', hasInvestigation: true, hasAiAnalysis: false, hasRecommendation: false,
  ticketCount: 0, approvalPending: false, approvalBlocked: false, anyReadyOrLater: false, anyCompleted: false, anyVerification: false,
}
const state = (f: Partial<LifecycleFacts>) => Object.fromEntries(lifecycle({ ...base, ...f }).map((s) => [s.key, s.state]))

test('lifecycle: first unfinished step is current', () => {
  const s = state({})
  assert.equal(s.investigation, 'done')
  assert.equal(s.ai, 'current')
  assert.equal(s.recommendation, 'todo')
  assert.equal(s.resolution, 'todo')
})

test('lifecycle: a ticket awaiting the IR decision keeps "IR decision" current; an IR rejection blocks it', () => {
  const pending = state({ hasAiAnalysis: true, hasRecommendation: true, ticketCount: 1, approvalPending: true })
  assert.equal(pending.policy, 'done')
  assert.equal(pending.approval, 'current')
  assert.equal(state({ hasAiAnalysis: true, hasRecommendation: true, ticketCount: 1, approvalBlocked: true }).approval, 'blocked')
})

test('lifecycle: Resolution is done only when resolved; escalated shows a blocked Escalated step', () => {
  const all = { hasAiAnalysis: true, hasRecommendation: true, ticketCount: 1, anyReadyOrLater: true, anyCompleted: true, anyVerification: true }
  assert.equal(state({ ...all, incidentStatus: 'resolved' }).resolution, 'done')
  assert.equal(state({ ...all, incidentStatus: 'investigating' }).resolution, 'current')
  const esc = lifecycle({ ...base, ...all, incidentStatus: 'escalated' }).at(-1)!
  assert.deepEqual([esc.label, esc.state], ['Escalated', 'blocked'])
})

test('audit labels, groups and outcomes are readable', () => {
  assert.equal(auditLabel('APPROVAL_APPROVED'), 'IR approved')
  assert.equal(auditLabel('RECOMMENDATION_SENT_TO_IR'), 'Recommendation sent to IR')
  assert.equal(lifecycle(base).map((s) => s.label).join(' > ').includes('IR decision'), true)
  assert.equal(auditLabel('SOMETHING_NEW'), 'Something new')
  assert.equal(auditGroup('EMAIL_SKIPPED'), 'email')
  assert.equal(auditGroup('APPROVAL_REJECTED'), 'approval')
  assert.equal(auditGroup('REHUNT_FAILED'), 'verification')
  assert.equal(auditOutcome({ status: 'approved', approvalRole: 'IR_TEAM', stepOrder: 1, nested: { x: 1 } }), 'status: approved · role: IR_TEAM · step: 1')
  assert.equal(auditOutcome({}), null)
})

test('actor is never shown as a bare UUID', () => {
  assert.equal(actorName({ actor: '73e2dbd6-cb20-4499-a3d1-ab1eec66d264', actorEmail: 'ir@x.test', actorRole: 'IR_TEAM' }), 'ir@x.test (IR_TEAM)')
  assert.equal(actorName({ actor: '73e2dbd6-cb20-4499-a3d1-ab1eec66d264', actorEmail: null, actorRole: null }), 'user (unknown account)')
  assert.equal(actorName({ actor: 'vigix-ai-worker', actorEmail: null, actorRole: null }), 'vigix-ai-worker')
})

test('severity validation is labelled and grouped under Policy; outcome shows from/to severity', () => {
  assert.equal(auditLabel('SEVERITY_VALIDATED'), 'Severity validated by analyst')
  assert.equal(auditGroup('SEVERITY_VALIDATED'), 'policy')
  assert.equal(auditOutcome({ previous: 'LOW', severity: 'HIGH', changed: true }), 'severity: HIGH · from: LOW')
})
