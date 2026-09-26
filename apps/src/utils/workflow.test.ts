import test from 'node:test'
import assert from 'node:assert/strict'
import { canCreateTicket, canDecideApproval, mutate, mutationState, workflowError, approvalChainFor, currentApproval } from './workflow.ts'
import { workflowApi } from '../api/vigix.ts'
import { api, currentSession, setSession, setUnauthorizedHandler } from '../api/http.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')
import { isExpiredToken, safeNext } from './session.ts'

test('only the SOC sends to IR (creates tickets); IR, admin, a retired MANAGER and anonymous cannot', () => {
  assert.equal(canCreateTicket('SOC'), true)
  for (const role of ['IR_TEAM', 'admin', 'MANAGER', null]) assert.equal(canCreateTicket(role), false)
})
test('only IR_TEAM decides an open IR decision (never admin, SOC or a retired MANAGER)', () => {
  const approval = { status: 'pending', approvalRole: 'IR_TEAM' }
  assert.equal(canDecideApproval('IR_TEAM', approval), true)
  // Spec: admin must not stand in for IR (backend: ADMIN_NOT_APPROVER).
  for (const role of ['admin', 'SOC', 'MANAGER', null]) assert.equal(canDecideApproval(role, approval), false)
  assert.equal(canDecideApproval('IR_TEAM', { ...approval, status: 'approved' }), false)
  // A historical row naming a retired role is never decidable.
  assert.equal(canDecideApproval('IR_TEAM', { status: 'pending', approvalRole: 'MANAGER' }), false)
})
test('ticket creation calls existing response API only and reloads after success', async () => {
  const original = globalThis.fetch; const calls: string[] = []
  globalThis.fetch = async (url, init) => { calls.push(String(url)); assert.equal(init?.method, 'POST'); assert.deepEqual(JSON.parse(String(init?.body)), { recommendationId: 'rec', stepId: 'step' }); return new Response('{}') }
  try { await mutate(mutationState(), () => workflowApi.createPlan('rec', 'step'), async () => { calls.push('reload') }); assert.deepEqual(calls, ['/api/responses', 'reload']) }
  finally { globalThis.fetch = original }
})
test('duplicate click is ignored while running; failed reload retries read only', async () => {
  let writes = 0; let release!: () => void
  const state = mutationState()
  const first = mutate(state, async () => { writes++; await new Promise<void>(r => { release = r }) }, async () => { throw Error() })
  assert.equal(await mutate(state, async () => { writes++ }, async () => {}), false)
  release(); await first; assert.equal(state.saved, true)
  await mutate(state, async () => { writes++ }, async () => {})
  assert.equal(writes, 1); assert.equal(state.success, true)
})
test('write error allows retry and never reports success', async () => {
  const state = mutationState(); await mutate(state, async () => { throw { code: 'ROLE_MISMATCH' } }, async () => assert.fail())
  assert.equal(state.success, false); assert.match(state.error, /IR team/)
  await mutate(state, async () => {}, async () => {}); assert.equal(state.success, true)
})
test('IR approve / reject carry the mandatory note; Send to IR, start and fail use the exact endpoints/bodies', async () => {
  const original = globalThis.fetch; const calls: [string, unknown][] = []
  globalThis.fetch = async (url, init) => { calls.push([String(url), JSON.parse(String(init?.body))]); return new Response('{}') }
  try {
    await workflowApi.approve('a', 'verified the host and IP'); await workflowApi.reject('a', 'wrong target'); await workflowApi.sendToIr('rec'); await workflowApi.start('t'); await workflowApi.fail('t', { outcome: 'failed', reason: 'reason', by: 'ir' })
    assert.deepEqual(calls.map(c => c[0]), ['/api/approvals/a/approve', '/api/approvals/a/reject', '/api/recommendations/rec/send-to-ir', '/api/responses/t/start', '/api/responses/t/fail'])
    assert.deepEqual(calls[0]?.[1], { comment: 'verified the host and IP' }); assert.deepEqual(calls[1]?.[1], { comment: 'wrong target' })
    assert.deepEqual(calls[2]?.[1], { note: null }); assert.deepEqual(calls[3]?.[1], {})
    assert.deepEqual(calls[4]?.[1], { executionResult: { outcome: 'failed', reason: 'reason', by: 'ir' } })
    assert.equal('requestMoreEvidence' in workflowApi, false)
  } finally { globalThis.fetch = original }
})
test('GET 401 clears session before unauthorized navigation', async () => {
  const original = globalThis.fetch; let cleared = false
  setSession({ token: 'test', role: 'SOC', email: 'test@example.invalid' })
  setUnauthorizedHandler(() => { cleared = currentSession() === null })
  globalThis.fetch = async () => new Response('{}', { status: 401 })
  try { await assert.rejects(api('/test')); assert.equal(cleared, true) } finally { globalThis.fetch = original }
})
test('expired/malformed tokens are rejected and login next stays internal', () => {
  const token = (exp: number) => `x.${btoa(JSON.stringify({ exp }))}.x`
  assert.equal(isExpiredToken(token(1), 1000), true); assert.equal(isExpiredToken(token(2), 1000), false)
  assert.equal(isExpiredToken('invalid'), true); assert.equal(safeNext('//evil.example'), '/dashboard')
  assert.equal(safeNext('/tickets/123?tab=approval'), '/tickets/123?tab=approval')
})
test('required domain failures have actionable messages without stack traces', () => {
  for (const code of ['ROLE_MISMATCH', 'ALREADY_DECIDED', 'STEP_HAS_NO_ACTION', 'RESPONSE_NOT_FOUND', 'NOTE_REQUIRED', 'ALERT_ALREADY_DECIDED', 'CLOSE_NOT_ALLOWED', 'NOTHING_TO_SEND']) assert.doesNotMatch(workflowError({ code }), /could not be completed/)
  for (const code of ['NOT_CLAIMED', 'ALREADY_CLAIMED', 'DECISION_NOTE_REQUIRED']) assert.match(workflowError({ code }), /could not be completed/) // retired codes
})

test('IR decision history: the open IR_TEAM step is current; a re-request after a rejection starts a new history', () => {
  const rows = [
    { id: 'i1', responseId: 'r1', approvalRole: 'IR_TEAM', status: 'rejected', stepOrder: 1, decidedAt: '2026-09-24T10:05:00.000Z', createdAt: '2026-09-24T10:00:00.000Z' },
    { id: 'i2', responseId: 'r1', approvalRole: 'IR_TEAM', status: 'pending', stepOrder: 1, decidedAt: null, createdAt: '2026-09-24T11:00:00.000Z' },
    { id: 'x', responseId: 'r2', approvalRole: 'IR_TEAM', status: 'pending', stepOrder: 1, decidedAt: null, createdAt: '2026-09-24T09:00:00.000Z' },
  ]
  const chain = approvalChainFor(rows, 'r1')
  assert.deepEqual(chain.map((a) => a.id), ['i2'])
  assert.equal(currentApproval(chain)?.id, 'i2')
  assert.equal(canDecideApproval('IR_TEAM', chain[0]), true)
})

test('legacy tickets: a migrated open step (now IR_TEAM, step 2) is the current decision', () => {
  const rows = [
    { id: 'i', responseId: 'r1', approvalRole: 'IR_TEAM', status: 'approved', stepOrder: 1, decidedAt: '2026-09-24T10:05:00.000Z', createdAt: '2026-09-24T10:00:00.000Z' },
    { id: 'm', responseId: 'r1', approvalRole: 'IR_TEAM', status: 'pending', stepOrder: 2, decidedAt: null, createdAt: '2026-09-24T10:00:00.001Z' },
  ]
  assert.equal(currentApproval(approvalChainFor(rows, 'r1'))?.id, 'm')
})

test('legacy single approval rows (no stepOrder) still resolve', () => {
  const rows = [{ id: 'a', responseId: 'r1', approvalRole: 'IR_TEAM', status: 'approved', decidedAt: '2026-09-20T10:00:00.000Z' }]
  assert.equal(currentApproval(approvalChainFor(rows, 'r1'))?.id, 'a')
})
