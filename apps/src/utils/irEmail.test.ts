// Run with `npm test` (node --test, native TypeScript). No network, no email.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { recipientProblem, runSend, sendErrorMessage, type IrEmailOutcome, type SendState } from './irEmail.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

const outcome = (o: Partial<IrEmailOutcome>): IrEmailOutcome => ({
  status: 'SENT', recipientRole: 'IR_TEAM', recipient: 'i***@corp.test', sentAt: '2026-09-24T01:02:03.000Z', deliveryId: 'd-1', error: null, ...o,
})

test('success: sending → sent, with the backend timestamp and status', async () => {
  const seen: SendState[] = []
  const final = await runSend(async () => outcome({}), (s) => seen.push(s))
  assert.deepEqual(seen.map((s) => s.status), ['sending', 'sent'])
  assert.equal(final.sentAt, '2026-09-24T01:02:03.000Z')
  assert.equal(final.deliveryStatus, 'SENT')
  assert.equal(final.recipient, 'i***@corp.test')
  assert.equal(final.message, null)
})

test('an API error (e.g. 502 DELIVERY_FAILED) is shown as an error, never as sent', async () => {
  const final = await runSend(async () => { throw Object.assign(new Error('DELIVERY_FAILED'), { code: 'DELIVERY_FAILED', status: 502 }) }, () => {})
  assert.equal(final.status, 'error')
  assert.equal(final.sentAt, null)
  assert.match(final.message ?? '', /did not accept/)
})

test('a non-SENT outcome is an error even if the request itself succeeded', async () => {
  const final = await runSend(async () => outcome({ status: 'NOT_SENT', sentAt: null, error: 'IR_TEAM_EMAIL_NOT_CONFIGURED' }), () => {})
  assert.equal(final.status, 'error')
  assert.match(final.message ?? '', /No IR Team email/)
})

test('error messages for known codes; unknown codes keep the code', () => {
  assert.match(sendErrorMessage({ code: 'FORBIDDEN' }), /not allowed/)
  assert.match(sendErrorMessage({ code: 'CHANNEL_NOT_CONFIGURED' }), /not configured on the server/)
  assert.equal(sendErrorMessage({ code: 'WEIRD' }), 'The email could not be sent (WEIRD).')
  assert.equal(sendErrorMessage(new TypeError('Failed to fetch')), 'The email could not be sent (UNKNOWN).')
})

test('a repeated request the backend recognised as a duplicate still shows the original success (nothing re-sent)', async () => {
  const final = await runSend(async () => outcome({ duplicate: true }), () => {})
  assert.equal(final.status, 'sent')
  assert.equal(final.sentAt, '2026-09-24T01:02:03.000Z')
})

test('DUPLICATE_IN_PROGRESS / RESPONSE_NOT_FOUND / FORBIDDEN errors are explained', () => {
  assert.match(sendErrorMessage({ code: 'DUPLICATE_IN_PROGRESS' }), /already being sent/)
  assert.match(sendErrorMessage({ code: 'RESPONSE_NOT_FOUND' }), /response ticket/)
  assert.match(sendErrorMessage({ code: 'HTTP_403' }), /not allowed/)
})

test('the dialog blocks sending when no IR email or no email channel is configured', () => {
  assert.match(recipientProblem({ recipient: null, emailChannelConfigured: true }) ?? '', /No IR Team email/)
  assert.match(recipientProblem({ recipient: 'i***@corp.test', emailChannelConfigured: false }) ?? '', /not configured on the server/)
  assert.equal(recipientProblem({ recipient: 'i***@corp.test', emailChannelConfigured: true }), null)
  assert.equal(recipientProblem(null), null)
})
