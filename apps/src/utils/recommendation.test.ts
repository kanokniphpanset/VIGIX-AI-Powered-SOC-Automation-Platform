// Run with `npm test` (node --test, native TypeScript). No network.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canGenerateRecommendation, generateButtonLabel, generateErrorMessage, initialGenerateState, runGenerate, type GenerateState } from './recommendation.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

test('no recommendation → "Generate Recommendation"; existing one → "Regenerate Recommendation"', () => {
  assert.equal(generateButtonLabel(initialGenerateState(), false), 'Generate Recommendation')
  assert.equal(generateButtonLabel(initialGenerateState(), true), 'Regenerate Recommendation')
})

test('the button calls the provided (existing) generate API exactly once and reports loading then success', async () => {
  let calls = 0
  const seen: GenerateState[] = []
  const final = await runGenerate(initialGenerateState(), async () => { calls++; return { recommendationNumber: 1 } }, (s) => seen.push(s))
  assert.equal(calls, 1)
  assert.deepEqual(seen.map((s) => s.status), ['running', 'success'])
  assert.equal(generateButtonLabel(seen[0], false), 'Generating...')
  assert.equal(final?.message, 'Recommendation #1 generated and validated.')
})

test('a click while generating is ignored — no second API call', async () => {
  let calls = 0
  const result = await runGenerate({ status: 'running', message: null }, async () => { calls++; return { recommendationNumber: 2 } }, () => {})
  assert.equal(result, null)
  assert.equal(calls, 0)
})

test('failure shows the backend error and allows a retry', async () => {
  const failed = await runGenerate(initialGenerateState(), async () => { throw Object.assign(new Error('INVALID_AI_OUTPUT'), { code: 'INVALID_AI_OUTPUT', status: 502 }) }, () => {})
  assert.equal(failed?.status, 'error')
  assert.match(failed?.message ?? '', /failed validation; nothing was saved/)
  // retry from the error state is allowed and can succeed
  const retried = await runGenerate(failed!, async () => ({ recommendationNumber: 1 }), () => {})
  assert.equal(retried?.status, 'success')
  assert.match(generateErrorMessage({ code: 'AI_UNAVAILABLE' }), /unavailable/)
  assert.equal(generateErrorMessage({ code: 'WEIRD' }), 'The backend refused the request (WEIRD).')
})

test('RBAC mirrors the backend: SOC, IR_TEAM and admin may generate; a retired MANAGER token and anonymous may not', () => {
  assert.deepEqual(['SOC', 'IR_TEAM', 'admin'].map(canGenerateRecommendation), [true, true, true])
  assert.deepEqual(['MANAGER', null, undefined].map(canGenerateRecommendation), [false, false, false])
})
