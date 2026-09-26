// Run with `npm test` (node --test, native TypeScript). No network.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { aiButtonLabel, aiRunErrorMessage, hasAiAnalysis, initialAiRunState, runAiAnalysis, type AiRunState, type RunAiAnalysisResult } from './aiAnalysis.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

const result = (o: Partial<RunAiAnalysisResult> = {}): RunAiAnalysisResult => ({
  incidentId: 'inc-1', graphRunId: 'exec-1', status: 'SUCCESS', rerun: false, analysis: { summary: 's', keyFindings: [] }, ...o,
})

test('"Run AI Analysis" when the incident has no analysis yet', () => {
  assert.equal(aiButtonLabel(initialAiRunState(), null), 'Run AI Analysis')
  assert.equal(aiButtonLabel(initialAiRunState(), { summary: null }), 'Run AI Analysis')
  assert.equal(hasAiAnalysis({ summary: null }), false)
})

test('"Re-run AI Analysis" when an analysis exists', () => {
  assert.equal(aiButtonLabel(initialAiRunState(), { summary: 'LLM summary' }), 'Re-run AI Analysis')
})

test('"Analyzing..." while running, then success with the backend result', async () => {
  const seen: AiRunState[] = []
  const final = await runAiAnalysis(async () => result({ rerun: true }), (s) => seen.push(s))
  assert.deepEqual(seen.map((s) => s.status), ['running', 'success'])
  assert.equal(aiButtonLabel(seen[0], { summary: 's' }), 'Analyzing...')
  assert.equal(final.message, 'AI analysis re-run')
  assert.equal(/severity/i.test(final.message ?? ''), false) // the AI never reports a severity
})

test('partial success is reported as such', async () => {
  const final = await runAiAnalysis(async () => result({ status: 'PARTIAL_SUCCESS' }), () => {})
  assert.equal(final.status, 'success')
  assert.match(final.message ?? '', /some agents reported errors/)
})

test('error state: orchestrator unavailable / already running / forbidden — never shown as success', async () => {
  const down = await runAiAnalysis(async () => { throw Object.assign(new Error('AI_UNAVAILABLE'), { code: 'AI_UNAVAILABLE', status: 503 }) }, () => {})
  assert.equal(down.status, 'error')
  assert.match(down.message ?? '', /unavailable/)
  assert.match(aiRunErrorMessage({ code: 'ANALYSIS_IN_PROGRESS' }), /already running/)
  assert.match(aiRunErrorMessage({ code: 'HTTP_403' }), /not allowed/)
  assert.equal(aiRunErrorMessage({ code: 'WEIRD' }), 'The AI analysis could not be run (WEIRD).')
})
