import { test } from 'node:test'
import assert from 'node:assert/strict'
import { INCIDENT_TABS, resolveTab, tabForStep } from './incidentTabs.ts'

test('every former tab name still opens the tab that now holds its content', () => {
  assert.deepEqual(resolveTab('investigation'), { tab: 'evidence', anchor: 'sec-investigation' })
  assert.deepEqual(resolveTab('recommendation'), { tab: 'ai', anchor: 'sec-recommendation' })
  assert.deepEqual(resolveTab('verification'), { tab: 'history', anchor: 'sec-verification' })
  assert.deepEqual(resolveTab('email'), { tab: 'history', anchor: 'sec-email' })
  assert.deepEqual(resolveTab('audit'), { tab: 'history', anchor: 'sec-audit' })
  for (const t of INCIDENT_TABS) assert.equal(resolveTab(t)?.tab, t)
})

test('unknown or missing tab names are ignored', () => {
  assert.equal(resolveTab('nope'), null)
  assert.equal(resolveTab(undefined), null)
  assert.equal(resolveTab(['audit']), null)
  assert.equal(resolveTab('toString'), null)
})

test('the first tab follows the current step', () => {
  assert.equal(tabForStep('soc-severity'), 'overview')
  for (const k of ['soc-ai', 'soc-recommend', 'soc-regenerate', 'soc-send', 'soc-noaction', 'soc-rejected', 'soc-failed'] as const) assert.equal(tabForStep(k), 'ai', k)
  for (const k of ['ir-decide', 'ir-start', 'ir-complete'] as const) assert.equal(tabForStep(k), 'overview', k)
  for (const k of ['ir-rehunt', 'resolved', 'dismissed', 'escalated'] as const) assert.equal(tabForStep(k), 'history', k)
  assert.equal(tabForStep(null), 'overview')
})
