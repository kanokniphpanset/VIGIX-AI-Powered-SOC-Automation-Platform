import { test } from 'node:test'
import assert from 'node:assert/strict'
import { STATUS_TABS, STATUS_LABEL, available, reasonRequired, reviewDecisions } from './triage.ts'
import { setLocale } from '../i18n/locale.ts'

// These assertions check the English wording (the UI default is Thai; Thai text is covered by i18n/locale.test.ts).
setLocale('en')

test('status filter: All first; no claim / owner / monitoring queue', () => {
  assert.deepEqual(STATUS_TABS.map(([k]) => k), ['all', 'needs-review', 'in-incident', 'closed'])
  assert.equal(JSON.stringify(STATUS_TABS).toLowerCase().includes('claim'), false)
  assert.equal(Object.keys(STATUS_LABEL).includes('CLAIMED'), false)
})

test('MEDIUM: SOC reviews — create an incident or close it; HIGH / CRITICAL can only become an incident', () => {
  assert.deepEqual(reviewDecisions({ severity: 'medium', actionable: true }), ['CREATE_INCIDENT', 'FALSE_POSITIVE', 'INFORMATIONAL'])
  for (const severity of ['high', 'critical', 'HIGH']) assert.deepEqual(reviewDecisions({ severity, actionable: true }), ['CREATE_INCIDENT'])
})

test('decided / in-incident / LOW alerts offer no decision', () => {
  assert.deepEqual(reviewDecisions({ severity: 'medium', actionable: false }), [])
  assert.deepEqual(reviewDecisions({ severity: 'low', actionable: false }), [])
})

test('closing needs a reason; creating the incident does not (it keeps the Wazuh severity)', () => {
  assert.equal(reasonRequired('FALSE_POSITIVE'), true)
  assert.equal(reasonRequired('INFORMATIONAL'), true)
  assert.equal(reasonRequired('CREATE_INCIDENT'), false)
})

test('missing values are explicit and zero remains visible', () => {
  for (const v of [null, undefined, '']) assert.equal(available(v), 'Not available')
  assert.equal(available(0), '0')
})
