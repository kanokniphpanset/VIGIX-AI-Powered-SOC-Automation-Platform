import { test } from 'node:test'
import assert from 'node:assert/strict'
import { STATUS_TABS, STATUS_LABEL, agoText, available, durationText, incidentSla, reasonRequired, reviewDecisions, reviewSla, targetText } from './triage.ts'
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

test('the reason is optional for every decision', () => {
  for (const d of ['FALSE_POSITIVE', 'INFORMATIONAL', 'CREATE_INCIDENT'] as const) assert.equal(reasonRequired(d), false)
})

test('durations read as minutes, hours or days instead of raw minutes', () => {
  assert.equal(durationText(22), '22 min')
  assert.equal(durationText(185), '3 h 5 min')
  assert.equal(durationText(2 * 1440 + 250), '2 d 4 h')
  assert.equal(agoText(2880), '2 d 0 h ago')
})

const now = new Date('2026-09-29T10:00:00Z')
const inMin = (m: number) => new Date(now.getTime() + m * 60_000).toISOString()

test('SLA targets read in the plainest unit: minutes, hours, days or weeks', () => {
  assert.equal(targetText(15), '15 min')
  assert.equal(targetText(240), '4 h')
  assert.equal(targetText(90), '1 h 30 min')
  assert.equal(targetText(3 * 1440), '3 day(s)')
  assert.equal(targetText(10080), '1 week(s)')
  assert.equal(targetText(2400), '40 h')
})

const waiting = (dueInMin: number, startedMinAgo = 240) => ({ displayState: 'NEEDS_REVIEW', slaDueAt: inMin(dueInMin), receivedAt: inMin(-startedMinAgo), reviewAt: null, workflowState: 'NEW' })

test('review SLA is a target while the alert waits: "review within …" + deadline, never "overdue"', () => {
  assert.deepEqual(reviewSla(waiting(60, 180), now), { text: 'Review within 4 h', dueAt: inMin(60), doneAt: null, late: false })
  // Past the deadline: same target wording; only `late` changes (the view colours the deadline).
  const late = reviewSla(waiting(-30, 270), now)!
  assert.equal(late.text, 'Review within 4 h')
  assert.equal(late.late, true)
  assert.doesNotMatch(late.text, /overdue|breach|miss/i)
  // Reviewed (in an incident / closed) or no target: nothing shown.
  assert.equal(reviewSla({ ...waiting(-30), displayState: 'IN_INCIDENT' }, now), null)
  assert.equal(reviewSla({ ...waiting(-30), displayState: 'CLOSED' }, now), null)
  assert.equal(reviewSla({ ...waiting(0), slaDueAt: null }, now), null)
})

test('incident SLA lists both targets with deadlines and when each was done', () => {
  const clock = (targetMinutes: number, dueInMin: number, status: string, at: string | null = null) => ({ targetMinutes, dueAt: inMin(dueInMin), status, at })
  assert.deepEqual(incidentSla({ firstResponse: clock(240, -9, 'BREACHED'), resolution: clock(3 * 1440, 4000, 'ON_TRACK') }, now), [
    { text: 'Start responding within 4 h', dueAt: inMin(-9), doneAt: null, late: true },
    { text: 'Resolve within 3 day(s)', dueAt: inMin(4000), doneAt: null, late: false },
  ])
  const done = incidentSla({ firstResponse: clock(15, -5, 'MET', inMin(-20)), resolution: clock(240, 100, 'ON_TRACK') }, now)
  assert.equal(done[0].doneAt, inMin(-20))
  assert.equal(done[0].late, false)
  // The Policy wording wins over the plain duration: P2 / P3 targets read in business days.
  const policy = (targetMinutes: number, value: number, unit: 'minute' | 'hour' | 'business_day') => ({ targetMinutes, target: { value, unit }, dueAt: inMin(targetMinutes), status: 'ON_TRACK', at: null })
  assert.deepEqual(incidentSla({ firstResponse: policy(240, 4, 'hour'), resolution: policy(4320, 3, 'business_day') }, now).map((r) => r.text), ['Start responding within 4 h', 'Resolve within 3 business day(s)'])
  assert.deepEqual(incidentSla({ firstResponse: policy(1440, 1, 'business_day'), resolution: policy(10080, 5, 'business_day') }, now).map((r) => r.text), ['Start responding within 1 business day(s)', 'Resolve within 5 business days (1 week)'])
  assert.deepEqual(incidentSla({ firstResponse: policy(15, 15, 'minute'), resolution: null }, now).map((r) => r.text), ['Start responding within 15 min'])
  // Dismissed incident (cancelled clocks) or no Policy SLA: no targets.
  assert.deepEqual(incidentSla({ firstResponse: clock(15, 0, 'CANCELLED'), resolution: clock(240, 0, 'CANCELLED') }, now), [])
  assert.deepEqual(incidentSla(null, now), [])
})

test('missing values are explicit and zero remains visible', () => {
  for (const v of [null, undefined, '']) assert.equal(available(v), 'Not available')
  assert.equal(available(0), '0')
})
