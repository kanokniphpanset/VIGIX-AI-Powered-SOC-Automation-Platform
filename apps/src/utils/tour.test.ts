import { test } from 'node:test'
import assert from 'node:assert/strict'
import { cardPosition, tourSeenKey, tourSteps } from './tour.ts'
import { th } from '../i18n/messages.ts'

test('each role gets its own short tour that starts with a welcome and ends with help + language', () => {
  for (const role of ['SOC', 'IR_TEAM', 'admin', null]) {
    const steps = tourSteps(role)
    assert.ok(steps.length <= 7, 'tour stays short')
    assert.equal(steps[0].target, null)
    assert.deepEqual(steps.slice(-2).map((s) => s.key), ['help', 'lang'])
  }
  assert.ok(tourSteps('SOC').some((s) => s.key === 'nav-alerts'))
  assert.ok(!tourSteps('SOC').some((s) => s.key === 'nav-tickets')) // SOC has no Response Tickets menu
  assert.ok(tourSteps('IR_TEAM').some((s) => s.key === 'nav-tickets'))
})

test('every tour step has its text', () => {
  for (const role of ['SOC', 'IR_TEAM', 'admin'])
    for (const s of tourSteps(role)) {
      assert.ok(`tour.${s.key}.title` in th, s.key)
      assert.ok(`tour.${s.key}.body` in th, s.key)
    }
})

test('"seen" is remembered per user', () => {
  assert.equal(tourSeenKey('SOC@x.local'), 'vigix.tour.v1.soc@x.local')
  assert.notEqual(tourSeenKey('a@x'), tourSeenKey('b@x'))
})

test('the card goes right of the target, else below, else centred (null)', () => {
  const vp = { width: 1200, height: 800 }
  const c = { width: 320, height: 200 }
  assert.deepEqual(cardPosition({ top: 100, left: 10, right: 250, bottom: 140 }, vp, c), { top: 100, left: 266 })
  assert.deepEqual(cardPosition({ top: 100, left: 700, right: 1150, bottom: 300 }, vp, c), { top: 316, left: 700 })
  assert.equal(cardPosition({ top: 16, left: 0, right: 1200, bottom: 790 }, vp, c), null)
  assert.equal(cardPosition(null, vp, c), null)
})
