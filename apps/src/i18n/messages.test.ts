import { test } from 'node:test'
import assert from 'node:assert/strict'
import { en, th, translate, type MsgKey } from './messages.ts'

const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort()

test('English has exactly the Thai keys, and no text is empty', () => {
  assert.deepEqual(Object.keys(en).sort(), Object.keys(th).sort())
  for (const [k, v] of [...Object.entries(th), ...Object.entries(en)]) assert.ok(v.trim(), `empty text for ${k}`)
})

test('both languages use the same placeholders for every key (a missing {n} would show a wrong number)', () => {
  for (const k of Object.keys(th) as MsgKey[]) assert.deepEqual(placeholders(en[k]), placeholders(th[k]), k)
})

test('translate fills placeholders and follows the chosen language', () => {
  assert.equal(translate('th', 'attn.slaBreached', { n: 3 }), '3 เคสเกิน SLA แล้ว')
  assert.equal(translate('en', 'attn.slaBreached', { n: 3 }), '3 cases breached SLA')
  assert.equal(translate('en', 'dash.sla.counts', { breached: 1, atRisk: 2, onTrack: 0 }), 'Breached 1 · At risk 2 · On track 0')
})

test('a placeholder without a value stays visible instead of disappearing', () => {
  assert.equal(translate('th', 'attn.slaBreached'), '{n} เคสเกิน SLA แล้ว')
})
