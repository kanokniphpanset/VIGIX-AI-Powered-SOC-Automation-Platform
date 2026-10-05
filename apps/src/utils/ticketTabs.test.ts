import { test } from 'node:test'
import assert from 'node:assert/strict'
import { attentionCount, groupCount, groupOf, initialQueue, queueForGroup } from './ticketTabs.ts'

test('every backend queue belongs to one tab or to the "other status" filter', () => {
  assert.equal(groupOf('my-work'), 'my-work')
  assert.equal(groupOf('awaiting-decision'), 'awaiting-decision')
  for (const q of ['ready', 'in-progress', 'awaiting-rehunt'] as const) assert.equal(groupOf(q), 'active', q)
  assert.equal(groupOf('completed'), 'completed')
  for (const q of ['failed', 'escalated', 'rejected', 'all'] as const) assert.equal(groupOf(q), 'other', q)
})

test('the "in progress" tab counts its three queues and opens the first one with work', () => {
  const counts = { ready: 0, 'in-progress': 2, 'awaiting-rehunt': 5 }
  assert.equal(groupCount('active', counts), 7)
  assert.equal(queueForGroup('active', counts), 'in-progress')
  assert.equal(queueForGroup('active', {}), 'ready')
  assert.equal(queueForGroup('completed', counts), 'completed')
})

test('a count is unknown (null) until the backend returned it', () => {
  assert.equal(groupCount('completed', {}), null)
  assert.equal(groupCount('completed', { completed: 0 }), 0)
})

test('failed and escalated tickets raise the attention count', () => {
  assert.equal(attentionCount({ failed: 1, escalated: 2, rejected: 4 }), 3)
  assert.equal(attentionCount({}), 0)
})

test('links keep working and each role gets its default queue', () => {
  assert.equal(initialQueue('awaiting-rehunt', true), 'awaiting-rehunt')
  assert.equal(initialQueue('nope', true), 'my-work')
  assert.equal(initialQueue(undefined, false), 'all')
})
