import { test } from 'node:test'
import assert from 'node:assert/strict'
import { draftSource, playbookLifecycle, type PlaybookRevisionItem } from './playbookLifecycle.ts'
import { draftFromPlaybook } from './playbookForm.ts'

const rev = (n: number, status: PlaybookRevisionItem['status'], publishedAt: string | null = null): PlaybookRevisionItem => ({
  id: `r${n}`, revisionNumber: n, version: `1.${n - 1}`, status, publishedAt, createdBy: 'u-SOC', createdAt: `2026-10-0${n}T00:00:00Z`,
  content: { code: 'PB-X', name: `v${n}`, description: null, triggerConditions: { incidentType: 'X' }, playbookStatus: 'ACTIVE', version: `1.${n - 1}`, steps: [{ stepOrder: 1, title: 'a', description: null }] },
})

test('a never-published playbook is a Draft with Edit + Publish (and delete) for SOC / IR_TEAM', () => {
  for (const role of ['SOC', 'IR_TEAM']) {
    const l = playbookLifecycle([rev(1, 'DRAFT')], role)
    assert.equal(l.state, 'DRAFT')
    assert.equal(l.version, '1.0')
    assert.deepEqual(l.actions, ['view', 'edit', 'publish', 'delete'])
  }
})

test('a published playbook has no direct Edit: View + Create New Version (+ Rollback when an earlier version exists)', () => {
  const first = playbookLifecycle([rev(1, 'PUBLISHED', '2026-10-01')], 'SOC')
  assert.equal(first.state, 'PUBLISHED')
  assert.deepEqual(first.actions, ['view', 'createVersion'])
  const later = playbookLifecycle([rev(1, 'SUPERSEDED', '2026-10-01'), rev(2, 'PUBLISHED', '2026-10-02')], 'IR_TEAM')
  assert.deepEqual(later.actions, ['view', 'createVersion', 'rollback'])
  assert.equal(later.rollbackTo?.version, '1.0')
  assert.equal(later.version, '1.1')
})

test('after Create New Version the open draft gets Edit + Publish while the live version stays Published', () => {
  const l = playbookLifecycle([rev(1, 'PUBLISHED', '2026-10-01'), rev(2, 'DRAFT')], 'SOC')
  assert.equal(l.state, 'PUBLISHED')
  assert.equal(l.version, '1.0')
  assert.equal(l.draft?.version, '1.1')
  assert.deepEqual(l.actions, ['view', 'edit', 'publish'])
})

test('rollback goes to the most recently published earlier version; a never-published superseded row is ignored', () => {
  const l = playbookLifecycle([rev(1, 'SUPERSEDED', '2026-10-01'), rev(2, 'SUPERSEDED', '2026-10-03'), rev(3, 'PUBLISHED', '2026-10-04'), rev(4, 'SUPERSEDED')], 'SOC')
  assert.equal(l.rollbackTo?.id, 'r2')
})

test('no approval step anywhere; admin edits but never publishes or rolls back; other roles only view', () => {
  const all = [rev(1, 'SUPERSEDED', '2026-10-01'), rev(2, 'PUBLISHED', '2026-10-02'), rev(3, 'DRAFT')]
  assert.deepEqual(playbookLifecycle(all, 'admin').actions, ['view', 'edit'])
  assert.deepEqual(playbookLifecycle(all, 'VIEWER').actions, ['view'])
  assert.deepEqual(playbookLifecycle([rev(1, 'DRAFT')], 'admin').actions, ['view', 'edit', 'delete'])
  for (const role of ['SOC', 'IR_TEAM', 'admin', 'VIEWER']) {
    for (const a of playbookLifecycle(all, role).actions) assert.ok(!/approve|review|reject|submit/i.test(a))
  }
})

test('a legacy IN_REVIEW / APPROVED row is not treated as an editable draft', () => {
  const l = playbookLifecycle([rev(1, 'PUBLISHED', '2026-10-01'), rev(2, 'APPROVED')], 'SOC')
  assert.equal(l.draft, null)
  assert.deepEqual(l.actions, ['view', 'createVersion'])
})

test('the draft content loads into the playbook form (status = status once published)', () => {
  const r = rev(2, 'DRAFT')
  r.content.playbookStatus = 'DEPRECATED'
  const d = draftFromPlaybook(draftSource(r))
  assert.equal(d.name, 'v2')
  assert.equal(d.status, 'DEPRECATED')
  assert.equal(d.incidentType, 'X')
})
