import { test } from 'node:test'
import assert from 'node:assert/strict'
import { draftFromPlaybook, emptyPlaybookDraft, hasErrors, playbookPayload, validatePlaybookDraft } from './playbookForm.ts'

const STORED = {
  id: 'pb-ssh', code: 'PB-SSH-BRUTEFORCE', name: 'SSH Brute Force Response', description: null, status: 'ACTIVE', version: '1.0',
  triggerConditions: { scope: 'INCIDENT', incidentType: 'SSH_BRUTE_FORCE', mitreTechniques: ['T1110'] },
  steps: [{ stepOrder: 2, title: 'Reset', description: null }, { stepOrder: 1, title: 'Block', description: 'at the edge' }],
}

test('a stored playbook becomes a draft with ordered steps and its incident type', () => {
  assert.deepEqual(draftFromPlaybook(STORED), {
    code: 'PB-SSH-BRUTEFORCE', name: 'SSH Brute Force Response', description: '', incidentType: 'SSH_BRUTE_FORCE', status: 'ACTIVE',
    steps: [{ title: 'Block', description: 'at the edge' }, { title: 'Reset', description: '' }],
  })
})

test('required fields: code (create), name, at least one step', () => {
  const e = validatePlaybookDraft(emptyPlaybookDraft(), true)
  assert.deepEqual({ code: e.code, name: e.name, steps: e.steps }, { code: 'pbf.err.codeRequired', name: 'pbf.err.nameRequired', steps: 'pbf.err.stepsRequired' })
  assert.equal(validatePlaybookDraft(emptyPlaybookDraft(), false).code, undefined, 'code is not edited after creation')
})

test('code format and duplicate code are caught before sending', () => {
  const d = { ...emptyPlaybookDraft(), name: 'X', steps: [{ title: 'a', description: '' }] }
  assert.equal(validatePlaybookDraft({ ...d, code: 'pb ssh' }, true).code, 'pbf.err.codeFormat')
  assert.equal(validatePlaybookDraft({ ...d, code: 'pb-ssh-bruteforce' }, true, ['PB-SSH-BRUTEFORCE']).code, 'pbf.err.codeDuplicate')
  assert.equal(hasErrors(validatePlaybookDraft({ ...d, code: 'pb-new' }, true, ['PB-SSH-BRUTEFORCE'])), false)
})

test('incident type must be an UPPER_SNAKE category; a step with text but no title is flagged', () => {
  const d = { ...emptyPlaybookDraft(), code: 'PB-A', name: 'A', steps: [{ title: 'ok', description: '' }, { title: ' ', description: 'orphan text' }] }
  const e = validatePlaybookDraft({ ...d, incidentType: 'ssh brute-force' }, true)
  assert.equal(e.incidentType, 'pbf.err.incidentType')
  assert.deepEqual(e.stepTitles, [1])
})

test('payload: trimmed, empty rows dropped, steps renumbered, code only on create', () => {
  const d = { code: ' pb-test ', name: ' Test ', description: ' ', incidentType: 'test_case', status: 'DEPRECATED' as const, steps: [{ title: ' First ', description: '' }, { title: '', description: '' }, { title: 'Second', description: 'why' }] }
  assert.deepEqual(playbookPayload(d, true), {
    code: 'PB-TEST', name: 'Test', description: null, incidentType: 'TEST_CASE', status: 'DEPRECATED',
    steps: [{ stepOrder: 1, title: 'First', description: null }, { stepOrder: 2, title: 'Second', description: 'why' }],
  })
  assert.equal('code' in playbookPayload(d, false), false)
})
