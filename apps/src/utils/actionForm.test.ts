import { test } from 'node:test'
import assert from 'node:assert/strict'
import { actionGovernanceBody, canSetActionGovernance, initialActionGovernance } from './actionForm.ts'

const LOW_FORM = { impactLevel: 'LOW', defaultApprovalRequired: false }

test('only admin may set the impact level and approval requirement', () => {
  assert.equal(canSetActionGovernance('admin'), true)
  for (const role of ['SOC', 'IR_TEAM', 'VIEWER', null]) assert.equal(canSetActionGovernance(role), false)
})

test('SOC / IR_TEAM creating: the form starts at HIGH + approval required and sends exactly that', () => {
  for (const role of ['SOC', 'IR_TEAM']) {
    assert.deepEqual(initialActionGovernance(role, true), { impactLevel: 'HIGH', defaultApprovalRequired: true })
    // Even if the form state were tampered with, the body only ever carries the accepted values.
    assert.deepEqual(actionGovernanceBody(role, true, LOW_FORM), { impactLevel: 'HIGH', defaultApprovalRequired: true })
  }
})

test('SOC / IR_TEAM editing: shows the stored values and sends neither field', () => {
  for (const role of ['SOC', 'IR_TEAM']) {
    assert.deepEqual(initialActionGovernance(role, false, { impactLevel: 'MEDIUM', defaultApprovalRequired: false }), { impactLevel: 'MEDIUM', defaultApprovalRequired: false })
    assert.deepEqual(actionGovernanceBody(role, false, LOW_FORM), {})
  }
})

test('admin creating or editing: starts from the stored values (LOW / false for a new action) and sends what the form holds', () => {
  assert.deepEqual(initialActionGovernance('admin', true), { impactLevel: 'LOW', defaultApprovalRequired: false })
  assert.deepEqual(initialActionGovernance('admin', false, { impactLevel: 'HIGH', defaultApprovalRequired: true }), { impactLevel: 'HIGH', defaultApprovalRequired: true })
  for (const creating of [true, false]) {
    assert.deepEqual(actionGovernanceBody('admin', creating, LOW_FORM), LOW_FORM)
    assert.deepEqual(actionGovernanceBody('admin', creating, { impactLevel: 'MEDIUM', defaultApprovalRequired: true }), { impactLevel: 'MEDIUM', defaultApprovalRequired: true })
  }
})
