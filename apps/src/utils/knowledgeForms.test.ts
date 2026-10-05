import { test } from 'node:test'
import assert from 'node:assert/strict'
import { emptyPolicyDraft, emptyRule, hasPolicyErrors, policyPayload, validatePolicyDraft, type PolicyDraft } from './policyForm.ts'
import { actionPayload, emptyActionDraft, hasActionErrors, validateActionDraft } from './actionForm.ts'

// RULE-I01 as seeded: LOW-severity alerts are stored but never open an incident.
const INTAKE: PolicyDraft = {
  code: ' rule-i99 ', name: ' Low Severity Alert Not In SOC Workflow ', description: '', type: 'INTAKE', precedence: '5',
  rules: [{ conditions: [{ field: 'severity', operator: 'eq', value: 'LOW' }], result: { autoCreateIncident: 'false', priority: '' } }],
}

test('policy payload matches the stored format (leaf condition, typed result, unset fields left out)', () => {
  assert.equal(hasPolicyErrors(validatePolicyDraft(INTAKE)), false)
  assert.deepEqual(policyPayload(INTAKE), {
    code: 'RULE-I99', name: 'Low Severity Alert Not In SOC Workflow', description: null, type: 'INTAKE', precedence: 5,
    rules: [{ condition: { field: 'severity', operator: 'eq', value: 'LOW' }, result: { autoCreateIncident: false } }],
  })
})

test('several conditions become { all }, flags become booleans, lists and numbers are typed', () => {
  const d: PolicyDraft = {
    ...INTAKE, type: 'APPROVAL',
    rules: [{
      conditions: [{ field: 'severity', operator: 'gte', value: 'HIGH' }, { field: 'spreadDetected', operator: 'eq', value: 'true' }],
      result: { approvalRequired: 'true', approvalChain: 'ir_team', approvalReason: 'High severity, spread', triageSlaMinutes: '30' },
    }],
  }
  assert.deepEqual((policyPayload(d).rules as unknown[])[0], {
    condition: { all: [{ field: 'severity', operator: 'gte', value: 'HIGH' }, { field: 'spreadDetected', operator: 'eq', value: true }] },
    result: { approvalRequired: true, approvalChain: ['IR_TEAM'], approvalReason: ['High severity', 'spread'], triageSlaMinutes: 30 },
  })
})

test('policy validation: code, name, type, precedence, and each rule needs a valid condition and a result', () => {
  const e = validatePolicyDraft(emptyPolicyDraft())
  assert.deepEqual({ code: e.code, name: e.name, type: e.type }, { code: 'polf.err.codeRequired', name: 'polf.err.nameRequired', type: 'polf.err.typeRequired' })
  assert.equal(e.rules?.[0], 'polf.err.condition', 'a condition without a value is flagged')
  assert.equal(validatePolicyDraft({ ...INTAKE, code: 'rule i99' }).code, 'polf.err.codeFormat')
  assert.equal(validatePolicyDraft(INTAKE, ['RULE-I99']).code, 'polf.err.codeDuplicate')
  assert.equal(validatePolicyDraft({ ...INTAKE, precedence: '1.5' }).precedence, 'polf.err.precedence')
  const noResult = { ...INTAKE, rules: [{ ...emptyRule(), conditions: [{ field: 'severity', operator: 'eq', value: 'LOW' }] }] }
  assert.equal(validatePolicyDraft(noResult).rules?.[0], 'polf.err.resultRequired')
  const badSla = { ...INTAKE, rules: [{ ...INTAKE.rules[0], result: { triageSlaMinutes: '-5' } }] }
  assert.equal(validatePolicyDraft(badSla).rules?.[0], 'polf.err.number')
  const fractionalTriage = { ...INTAKE, rules: [{ ...INTAKE.rules[0], result: { triageSlaMinutes: '1.5' } }] }
  assert.equal(validatePolicyDraft(fractionalTriage).rules?.[0], 'polf.err.number', 'the backend only accepts whole triage minutes')
  const fractionalFirstResponse = { ...INTAKE, rules: [{ ...INTAKE.rules[0], result: { firstResponseSlaMinutes: '1.5' } }] }
  assert.equal(validatePolicyDraft(fractionalFirstResponse).rules?.[0], undefined)
  const badChain = { ...INTAKE, rules: [{ ...INTAKE.rules[0], result: { approvalChain: 'MANAGER' } }] }
  assert.equal(validatePolicyDraft(badChain).rules?.[0], 'polf.err.chain')
})

test('action payload matches the stored format; runbook optional', () => {
  const d = { code: ' act-008 ', name: ' Isolate Host ', description: ' ', category: 'CONTAINMENT', impactLevel: 'HIGH', defaultApprovalRequired: true, runbookId: '' }
  assert.equal(hasActionErrors(validateActionDraft(d)), false)
  assert.deepEqual(actionPayload(d), { code: 'ACT-008', name: 'Isolate Host', description: null, category: 'CONTAINMENT', impactLevel: 'HIGH', defaultApprovalRequired: true, runbookId: null })
  assert.equal(actionPayload({ ...d, runbookId: 'rb-1' }).runbookId, 'rb-1')
})

test('action validation: code, name, category and impact are required; duplicate code caught', () => {
  assert.deepEqual(validateActionDraft(emptyActionDraft()), {
    code: 'actf.err.codeRequired', name: 'actf.err.nameRequired', category: 'actf.err.categoryRequired', impactLevel: 'actf.err.impactRequired',
  })
  const d = { ...emptyActionDraft(), code: 'act-007', name: 'x', category: 'INVESTIGATION', impactLevel: 'LOW' }
  assert.equal(validateActionDraft(d, ['ACT-007']).code, 'actf.err.codeDuplicate')
  assert.equal(validateActionDraft({ ...d, code: 'act 7' }).code, 'actf.err.codeFormat')
})
