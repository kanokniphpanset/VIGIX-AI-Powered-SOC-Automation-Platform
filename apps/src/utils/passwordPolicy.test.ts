import { test } from 'node:test'
import assert from 'node:assert/strict'
import { hasChangePasswordErrors, passwordBytes, passwordPolicyViolations, validateChangePassword } from './passwordPolicy.ts'

test('length is measured in UTF-8 bytes: 12 to 72 bytes', () => {
  assert.deepEqual(passwordPolicyViolations('Abcdef1!ghij'), [])
  assert.deepEqual(passwordPolicyViolations(`Aa1!${'x'.repeat(68)}`), [])
  assert.deepEqual(passwordPolicyViolations('Sh0rt!pass'), ['MIN_BYTES'])
  assert.deepEqual(passwordPolicyViolations(`Aa1!${'x'.repeat(69)}`), ['MAX_BYTES'])
  const thai = `Aa1${'ก'.repeat(25)}` // 28 characters, 78 bytes
  assert.equal(thai.length, 28)
  assert.equal(passwordBytes(thai), 78)
  assert.deepEqual(passwordPolicyViolations(thai), ['MAX_BYTES'])
})

test('at least 3 of 4 character types (lowercase, uppercase, number, symbol)', () => {
  assert.deepEqual(passwordPolicyViolations('lowercaseonly123'), ['CHARACTER_TYPES'])
  assert.deepEqual(passwordPolicyViolations('lowercase-symbol-1'), [])
  assert.deepEqual(passwordPolicyViolations('UPPER-lower-only'), [])
  assert.deepEqual(passwordPolicyViolations('abcdefghijklmn'), ['CHARACTER_TYPES'])
})

test('must not equal the email (case-insensitive)', () => {
  assert.deepEqual(passwordPolicyViolations('analyst.one2026@VIGIX.test', 'Analyst.One2026@vigix.test'), ['SAME_AS_EMAIL'])
  assert.deepEqual(passwordPolicyViolations('analyst.one2026@VIGIX.test', 'someone@vigix.test'), [])
})

test('form validation: required fields, policy, unchanged password and confirmation', () => {
  assert.deepEqual(validateChangePassword({ currentPassword: '', newPassword: '', confirmPassword: '' }), {
    currentPassword: ['currentRequired'], newPassword: ['newRequired'], confirmPassword: ['confirmRequired'],
  })
  assert.deepEqual(validateChangePassword({ currentPassword: 'Old-Passw0rd-2026', newPassword: 'New-Passw0rd-2026', confirmPassword: 'New-Passw0rd-2027' }), { confirmPassword: ['mismatch'] })
  assert.deepEqual(validateChangePassword({ currentPassword: 'Old-Passw0rd-2026', newPassword: 'Old-Passw0rd-2026', confirmPassword: 'Old-Passw0rd-2026' }), { newPassword: ['UNCHANGED'] })
  assert.deepEqual(validateChangePassword({ currentPassword: 'x', newPassword: 'short', confirmPassword: 'short' }), { newPassword: ['MIN_BYTES', 'CHARACTER_TYPES'] })
  const ok = validateChangePassword({ currentPassword: 'Old-Passw0rd-2026', newPassword: 'New-Passw0rd-2026', confirmPassword: 'New-Passw0rd-2026' }, 'soc@vigix.test')
  assert.equal(hasChangePasswordErrors(ok), false)
})
