// Password policy for Settings → Security → Change password. Pure; runs under `node --test`. Mirrors the backend
// (application/identity/dto/ChangePasswordDto.ts), which is the real check — this only gives clear messages before
// sending. Length is measured in UTF-8 bytes because bcrypt only uses the first 72 bytes.

export type PasswordPolicyRule = 'MIN_BYTES' | 'MAX_BYTES' | 'CHARACTER_TYPES' | 'SAME_AS_EMAIL'

export const PASSWORD_MIN_BYTES = 12
export const PASSWORD_MAX_BYTES = 72
export const PASSWORD_MIN_CHARACTER_TYPES = 3

const CHARACTER_TYPES = [/\p{Ll}/u, /\p{Lu}/u, /\p{Nd}/u, /[^\p{L}\p{Nd}\s]/u]

export const passwordBytes = (password: string) => new TextEncoder().encode(password).length

/** Rules the password breaks (empty = acceptable). */
export function passwordPolicyViolations(password: string, email?: string | null): PasswordPolicyRule[] {
  const violations: PasswordPolicyRule[] = []
  const bytes = passwordBytes(password)
  if (bytes < PASSWORD_MIN_BYTES) violations.push('MIN_BYTES')
  if (bytes > PASSWORD_MAX_BYTES) violations.push('MAX_BYTES')
  if (CHARACTER_TYPES.filter((re) => re.test(password)).length < PASSWORD_MIN_CHARACTER_TYPES) violations.push('CHARACTER_TYPES')
  if (email && password.trim().toLowerCase() === email.trim().toLowerCase()) violations.push('SAME_AS_EMAIL')
  return violations
}

export interface ChangePasswordForm { currentPassword: string; newPassword: string; confirmPassword: string }
export type ChangePasswordFieldErrors = Partial<Record<'currentPassword' | 'newPassword' | 'confirmPassword', string[]>>

/** Field → message keys (without the i18n prefix); empty when the form can be sent. */
export function validateChangePassword(form: ChangePasswordForm, email?: string | null): ChangePasswordFieldErrors {
  const errors: ChangePasswordFieldErrors = {}
  if (!form.currentPassword) errors.currentPassword = ['currentRequired']
  if (!form.newPassword) errors.newPassword = ['newRequired']
  else {
    const rules = passwordPolicyViolations(form.newPassword, email)
    if (form.currentPassword && form.newPassword === form.currentPassword) rules.push('UNCHANGED' as PasswordPolicyRule)
    if (rules.length) errors.newPassword = rules
  }
  if (!form.confirmPassword) errors.confirmPassword = ['confirmRequired']
  else if (form.newPassword && form.confirmPassword !== form.newPassword) errors.confirmPassword = ['mismatch']
  return errors
}

export const hasChangePasswordErrors = (e: ChangePasswordFieldErrors) => Object.keys(e).length > 0
