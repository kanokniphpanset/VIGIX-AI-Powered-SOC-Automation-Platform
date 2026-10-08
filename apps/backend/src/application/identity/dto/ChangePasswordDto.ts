import { z } from "zod";

/**
 * Self-service password change. Strict: the account is always the authenticated user (JWT), so any identity field
 * (userId, email, tenantId, role, token) in the body is rejected as an unknown key (400). The upper bound only caps the
 * payload; the real length rule is the byte-based password policy below.
 */
export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1).max(1024),
    newPassword: z.string().min(1).max(1024),
    confirmPassword: z.string().min(1).max(1024),
  })
  .strict();

export type ChangePasswordDto = z.infer<typeof changePasswordSchema>;

export type PasswordPolicyRule = "MIN_BYTES" | "MAX_BYTES" | "CHARACTER_TYPES" | "SAME_AS_EMAIL";

/** bcrypt only uses the first 72 bytes, so the policy is measured in UTF-8 bytes, not string length. */
export const PASSWORD_MIN_BYTES = 12;
export const PASSWORD_MAX_BYTES = 72;
export const PASSWORD_MIN_CHARACTER_TYPES = 3;

const CHARACTER_TYPES = [/\p{Ll}/u, /\p{Lu}/u, /\p{Nd}/u, /[^\p{L}\p{Nd}\s]/u];

/** Rules the password breaks (empty = acceptable). Mirrored in the frontend for UX only. */
export function passwordPolicyViolations(password: string, email?: string | null): PasswordPolicyRule[] {
  const violations: PasswordPolicyRule[] = [];
  const bytes = Buffer.byteLength(password, "utf8");
  if (bytes < PASSWORD_MIN_BYTES) violations.push("MIN_BYTES");
  if (bytes > PASSWORD_MAX_BYTES) violations.push("MAX_BYTES");
  if (CHARACTER_TYPES.filter((re) => re.test(password)).length < PASSWORD_MIN_CHARACTER_TYPES) violations.push("CHARACTER_TYPES");
  if (email && password.trim().toLowerCase() === email.trim().toLowerCase()) violations.push("SAME_AS_EMAIL");
  return violations;
}
