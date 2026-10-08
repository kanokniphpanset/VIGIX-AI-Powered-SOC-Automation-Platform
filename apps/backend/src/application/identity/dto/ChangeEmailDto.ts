import { z } from "zod";

/**
 * Self-service email change. Strict like ChangePasswordDto: the account is always the authenticated user (JWT), so any
 * identity field (userId, email, tenantId, role, token) in the body is rejected as an unknown key (400). The current
 * password is required so a hijacked session alone cannot move the sign-in email (account takeover).
 */
export const changeEmailSchema = z
  .object({
    newEmail: z.string().trim().max(254).email(),
    currentPassword: z.string().min(1).max(1024),
  })
  .strict();

export type ChangeEmailDto = z.infer<typeof changeEmailSchema>;

/** Sign-in emails are stored trimmed and lower-cased; login looks them up exactly. */
export const normalizeEmail = (email: string) => email.trim().toLowerCase();
