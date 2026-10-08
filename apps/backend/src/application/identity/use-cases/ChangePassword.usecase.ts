import bcrypt from "bcryptjs";
import { PrismaAuthRepository } from "../../../infrastructure/database/postgres/repositories/AuthRepository.prisma";
import { Result } from "../../../shared/result/Result";
import { ChangePasswordDto, PasswordPolicyRule, passwordPolicyViolations } from "../dto/ChangePasswordDto";

export type ChangePasswordError =
  | { code: "PASSWORD_CONFIRMATION_MISMATCH" }
  | { code: "PASSWORD_POLICY_VIOLATION"; rules: PasswordPolicyRule[] }
  | { code: "USER_NOT_FOUND" }
  | { code: "CURRENT_PASSWORD_INCORRECT" }
  | { code: "PASSWORD_UNCHANGED" };

/** Same cost as the seeded accounts (prisma/seed.ts). */
const BCRYPT_COST = 10;

/**
 * Changes the password of the authenticated user only: `userId` / `tenantId` come from the verified JWT, never from
 * the request. The new hash and the PASSWORD_CHANGED audit record commit together. Existing JWTs stay valid until
 * they expire (no revocation yet); the response tells the client to sign in again. No password value is ever logged,
 * audited or returned.
 */
export class ChangePasswordUseCase {
  constructor(private readonly authRepository: Pick<PrismaAuthRepository, "findCredentialById" | "updatePasswordHash">) {}

  async execute(input: ChangePasswordDto & { userId: string; tenantId: string }): Promise<Result<{ changed: true; reauthRequired: true }, ChangePasswordError>> {
    if (input.newPassword !== input.confirmPassword) return Result.fail({ code: "PASSWORD_CONFIRMATION_MISMATCH" });
    const policy = passwordPolicyViolations(input.newPassword);
    if (policy.length) return Result.fail({ code: "PASSWORD_POLICY_VIOLATION", rules: policy });

    const user = await this.authRepository.findCredentialById(input.userId, input.tenantId);
    if (!user) return Result.fail({ code: "USER_NOT_FOUND" });
    const emailRule = passwordPolicyViolations(input.newPassword, user.email).filter((r) => r === "SAME_AS_EMAIL");
    if (emailRule.length) return Result.fail({ code: "PASSWORD_POLICY_VIOLATION", rules: emailRule });

    if (!(await bcrypt.compare(input.currentPassword, user.passwordHash))) return Result.fail({ code: "CURRENT_PASSWORD_INCORRECT" });
    if (input.newPassword === input.currentPassword) return Result.fail({ code: "PASSWORD_UNCHANGED" });

    const passwordHash = await bcrypt.hash(input.newPassword, BCRYPT_COST);
    await this.authRepository.updatePasswordHash(user.id, input.tenantId, passwordHash);
    return Result.ok({ changed: true, reauthRequired: true });
  }
}
