import bcrypt from "bcryptjs";
import { PrismaAuthRepository } from "../../../infrastructure/database/postgres/repositories/AuthRepository.prisma";
import { Result } from "../../../shared/result/Result";
import { ChangeEmailDto, normalizeEmail } from "../dto/ChangeEmailDto";

export type ChangeEmailError =
  | { code: "USER_NOT_FOUND" }
  | { code: "CURRENT_PASSWORD_INCORRECT" }
  | { code: "EMAIL_UNCHANGED" }
  | { code: "EMAIL_TAKEN" };

/**
 * Changes the sign-in email of the authenticated user only: `userId` / `tenantId` come from the verified JWT, never from
 * the request, and the current password must match. Emails are unique across all users (users.email) and compared
 * case-insensitively. The new email and the EMAIL_CHANGED audit record (previous + new email, no password) commit
 * together. The JWT carries no email, so the session stays valid; the next sign-in uses the new email.
 * The per-role notification recipients (Settings → Integrations) are separate and are not changed here.
 */
export class ChangeEmailUseCase {
  constructor(private readonly authRepository: Pick<PrismaAuthRepository, "findCredentialById" | "emailInUse" | "updateEmail">) {}

  async execute(input: ChangeEmailDto & { userId: string; tenantId: string }): Promise<Result<{ changed: true; email: string }, ChangeEmailError>> {
    const user = await this.authRepository.findCredentialById(input.userId, input.tenantId);
    if (!user) return Result.fail({ code: "USER_NOT_FOUND" });
    if (!(await bcrypt.compare(input.currentPassword, user.passwordHash))) return Result.fail({ code: "CURRENT_PASSWORD_INCORRECT" });

    const email = normalizeEmail(input.newEmail);
    if (email === normalizeEmail(user.email)) return Result.fail({ code: "EMAIL_UNCHANGED" });
    if (await this.authRepository.emailInUse(email, user.id)) return Result.fail({ code: "EMAIL_TAKEN" });

    // A concurrent change to the same email loses on the unique index and is reported the same way.
    const updated = await this.authRepository.updateEmail(user.id, input.tenantId, email, user.email);
    if (updated === "EMAIL_TAKEN") return Result.fail({ code: "EMAIL_TAKEN" });
    return Result.ok({ changed: true, email });
  }
}
