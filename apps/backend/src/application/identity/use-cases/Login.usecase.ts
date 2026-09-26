import bcrypt from "bcryptjs";
import { PrismaAuthRepository } from "../../../infrastructure/database/postgres/repositories/AuthRepository.prisma";
import { signToken } from "../../../presentation/http/middlewares/auth.middleware";
import { Result } from "../../../shared/result/Result";

export interface LoginOutput {
  token: string;
  role: string;
  tenantId: string;
}

export class LoginUseCase {
  constructor(private readonly authRepository: PrismaAuthRepository) {}

  async execute(input: { email: string; password: string }): Promise<Result<LoginOutput, "INVALID_CREDENTIALS">> {
    const user = await this.authRepository.findByEmail(input.email);
    if (!user) return Result.fail("INVALID_CREDENTIALS");

    const passwordMatches = await bcrypt.compare(input.password, user.passwordHash);
    if (!passwordMatches) return Result.fail("INVALID_CREDENTIALS");

    const token = signToken({ id: user.id, tenantId: user.tenantId, role: user.role });
    return Result.ok({ token, role: user.role, tenantId: user.tenantId });
  }
}
