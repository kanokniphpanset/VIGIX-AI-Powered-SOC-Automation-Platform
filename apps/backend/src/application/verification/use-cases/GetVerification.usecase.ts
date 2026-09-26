import { IVerificationRepository } from "../../../domain/verification/repositories/IVerificationRepository";
import { Verification } from "../../../domain/verification/entities/Verification.entity";
import { Result } from "../../../shared/result/Result";

export class GetVerificationUseCase {
  constructor(private readonly verificationRepository: IVerificationRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Verification, "NOT_FOUND">> {
    const verification = await this.verificationRepository.findById(input.id, input.tenantId);
    if (!verification) return Result.fail("NOT_FOUND");
    return Result.ok(verification);
  }
}
