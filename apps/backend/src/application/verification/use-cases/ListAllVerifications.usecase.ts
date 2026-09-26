import { IVerificationRepository } from "../../../domain/verification/repositories/IVerificationRepository";
import { Verification } from "../../../domain/verification/entities/Verification.entity";

/** Tenant-wide (not incident-scoped — see ListVerifications.usecase.ts for that).
 * Powers the Response Operations Dashboard's "Awaiting Verification" count. */
export class ListAllVerificationsUseCase {
  constructor(private readonly verificationRepository: IVerificationRepository) {}

  async execute(input: { tenantId: string; limit?: number; offset?: number }): Promise<Verification[]> {
    return this.verificationRepository.findAll(input.tenantId, input.limit, input.offset);
  }
}
