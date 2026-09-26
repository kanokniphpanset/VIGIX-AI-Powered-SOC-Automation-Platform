import { IVerificationRepository } from "../../../domain/verification/repositories/IVerificationRepository";
import { Verification } from "../../../domain/verification/entities/Verification.entity";

export class ListVerificationsUseCase {
  constructor(private readonly verificationRepository: IVerificationRepository) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Verification[]> {
    return this.verificationRepository.findAllByIncident(input.incidentId, input.tenantId);
  }
}
