import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { Approval } from "../../../domain/approval/entities/Approval.entity";

/** Wires the pre-existing IApprovalRepository.findByRecommendation() (already used
 * internally by earlier use-cases) to an HTTP-reachable read — no new repository logic. */
export class ListApprovalsByRecommendationUseCase {
  constructor(private readonly approvalRepository: IApprovalRepository) {}

  async execute(input: { recommendationId: string; tenantId: string }): Promise<Approval[]> {
    return this.approvalRepository.findByRecommendation(input.recommendationId, input.tenantId);
  }
}
