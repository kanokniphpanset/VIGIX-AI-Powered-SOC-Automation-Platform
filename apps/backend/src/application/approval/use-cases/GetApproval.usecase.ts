import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { Approval } from "../../../domain/approval/entities/Approval.entity";
import { Result } from "../../../shared/result/Result";

export class GetApprovalUseCase {
  constructor(private readonly approvalRepository: IApprovalRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Approval, "NOT_FOUND">> {
    const approval = await this.approvalRepository.findById(input.id, input.tenantId);
    if (!approval) return Result.fail("NOT_FOUND");
    return Result.ok(approval);
  }
}
