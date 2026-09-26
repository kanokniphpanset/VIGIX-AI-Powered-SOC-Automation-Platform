import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";

export class GetResponseUseCase {
  constructor(private readonly responsePlanRepository: IResponsePlanRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<ResponsePlan, "NOT_FOUND">> {
    const response = await this.responsePlanRepository.findById(input.id, input.tenantId);
    if (!response) return Result.fail("NOT_FOUND");
    return Result.ok(response);
  }
}
