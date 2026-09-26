import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";

export interface ListResponsePlansInput {
  tenantId: string;
  limit?: number;
  offset?: number;
  /** Only this incident's plans (Incident Detail). */
  incidentId?: string;
}

export interface ListResponsePlansOutput {
  items: ResponsePlan[];
  total: number;
  limit: number;
  offset: number;
}

export class ListResponsePlansUseCase {
  constructor(private readonly responsePlanRepository: IResponsePlanRepository) {}

  async execute(input: ListResponsePlansInput): Promise<Result<ListResponsePlansOutput>> {
    const limit = input.limit ?? 25;
    const offset = input.offset ?? 0;

    const [items, total] = await Promise.all([
      this.responsePlanRepository.findAll(input.tenantId, limit, offset, input.incidentId),
      this.responsePlanRepository.countAll(input.tenantId, input.incidentId),
    ]);

    return Result.ok({ items, total, limit, offset });
  }
}
