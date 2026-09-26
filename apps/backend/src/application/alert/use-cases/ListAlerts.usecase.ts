import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { Result } from "../../../shared/result/Result";

export interface ListAlertsInput {
  tenantId: string;
  limit?: number;
  offset?: number;
  unlinked?: boolean;
}

export interface ListAlertsOutput {
  items: Alert[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * ListAlertsUseCase — application layer (Ring 2).
 * Depends only on IAlertRepository (a port), never on Prisma.
 */
export class ListAlertsUseCase {
  constructor(private readonly alertRepository: IAlertRepository) {}

  async execute(input: ListAlertsInput): Promise<Result<ListAlertsOutput>> {
    const limit = input.limit ?? 25;
    const offset = input.offset ?? 0;

    const [items, total] = await Promise.all([
      this.alertRepository.findAll(input.tenantId, limit, offset, { unlinked: input.unlinked }),
      this.alertRepository.countAll(input.tenantId, { unlinked: input.unlinked }),
    ]);

    return Result.ok({ items, total, limit, offset });
  }
}
