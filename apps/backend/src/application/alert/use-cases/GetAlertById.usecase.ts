import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { Result } from "../../../shared/result/Result";

export interface GetAlertByIdInput {
  id: string;
  tenantId: string;
}

export class GetAlertByIdUseCase {
  constructor(private readonly alertRepository: IAlertRepository) {}

  async execute(input: GetAlertByIdInput): Promise<Result<Alert, "NOT_FOUND">> {
    const alert = await this.alertRepository.findById(input.id, input.tenantId);
    if (!alert) {
      return Result.fail("NOT_FOUND");
    }
    return Result.ok(alert);
  }
}
