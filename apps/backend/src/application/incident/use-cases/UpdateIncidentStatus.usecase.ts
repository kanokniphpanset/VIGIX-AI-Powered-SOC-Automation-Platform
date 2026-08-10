import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { Incident, IncidentStatus } from "../../../domain/incident/entities/Incident.entity";
import { Result } from "../../../shared/result/Result";

const VALID_STATUSES: IncidentStatus[] = ["open", "investigating", "resolved", "dismissed"];

export interface UpdateIncidentStatusInput {
  id: string;
  tenantId: string;
  status: string;
}

export class UpdateIncidentStatusUseCase {
  constructor(private readonly incidentRepository: IIncidentRepository) {}

  async execute(
    input: UpdateIncidentStatusInput
  ): Promise<Result<Incident, "NOT_FOUND" | "INVALID_STATUS">> {
    if (!VALID_STATUSES.includes(input.status as IncidentStatus)) {
      return Result.fail("INVALID_STATUS");
    }

    const existing = await this.incidentRepository.findById(input.id, input.tenantId);
    if (!existing) {
      return Result.fail("NOT_FOUND");
    }

    const updated = await this.incidentRepository.updateStatus(
      input.id,
      input.tenantId,
      input.status as IncidentStatus
    );
    return Result.ok(updated);
  }
}
