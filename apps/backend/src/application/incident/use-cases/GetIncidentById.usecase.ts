import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { Incident } from "../../../domain/incident/entities/Incident.entity";
import { Result } from "../../../shared/result/Result";

export interface GetIncidentByIdInput {
  id: string;
  tenantId: string;
}

export class GetIncidentByIdUseCase {
  constructor(private readonly incidentRepository: IIncidentRepository) {}

  async execute(input: GetIncidentByIdInput): Promise<Result<Incident, "NOT_FOUND">> {
    const incident = await this.incidentRepository.findById(input.id, input.tenantId);
    if (!incident) {
      return Result.fail("NOT_FOUND");
    }
    return Result.ok(incident);
  }
}
