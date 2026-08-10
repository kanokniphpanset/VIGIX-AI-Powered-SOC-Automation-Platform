import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { Incident } from "../../../domain/incident/entities/Incident.entity";
import { Result } from "../../../shared/result/Result";

export interface ListIncidentsInput {
  tenantId: string;
  limit?: number;
  offset?: number;
}

export interface ListIncidentsOutput {
  items: Incident[];
  total: number;
  limit: number;
  offset: number;
}

export class ListIncidentsUseCase {
  constructor(private readonly incidentRepository: IIncidentRepository) {}

  async execute(input: ListIncidentsInput): Promise<Result<ListIncidentsOutput>> {
    const limit = input.limit ?? 25;
    const offset = input.offset ?? 0;

    const [items, total] = await Promise.all([
      this.incidentRepository.findAll(input.tenantId, limit, offset),
      this.incidentRepository.countAll(input.tenantId),
    ]);

    return Result.ok({ items, total, limit, offset });
  }
}
