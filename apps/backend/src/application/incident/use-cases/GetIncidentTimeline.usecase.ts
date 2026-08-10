import {
  IIncidentRepository,
  IncidentTimelineEntry,
} from "../../../domain/incident/repositories/IIncidentRepository";
import { Result } from "../../../shared/result/Result";

export interface GetIncidentTimelineInput {
  incidentId: string;
  tenantId: string;
}

export class GetIncidentTimelineUseCase {
  constructor(private readonly incidentRepository: IIncidentRepository) {}

  async execute(
    input: GetIncidentTimelineInput
  ): Promise<Result<IncidentTimelineEntry[], "NOT_FOUND">> {
    const incident = await this.incidentRepository.findById(input.incidentId, input.tenantId);
    if (!incident) {
      return Result.fail("NOT_FOUND");
    }
    const timeline = await this.incidentRepository.findTimeline(input.incidentId);
    return Result.ok(timeline);
  }
}
