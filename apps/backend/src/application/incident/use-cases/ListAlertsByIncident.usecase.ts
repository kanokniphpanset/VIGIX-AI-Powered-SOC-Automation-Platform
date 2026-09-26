import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { Result } from "../../../shared/result/Result";

/** Read-only: every alert grouped into the incident (incident_alerts plus the originating Incident.alertId). */
export class ListAlertsByIncidentUseCase {
  constructor(private readonly incidentRepository: IIncidentRepository) {}

  async execute(input: { incidentId: string; tenantId: string }): Promise<Result<Alert[], "INCIDENT_NOT_FOUND">> {
    const incident = await this.incidentRepository.findById(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    return Result.ok(await this.incidentRepository.findAlerts(input.incidentId, input.tenantId));
  }
}
