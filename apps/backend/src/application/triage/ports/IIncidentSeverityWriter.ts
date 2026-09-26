import { Severity } from "../../../domain/policy/entities/PolicyEvaluationTypes";

/**
 * Writes an analyst-validated incident severity (incidents.priority holds the incident severity: low..critical) and
 * the matching timeline entry. Used only by ValidateIncidentSeverityUseCase — AI never calls it.
 */
export interface IIncidentSeverityWriter {
  setSeverity(input: { tenantId: string; incidentId: string; severity: Severity; actor: string; description: string }): Promise<void>;
  /** Statuses of the incident's response tickets (used to lock severity changes mid-approval / mid-execution). */
  ticketStatuses(tenantId: string, incidentId: string): Promise<string[]>;
}
