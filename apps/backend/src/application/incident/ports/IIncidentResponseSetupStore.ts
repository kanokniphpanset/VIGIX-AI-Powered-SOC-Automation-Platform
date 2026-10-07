/** SOC guidance recorded on one incident before a Recommendation is created. */
export interface CaseGuidance {
  allowedActions: string[];
  instructions: string | null;
  setBy: string;
  setAt: string;
}

/**
 * The SOC's per-incident response setup: the confirmed incident type and the case guidance. Both are optional —
 * null means "detected from MITRE" / "the group policy (or the playbook default) applies".
 */
export interface IIncidentResponseSetupStore {
  get(incidentId: string, tenantId: string): Promise<{ severity: string; status: string; incidentType: string | null; guidance: CaseGuidance | null } | null>;
  setIncidentType(incidentId: string, tenantId: string, incidentType: string | null): Promise<void>;
  setGuidance(incidentId: string, tenantId: string, guidance: CaseGuidance | null): Promise<void>;
}
