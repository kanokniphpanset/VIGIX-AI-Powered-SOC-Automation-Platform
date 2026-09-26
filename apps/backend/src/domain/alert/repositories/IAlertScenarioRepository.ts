export interface AlertScenarioTagRecord {
  alertId: string;
  scenarioId: string;
  taggedBy: string | null;
  taggedAt: Date;
}

/** Analyst-set test-scenario label per alert (alert_scenario_tags). */
export interface IAlertScenarioRepository {
  findByAlertIds(alertIds: string[], tenantId: string): Promise<Map<string, AlertScenarioTagRecord>>;
  set(alertId: string, tenantId: string, scenarioId: string, taggedBy: string): Promise<AlertScenarioTagRecord>;
  clear(alertId: string, tenantId: string): Promise<void>;
}
