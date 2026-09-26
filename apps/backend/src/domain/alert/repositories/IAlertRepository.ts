import { Alert, AlertStatus, AlertTriage, SiemSource } from "../entities/Alert.entity";

export interface AlertListOptions {
  /** Only alerts that do not yet belong to any Incident (via incident_alerts or Incident.alertId). */
  unlinked?: boolean;
}

/**
 * IAlertRepository — port (interface) owned by the domain.
 * The infrastructure layer implements this (e.g. AlertRepository.prisma.ts).
 * Application/domain code depends ONLY on this interface, never on Prisma directly.
 */
export interface IAlertRepository {
  findById(id: string, tenantId: string): Promise<Alert | null>;
  findAll(tenantId: string, limit?: number, offset?: number, options?: AlertListOptions): Promise<Alert[]>;
  countAll(tenantId: string, options?: AlertListOptions): Promise<number>;
  /** Every stored alert with the same SIEM-side identity - used for duplicate protection. */
  findByExternalId(siemSource: SiemSource, externalAlertId: string, tenantId: string): Promise<Alert[]>;
  save(alert: Alert): Promise<Alert>;
  /** Stores the SOC triage and the resulting alert status. */
  recordTriage(id: string, tenantId: string, triage: AlertTriage, status: AlertStatus): Promise<Alert>;

  // ---------------------------------------------------------------- SOC review lifecycle (atomic, single statement)
  /**
   * Closes an OPEN alert (NEW / legacy IN_TRIAGE / MONITORING, not linked to an incident) as FALSE_POSITIVE / INFORMATIONAL:
   * TRIAGED with closed_at. Conditional write — when another analyst decided first, nothing is written (null).
   */
  commitTriage(id: string, tenantId: string, actor: string, decision: CommitTriageData): Promise<Alert | null>;
  /** MONITORING alerts whose review date has passed (any tenant). */
  findDueMonitors(now: Date, limit: number): Promise<Alert[]>;
  /**
   * A due (legacy) MONITORING alert goes back to the review queue (NEW). Only when it is still MONITORING and due — a
   * second run changes nothing (null). Monitor reason, review date and the triage history are kept.
   */
  returnDueMonitor(id: string, tenantId: string, now: Date): Promise<Alert | null>;
}

export interface CommitTriageData {
  disposition: "FALSE_POSITIVE" | "INFORMATIONAL";
  reason: string;
  at: Date;
}
