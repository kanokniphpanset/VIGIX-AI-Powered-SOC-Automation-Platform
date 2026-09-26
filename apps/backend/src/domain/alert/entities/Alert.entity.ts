import type { AlertWorkflowState } from "../triageWorkflow";
/**
 * Alert — domain entity (Ring 1: Domain).
 * Represents an alert as received from an external SIEM, before it becomes an Incident.
 * This class has ZERO knowledge of Express, Prisma, or HTTP — pure business object.
 */
export type SiemSource = "wazuh" | "splunk" | "defender" | "elk";
export type AlertSeverity = "low" | "medium" | "high" | "critical";
/** "monitoring": SOC triaged the alert as MONITOR — kept open in the Alert Inbox without an Incident. */
export type AlertStatus = "received" | "analyzing" | "escalated" | "closed" | "monitoring";

/** SOC triage outcome for an alert that does not become an Incident. */
export type AlertTriageDisposition = "FALSE_POSITIVE" | "INFORMATIONAL" | "MONITOR";
export const ALERT_TRIAGE_DISPOSITIONS: AlertTriageDisposition[] = ["FALSE_POSITIVE", "INFORMATIONAL", "MONITOR"];

export interface AlertTriage {
  disposition: AlertTriageDisposition;
  note: string | null;
  triagedBy: string;
  triagedAt: Date;
}

export interface AlertProps {
  id: string;
  tenantId: string;
  externalAlertId: string;
  siemSource: SiemSource;
  rawPayload: Record<string, unknown>;
  severity: AlertSeverity;
  status: AlertStatus;
  receivedAt: Date;
  createdAt: Date;
  /** Latest SOC triage (null = not triaged). */
  triage?: AlertTriage | null;
  /** SOC triage lifecycle (see domain/alert/triageWorkflow.ts). Defaults to NEW. */
  workflowState?: AlertWorkflowState;
  reviewAt?: Date | null;
  monitorReason?: string | null;
  closedAt?: Date | null;
}

export class Alert {
  private constructor(private readonly props: AlertProps) {}

  static create(props: AlertProps): Alert {
    if (!props.externalAlertId) {
      throw new Error("Alert must have an externalAlertId");
    }
    return new Alert(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get externalAlertId() {
    return this.props.externalAlertId;
  }
  get siemSource() {
    return this.props.siemSource;
  }
  get rawPayload() {
    return this.props.rawPayload;
  }
  get severity() {
    return this.props.severity;
  }
  get status() {
    return this.props.status;
  }
  get receivedAt() {
    return this.props.receivedAt;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get triage() {
    return this.props.triage ?? null;
  }
  get workflowState(): AlertWorkflowState {
    return this.props.workflowState ?? "NEW";
  }
  get reviewAt() {
    return this.props.reviewAt ?? null;
  }
  get monitorReason() {
    return this.props.monitorReason ?? null;
  }
  get closedAt() {
    return this.props.closedAt ?? null;
  }

  isHighPriority(): boolean {
    return this.props.severity === "high" || this.props.severity === "critical";
  }

  toJSON(): AlertProps {
    return { ...this.props };
  }
}
