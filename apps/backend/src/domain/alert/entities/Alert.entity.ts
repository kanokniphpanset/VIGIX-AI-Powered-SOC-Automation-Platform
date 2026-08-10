/**
 * Alert — domain entity (Ring 1: Domain).
 * Represents an alert as received from an external SIEM, before it becomes an Incident.
 * This class has ZERO knowledge of Express, Prisma, or HTTP — pure business object.
 */
export type SiemSource = "wazuh" | "splunk" | "defender" | "elk";
export type AlertSeverity = "low" | "medium" | "high" | "critical";
export type AlertStatus = "received" | "analyzing" | "escalated" | "closed";

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

  isHighPriority(): boolean {
    return this.props.severity === "high" || this.props.severity === "critical";
  }

  toJSON(): AlertProps {
    return { ...this.props };
  }
}
