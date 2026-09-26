/**
 * "escalated": the verification loop ended after MAX_INVESTIGATION_ROUNDS without containment — no new cycle or
 * recommendation is generated; a human IR decision is required. Not closed (closedAt stays null).
 */
export type IncidentStatus = "open" | "investigating" | "resolved" | "dismissed" | "escalated";
export type IncidentPriority = "low" | "medium" | "high" | "critical";

export interface IncidentProps {
  id: string;
  tenantId: string;
  alertId: string;
  title: string;
  status: IncidentStatus;
  priority: IncidentPriority;
  openedAt: Date;
  closedAt: Date | null;
  mttdSeconds: number | null;
  mttrSeconds: number | null;
  investigationNumber: number;
}

export class Incident {
  private constructor(private readonly props: IncidentProps) {}

  static create(props: IncidentProps): Incident {
    if (!props.title) {
      throw new Error("Incident must have a title");
    }
    return new Incident(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get alertId() {
    return this.props.alertId;
  }
  get title() {
    return this.props.title;
  }
  get status() {
    return this.props.status;
  }
  get priority() {
    return this.props.priority;
  }
  get openedAt() {
    return this.props.openedAt;
  }
  get closedAt() {
    return this.props.closedAt;
  }
  get mttdSeconds() {
    return this.props.mttdSeconds;
  }
  get mttrSeconds() {
    return this.props.mttrSeconds;
  }
  get investigationNumber() {
    return this.props.investigationNumber;
  }

  isOpen(): boolean {
    return this.props.status === "open" || this.props.status === "investigating";
  }

  toJSON(): IncidentProps {
    return { ...this.props };
  }
}
