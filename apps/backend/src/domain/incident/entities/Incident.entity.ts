export type IncidentStatus = "open" | "investigating" | "resolved" | "dismissed";
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

  isOpen(): boolean {
    return this.props.status === "open" || this.props.status === "investigating";
  }

  toJSON(): IncidentProps {
    return { ...this.props };
  }
}
