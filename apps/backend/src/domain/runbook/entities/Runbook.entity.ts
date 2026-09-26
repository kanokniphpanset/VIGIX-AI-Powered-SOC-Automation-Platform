export type RunbookStatus = "ACTIVE" | "DEPRECATED";

export interface RunbookProps {
  id: string;
  tenantId: string;
  code: string;
  name: string;
  version: string;
  status: RunbookStatus;
  description: string | null;
  trigger: string | null;
  preconditions: string[];
  objective: string | null;
  procedure: string[];
  decisionPoints: string[];
  expectedResult: string | null;
  escalation: string | null;
  verificationCriteria: string[];
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Runbook — the detailed technical procedure / source of truth an
 * incident's response steps may cite (spec section 10). NOT AI-generated:
 * the AI Recommendation Agent may only READ/reference a Runbook's
 * id/procedure, never create or modify one (RULE-005/015).
 */
export class Runbook {
  private constructor(private readonly props: RunbookProps) {}

  static create(props: RunbookProps): Runbook {
    if (!props.code) throw new Error("Runbook must have a code");
    if (!props.name) throw new Error("Runbook must have a name");
    if (props.procedure.length === 0) throw new Error("Runbook must have at least one procedure step");
    return new Runbook(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get code() {
    return this.props.code;
  }
  get name() {
    return this.props.name;
  }
  get version() {
    return this.props.version;
  }
  get status() {
    return this.props.status;
  }
  get isActive() {
    return this.props.status === "ACTIVE";
  }
  get description() {
    return this.props.description;
  }
  get trigger() {
    return this.props.trigger;
  }
  get preconditions() {
    return this.props.preconditions;
  }
  get objective() {
    return this.props.objective;
  }
  get procedure() {
    return this.props.procedure;
  }
  get decisionPoints() {
    return this.props.decisionPoints;
  }
  get expectedResult() {
    return this.props.expectedResult;
  }
  get escalation() {
    return this.props.escalation;
  }
  get verificationCriteria() {
    return this.props.verificationCriteria;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get updatedAt() {
    return this.props.updatedAt;
  }

  toJSON(): RunbookProps {
    return { ...this.props };
  }
}
