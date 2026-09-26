export type VerificationResult = "RESOLVED" | "NOT_RESOLVED";

export interface VerificationProps {
  id: string;
  tenantId: string;
  incidentId: string;
  responseId: string | null;
  wazuhIndex: string | null;
  query: string | null;
  timeRangeStart: Date | null;
  timeRangeEnd: Date | null;
  matchingEvents: number | null;
  affectedHosts: string[];
  iocRecurrence: boolean;
  spreadDetected: boolean;
  threatContained: boolean;
  beforeState: Record<string, unknown> | null;
  afterState: Record<string, unknown> | null;
  result: VerificationResult;
  notes: string | null;
  verifiedBy: string;
  verifiedAt: Date;
}

/**
 * Verification — the ONLY thing that can determine RESOLVED/NOT_RESOLVED
 * (spec: "AI cannot declare RESOLVED"). This entity is a passive record —
 * `result` is never set directly by a caller (see
 * CreateVerification.usecase.ts), it is DERIVED deterministically from
 * the evidence fields (threatContained, spreadDetected, iocRecurrence,
 * matchingEvents) a human supplies from an actual Wazuh re-hunt. There is
 * no AI adapter anywhere in this module.
 */
export class Verification {
  private constructor(private readonly props: VerificationProps) {}

  static create(props: VerificationProps): Verification {
    if (!props.verifiedBy) throw new Error("Verification must record who performed it");
    return new Verification(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get incidentId() {
    return this.props.incidentId;
  }
  get responseId() {
    return this.props.responseId;
  }
  get wazuhIndex() {
    return this.props.wazuhIndex;
  }
  get query() {
    return this.props.query;
  }
  get timeRangeStart() {
    return this.props.timeRangeStart;
  }
  get timeRangeEnd() {
    return this.props.timeRangeEnd;
  }
  get matchingEvents() {
    return this.props.matchingEvents;
  }
  get affectedHosts() {
    return this.props.affectedHosts;
  }
  get iocRecurrence() {
    return this.props.iocRecurrence;
  }
  get spreadDetected() {
    return this.props.spreadDetected;
  }
  get threatContained() {
    return this.props.threatContained;
  }
  get beforeState() {
    return this.props.beforeState;
  }
  get afterState() {
    return this.props.afterState;
  }
  get result() {
    return this.props.result;
  }
  get notes() {
    return this.props.notes;
  }
  get verifiedBy() {
    return this.props.verifiedBy;
  }
  get verifiedAt() {
    return this.props.verifiedAt;
  }

  toJSON() {
    return { ...this.props };
  }
}
