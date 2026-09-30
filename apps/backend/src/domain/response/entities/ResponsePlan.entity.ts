export type ResponseApprovalStatus = "NOT_REQUIRED" | "PENDING" | "APPROVED" | "REJECTED" | "MORE_EVIDENCE_REQUESTED";
/**
 * Response Ticket lifecycle (two roles): PENDING_IR_DECISION -> (IR APPROVE) READY_FOR_EXECUTION -> IN_PROGRESS ->
 * COMPLETED | FAILED, or (IR REJECT) PENDING_MANUAL_DECISION -> (IR approves its own manual response)
 * READY_FOR_EXECUTION. REJECTED is a history-only value of tickets rejected before the Manual Decision step. PENDING_APPROVAL / MORE_EVIDENCE_REQUESTED / APPROVED are
 * history-only values of older tickets (PENDING_APPROVAL rows were migrated to PENDING_IR_DECISION).
 */
export type ResponseStatus =
  | "DRAFT"
  | "PENDING_IR_DECISION"
  /** IR rejected the recommended response; waiting for IR's own manual response decision. */
  | "PENDING_MANUAL_DECISION"
  | "PENDING_APPROVAL"
  | "APPROVED"
  | "REJECTED"
  | "READY_FOR_EXECUTION"
  | "IN_PROGRESS"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  /** History only (retired "request more evidence" decision): this ticket can never start. */
  | "MORE_EVIDENCE_REQUESTED";

export interface ResponsePlanProps {
  id: string;
  tenantId: string;
  incidentId: string;
  recommendationId: string;
  recommendationStepId: string | null;
  actionId: string;
  target: string | null;
  reason: string;
  expectedResult: string | null;
  approvalStatus: ResponseApprovalStatus;
  assignedRole: string;
  assignedTo: string | null;
  status: ResponseStatus;
  executionResult: Record<string, unknown> | null;
  executedAt: Date | null;
  completedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * ResponsePlan — one concrete, actionable step from a validated
 * Recommendation, tracked through to manual IR Team execution. This
 * entity NEVER executes anything itself: it only records state
 * transitions (DRAFT -> ... -> IN_PROGRESS -> COMPLETED/FAILED). There is
 * no method here, or anywhere in the Response module, that calls a
 * shell, a firewall API, an EDR isolation endpoint, or n8n — "execute" in
 * this codebase always means "IR Team performed it manually and reported
 * the result back," never an automated action.
 */
export class ResponsePlan {
  private constructor(private readonly props: ResponsePlanProps) {}

  static create(props: ResponsePlanProps): ResponsePlan {
    if (!props.actionId) throw new Error("ResponsePlan must reference a concrete Action (cannot be created for an investigation-only step)");
    if (!props.reason) throw new Error("ResponsePlan must record a reason");
    return new ResponsePlan(props);
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
  get recommendationId() {
    return this.props.recommendationId;
  }
   get recommendationStepId() {
  return this.props.recommendationStepId;
}
  get actionId() {
    return this.props.actionId;
  }
  get target() {
    return this.props.target;
  }
  get reason() {
    return this.props.reason;
  }
  get expectedResult() {
    return this.props.expectedResult;
  }
  get approvalStatus() {
    return this.props.approvalStatus;
  }
  get assignedRole() {
    return this.props.assignedRole;
  }
  get assignedTo() {
    return this.props.assignedTo;
  }
  get status() {
    return this.props.status;
  }
  get executionResult() {
    return this.props.executionResult;
  }
  get executedAt() {
    return this.props.executedAt;
  }
  get completedAt() {
    return this.props.completedAt;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get updatedAt() {
    return this.props.updatedAt;
  }

  toJSON() {
    return { ...this.props };
  }
}
