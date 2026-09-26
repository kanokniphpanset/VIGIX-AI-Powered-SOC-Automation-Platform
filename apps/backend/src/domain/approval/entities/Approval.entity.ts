/**
 * "pending": waiting for the IR decision (APPROVE / REJECT).
 * "waiting" / "cancelled" / "more_evidence_requested": history only (retired multi-step chains) — never created now.
 */
export type ApprovalStatus = "pending" | "approved" | "rejected" | "more_evidence_requested" | "waiting" | "cancelled";
/** The only approver in the two-role workflow. Historical rows may still name a retired role (read-only). */
export type ApprovalRole = "IR_TEAM";

export interface ApprovalProps {
  id: string;
  tenantId: string;
  recommendationId: string | null;
  responseId: string | null;
  /** IR_TEAM for every approval opened now; a decided historical row may carry a retired role name. */
  approvalRole: string;
  reason: string;
  status: ApprovalStatus;
  /** Position in the Policy approval chain (1 = first approver). */
  stepOrder: number;
  requestedTo: string | null;
  decidedBy: string | null;
  decidedAt: Date | null;
  comment: string | null;
  createdAt: Date;
}

/**
 * Approval — a human decision gate on the NEW Recommendation/Response
 * pipeline (recommendationId/responseId), deliberately separate from the
 * legacy Decision-pipeline Approval rows (decisionId/requestedTo-only,
 * untouched by any use-case in this module — see
 * IApprovalRepository.prisma.ts). `approvalRole` is always set by the
 * Policy Engine's own evaluation (see EvaluatePolicy), never chosen by AI
 * or by this entity itself — this class only records and transitions the
 * decision, it never decides who is authorized.
 */
export class Approval {
  private constructor(private readonly props: ApprovalProps) {}

  static create(props: ApprovalProps): Approval {
    if (!props.reason) throw new Error("Approval must record a reason");
    if (!props.recommendationId && !props.responseId) {
      throw new Error("Approval must reference either a Recommendation or a ResponsePlan");
    }
    return new Approval(props);
  }

  get id() {
    return this.props.id;
  }
  get tenantId() {
    return this.props.tenantId;
  }
  get recommendationId() {
    return this.props.recommendationId;
  }
  get responseId() {
    return this.props.responseId;
  }
  get approvalRole() {
    return this.props.approvalRole;
  }
  get reason() {
    return this.props.reason;
  }
  get status() {
    return this.props.status;
  }
  get requestedTo() {
    return this.props.requestedTo;
  }
  get decidedBy() {
    return this.props.decidedBy;
  }
  get decidedAt() {
    return this.props.decidedAt;
  }
  get comment() {
    return this.props.comment;
  }
  get createdAt() {
    return this.props.createdAt;
  }
  get stepOrder() {
    return this.props.stepOrder;
  }
  get isPending() {
    return this.props.status === "pending";
  }
  /** Not decided yet: the active step (pending) or a later chain step (waiting). */
  get isOpen() {
    return this.props.status === "pending" || this.props.status === "waiting";
  }

  toJSON() {
    return { ...this.props };
  }
}
