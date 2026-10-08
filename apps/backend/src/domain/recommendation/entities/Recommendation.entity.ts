/** REJECTED: the SOC rejected it at SOC Validation and closed the incident (RejectRecommendationUseCase). */
export type RecommendationStatus = "GENERATED" | "VALIDATED" | "INVALID" | "SUPERSEDED" | "REJECTED";
export type RecommendationStepStatus = "PENDING" | "SUPERSEDED";
/** ACTION: catalog Action (ticketable). CHECK: investigation / decision step. MANUAL: control VIGIX cannot execute. */
export type RecommendationStepType = "ACTION" | "CHECK" | "MANUAL";

/** One ordered operational instruction of an action-level RecommendationStep (Task 10.3). */
export interface RecommendationInstruction {
  order: number;
  instruction: string;
  target: string | null;
  expectedResult: string | null;
  /** Subtype-knowledge recommendations (all optional, additive): contract-format pieces of one operational instruction. */
  title?: string;
  impact?: string | null;
  verify?: string | null;
  kind?: "action" | "verify";
  /** a named non-IR owner (e.g. DBA, business authority) who performs this instruction - IR does not do it for them. */
  manualOwner?: string | null;
  /** how to perform it / checks before acting / how to undo / why it is proposed again (all optional, additive). */
  method?: string | null;
  methodKind?: "method" | "detail";
  preconditions?: string[];
  rollback?: string | null;
  note?: string | null;
}

export interface RecommendationStepProps {
  id: string;
  stepOrder: number;
  /** Stored in recommendation_steps.phase; CHECK / MANUAL steps never have an actionId and are never ticketed.
   * Absent on in-memory rows built before step types existed: read it through stepTypeOfStep(). */
  stepType?: RecommendationStepType;
  title: string;
  objective: string | null;
  actionId: string | null;
  target: string | null;
  reason: string;
  evidence: string[];
  sourceRunbookId: string | null;
  /** The procedure condition that must be confirmed before the step is carried out. */
  precondition: string | null;
  expectedResult: string | null;
  requiresApproval: boolean;
  status: RecommendationStepStatus;
  instructions: RecommendationInstruction[];
  verificationCriteria: string | null;
}

/** A step's type; a step without one is ACTION when it carries an Action, otherwise CHECK (investigation only). */
export const stepTypeOfStep = (s: Pick<RecommendationStepProps, "stepType" | "actionId">): RecommendationStepType => s.stepType ?? (s.actionId ? "ACTION" : "CHECK");

export interface RecommendationProps {
  id: string;
  tenantId: string;
  incidentId: string;
  investigationNumber: number;
  recommendationNumber: number;
  status: RecommendationStatus;
  summary: string;
  createdBy: string;
  steps: RecommendationStepProps[];
  snapshotId?: string | null;
}

/**
 * Recommendation — AI-proposed, backend-validated guidance for an
 * incident's current investigation cycle (spec section 9-13). NEVER an
 * authorization to act: `steps[].requiresApproval` is the AI's own
 * suggestion only, and the Policy Engine's own evaluation is what actually
 * gates Approval/Response (see GenerateRecommendation.usecase.ts). A step's
 * `actionId === null` is a valid, first-class outcome meaning "additional
 * investigation only, no catalog action applies" — never coerced into a
 * fabricated action (RULE-009).
 */
export class Recommendation {
  private constructor(private readonly props: RecommendationProps) {}

  static create(props: RecommendationProps): Recommendation {
    if (!props.summary) throw new Error("Recommendation must have a summary");
    if (!props.createdBy) throw new Error("Recommendation must record createdBy (agent version, never a human actor)");
    return new Recommendation(props);
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
  get investigationNumber() {
    return this.props.investigationNumber;
  }
  get recommendationNumber() {
    return this.props.recommendationNumber;
  }
  get status() {
    return this.props.status;
  }
  get summary() {
    return this.props.summary;
  }
  get createdBy() {
    return this.props.createdBy;
  }
  get snapshotId() {
    return this.props.snapshotId ?? null;
  }
  get steps() {
    return [...this.props.steps].sort((a, b) => a.stepOrder - b.stepOrder);
  }

  toJSON() {
    return { ...this.props, steps: this.steps };
  }
}
