export type RecommendationStatus = "GENERATED" | "VALIDATED" | "INVALID" | "SUPERSEDED";
export type RecommendationStepStatus = "PENDING" | "SUPERSEDED";

/** One ordered operational instruction of an action-level RecommendationStep (Task 10.3). */
export interface RecommendationInstruction {
  order: number;
  instruction: string;
  target: string | null;
  expectedResult: string | null;
}

export interface RecommendationStepProps {
  id: string;
  stepOrder: number;
  title: string;
  objective: string | null;
  actionId: string | null;
  target: string | null;
  reason: string;
  evidence: string[];
  sourceRunbookId: string | null;
  precondition: string | null;
  expectedResult: string | null;
  requiresApproval: boolean;
  status: RecommendationStepStatus;
  instructions: RecommendationInstruction[];
  verificationCriteria: string | null;
}

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
