import { PlaybookRevisionProvenance } from "../../playbook/PlaybookRevisionProvenance";
import { Recommendation, RecommendationInstruction, RecommendationStatus, RecommendationStepProps, RecommendationStepType } from "../entities/Recommendation.entity";

export interface CreateRecommendationStepData {
  stepOrder: number;
  /** Persisted in recommendation_steps.phase. Absent -> ACTION (v2 action-level step). */
  stepType?: RecommendationStepType;
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
  instructions: RecommendationInstruction[];
  verificationCriteria: string | null;
}

/** Frozen grounding for one Recommendation generation; each generation gets a new snapshot. */
export interface RecommendationSnapshotData {
  playbookCode: string;
  playbookVersion: string;
  procedureCode: string;
  procedureVersion: string;
  procedureContent: unknown;
  policyResult: unknown;
}

export interface CreateRecommendationData {
  /** Required at runtime for all new persisted recommendations; legacy reads remain unchanged. */
  provenance?: PlaybookRevisionProvenance | null;
  tenantId: string;
  incidentId: string;
  investigationNumber: number;
  recommendationNumber: number;
  status: RecommendationStatus;
  summary: string;
  createdBy: string;
  steps: CreateRecommendationStepData[];
  snapshot?: RecommendationSnapshotData | null;
}

export interface IRecommendationRepository {
  findById(id: string, tenantId: string): Promise<Recommendation | null>;
  findByIncidentAndNumber(incidentId: string, recommendationNumber: number, tenantId: string): Promise<Recommendation | null>;
  findAllByIncident(incidentId: string, tenantId: string): Promise<Recommendation[]>;
  getNextRecommendationNumber(incidentId: string, tenantId: string): Promise<number>;
  create(data: CreateRecommendationData): Promise<Recommendation>;
  updateStatus(id: string, tenantId: string, status: RecommendationStatus): Promise<Recommendation>;
  supersedePrevious(incidentId: string, tenantId: string, keepRecommendationId: string): Promise<void>;
}

export type { RecommendationStepProps, RecommendationInstruction };
