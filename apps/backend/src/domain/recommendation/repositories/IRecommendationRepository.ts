import { Recommendation, RecommendationInstruction, RecommendationStatus, RecommendationStepProps } from "../entities/Recommendation.entity";

export interface CreateRecommendationStepData {
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
  instructions: RecommendationInstruction[];
  verificationCriteria: string | null;
}

/** Frozen record of what a Recommendation cycle was grounded in (playbook_snapshots, one per investigation cycle). */
export interface RecommendationSnapshotData {
  playbookCode: string;
  playbookVersion: string;
  procedureCode: string;
  procedureVersion: string;
  procedureContent: unknown;
  policyResult: unknown;
}

export interface CreateRecommendationData {
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
