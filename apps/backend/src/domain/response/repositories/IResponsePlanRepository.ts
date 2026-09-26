import { ResponsePlan, ResponseApprovalStatus, ResponseStatus } from "../entities/ResponsePlan.entity";

export interface CreateResponsePlanData {
  tenantId: string;
  incidentId: string;
  recommendationId: string;
  recommendationStepId: string;
  actionId: string;
  target: string | null;
  reason: string;
  expectedResult: string | null;
  approvalStatus: ResponseApprovalStatus;
  assignedRole: string;
  status: ResponseStatus;
}

/** Manual execution record of the plan's RecommendationStep (step_executions) — Task 10.3 traceability. */
export interface RecordStepExecutionData {
  status: "IN_PROGRESS" | "COMPLETED" | "FAILED";
  executedBy: string;
  at: Date;
  actualResult?: string | null;
}

export interface IResponsePlanRepository {
  findById(id: string, tenantId: string): Promise<ResponsePlan | null>;
  findByRecommendation(recommendationId: string, tenantId: string): Promise<ResponsePlan[]>;
  /** Tenant-wide list, newest first — powers the Response Operations Dashboard/list page. */
  findAll(tenantId: string, limit?: number, offset?: number, incidentId?: string): Promise<ResponsePlan[]>;
  countAll(tenantId: string, incidentId?: string): Promise<number>;
  create(data: CreateResponsePlanData): Promise<ResponsePlan>;
  /**
   * Records/updates the StepExecution row that traces this plan's manual execution back to its
   * RecommendationStep (Incident -> Recommendation -> RecommendationStep -> Action -> ResponsePlan -> StepExecution).
   * Optional so in-memory test doubles need not implement it; no-op for legacy plans without recommendationStepId.
   */
  recordStepExecution?(planId: string, tenantId: string, data: RecordStepExecutionData): Promise<void>;
  updateStatus(
    id: string,
    tenantId: string,
    data: Partial<{
      approvalStatus: ResponseApprovalStatus;
      status: ResponseStatus;
      assignedTo: string | null;
      executionResult: Record<string, unknown> | null;
      executedAt: Date | null;
      completedAt: Date | null;
    }>
  ): Promise<ResponsePlan>;
}
