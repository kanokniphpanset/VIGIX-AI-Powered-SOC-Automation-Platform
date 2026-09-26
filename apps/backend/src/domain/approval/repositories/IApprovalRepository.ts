import { Approval, ApprovalRole, ApprovalStatus } from "../entities/Approval.entity";

export interface CreateApprovalData {
  tenantId: string;
  recommendationId: string | null;
  responseId: string | null;
  approvalRole: ApprovalRole;
  reason: string;
  /** Chain position (default 1). */
  stepOrder?: number;
  /** "pending" for the active (first) step, "waiting" for later chain steps. Default "pending". */
  status?: "pending" | "waiting";
}

export interface IApprovalRepository {
  findById(id: string, tenantId: string): Promise<Approval | null>;
  findByRecommendation(recommendationId: string, tenantId: string): Promise<Approval[]>;
  /** Approvals opened for one specific ResponsePlan (Approval.responseId). */
  findByResponse(responseId: string, tenantId: string): Promise<Approval[]>;
  create(data: CreateApprovalData): Promise<Approval>;
  /** waiting -> pending (the previous chain step was approved). */
  activate(id: string, tenantId: string): Promise<Approval>;
  /** Every still-waiting step of the chain -> cancelled (an earlier step stopped the chain). */
  cancel(ids: string[], tenantId: string): Promise<void>;
  decide(
    id: string,
    tenantId: string,
    data: { status: ApprovalStatus; decidedBy: string; comment: string | null }
  ): Promise<Approval>;
}
