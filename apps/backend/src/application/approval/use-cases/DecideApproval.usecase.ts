import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Approval, ApprovalStatus } from "../../../domain/approval/entities/Approval.entity";
import { Result } from "../../../shared/result/Result";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { INotificationDispatcherPort } from "../../notification/ports/INotificationDispatcherPort";
import { buildApprovalDecidedEvent } from "../../notification/services/NotificationEventBuilder";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";
import { ResponseProcess } from "../../notification/events/NotificationEvent";
import { incidentSeverity } from "../../../domain/incident/severity";

export type DecideApprovalError = "NOT_FOUND" | "ALREADY_DECIDED" | "ROLE_MISMATCH" | "ADMIN_NOT_APPROVER" | "NOTE_REQUIRED";

/** The only decisions IR can take on a Response Ticket. */
export type ApprovalDecision = Extract<ApprovalStatus, "approved" | "rejected">;

const DECISION_AUDIT: Record<ApprovalDecision, string> = {
  approved: "APPROVAL_APPROVED",
  rejected: "APPROVAL_REJECTED",
};

/** Ticket statuses that are waiting for the IR decision (PENDING_APPROVAL: tickets created before the two-role change). */
const AWAITING_DECISION = new Set(["PENDING_IR_DECISION", "PENDING_APPROVAL"]);

/**
 * DecideApprovalUseCase — the IR decision on a Response Ticket: APPROVE or REJECT, each with a mandatory note
 * (NOTE_REQUIRED). AI has no path to this class (RULE-006): the only callers are HTTP routes gated to human IR_TEAM
 * tokens. The decider's role must match the approval's role (IR_TEAM); "admin" is a system role and may never stand
 * in (ADMIN_NOT_APPROVER). Every denied attempt is audited (APPROVAL_DECISION_DENIED).
 *   approved -> ticket READY_FOR_EXECUTION (IR executes it: checklist, re-hunt, verification)
 *   rejected -> ticket REJECTED; the rejection note is stored on the approval and in the audit; nothing is executed
 * Deciding never executes anything itself.
 */
export class DecideApprovalUseCase {
  constructor(
    private readonly approvalRepository: IApprovalRepository,
    private readonly auditLogger: AuditLogger,
    private readonly recommendationRepository: IRecommendationRepository,
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly notificationDispatcher: INotificationDispatcherPort,
    private readonly vigixBaseUrl: string
  ) {}

  async execute(input: {
    approvalId: string;
    tenantId: string;
    status: ApprovalDecision;
    decidedBy: string;
    decidedByRole: string;
    comment: string | null;
  }): Promise<Result<Approval, DecideApprovalError>> {
    const approval = await this.approvalRepository.findById(input.approvalId, input.tenantId);
    if (!approval) return Result.fail("NOT_FOUND");
    const note = input.comment?.trim() || null;
    const denied = !approval.isPending
      ? ("ALREADY_DECIDED" as const)
      : input.decidedByRole === "admin"
        ? ("ADMIN_NOT_APPROVER" as const)
        : input.decidedByRole !== approval.approvalRole
          ? ("ROLE_MISMATCH" as const)
          : !note
            ? ("NOTE_REQUIRED" as const)
            : null;
    if (denied) {
      try {
        await this.audit(input, "APPROVAL_DECISION_DENIED", approval.id, {
          reason: denied,
          attempted: input.status,
          approvalRole: approval.approvalRole,
          actorRole: input.decidedByRole,
          approvalStatus: approval.status,
          responseId: approval.responseId,
        });
      } catch {
        /* the denial itself must still be returned even if its audit write fails */
      }
      return Result.fail(denied);
    }

    const updated = await this.approvalRepository.decide(approval.id, input.tenantId, {
      status: input.status,
      decidedBy: input.decidedBy,
      comment: note,
    });

    const auditBase = { status: input.status, recommendationId: approval.recommendationId, responseId: approval.responseId, approvalRole: approval.approvalRole };
    await this.audit(input, "APPROVAL_DECIDED", approval.id, auditBase);
    await this.audit(input, DECISION_AUDIT[input.status], approval.id, { ...auditBase, comment: note, note });

    // The decision moves ONLY its own ticket (other tickets of the same recommendation are untouched).
    if (updated.responseId) {
      const response = await this.responsePlanRepository.findById(updated.responseId, input.tenantId);
      if (response && AWAITING_DECISION.has(response.status)) {
        await this.responsePlanRepository.updateStatus(
          response.id,
          input.tenantId,
          input.status === "approved"
            ? { approvalStatus: "APPROVED", status: "READY_FOR_EXECUTION" }
            : { approvalStatus: "REJECTED", status: "REJECTED" }
        );
      }
    }

    const recommendation = updated.recommendationId ? await this.recommendationRepository.findById(updated.recommendationId, input.tenantId) : null;
    if (recommendation) {
      try {
        const incidentContext = await this.contextRepository.getIncidentContext(recommendation.incidentId, input.tenantId);
        if (incidentContext) {
          await this.notificationDispatcher.emit(
            buildApprovalDecidedEvent({
              eventType: input.status === "approved" ? "APPROVAL_APPROVED" : "APPROVAL_REJECTED",
              tenantId: input.tenantId,
              baseUrl: this.vigixBaseUrl,
              incident: { id: recommendation.incidentId, title: incidentContext.title, priority: incidentContext.priority, investigationNumber: incidentContext.investigationNumber },
              recommendation,
              approval: updated,
              // Best effort: if the process details cannot be built, the decision notification still goes out.
              responseProcess:
                input.status === "approved"
                  ? await this.responseProcess(recommendation, updated.responseId, incidentContext, input.tenantId).catch((err) => {
                      console.error("Could not build the approved response process for the notification", approval.id, err);
                      return undefined;
                    })
                  : undefined,
            })
          );
        }
      } catch (err) {
        console.error("Failed to emit APPROVAL_APPROVED/REJECTED notification for approval", approval.id, err);
      }
    }

    return Result.ok(updated);
  }

  private audit(input: { tenantId: string; decidedBy: string }, action: string, entityId: string, metadata: Record<string, unknown>) {
    return this.auditLogger.record({ tenantId: input.tenantId, actor: input.decidedBy, action, entity: "Approval", entityId, metadata });
  }

  /**
   * The approved response process sent to IR: the approved ticket's step (or every step of a recommendation-level
   * approval) with its operational instructions, plus the current cycle's evidence and the incident severity.
   */
  private async responseProcess(
    recommendation: Recommendation,
    responseId: string | null,
    incident: { incidentId: string; investigationNumber: number; priority: string; alertSeverity: string },
    tenantId: string
  ): Promise<ResponseProcess> {
    const plan = responseId ? await this.responsePlanRepository.findById(responseId, tenantId) : null;
    const steps = plan?.recommendationStepId ? recommendation.steps.filter((s) => s.id === plan.recommendationStepId) : recommendation.steps;
    const evidence = await this.contextRepository.getEvidence(incident.incidentId, incident.investigationNumber).catch(() => []);
    return {
      severity: incidentSeverity(incident),
      evidence: evidence.slice(0, 8).map((e) => `${e.title}${e.host ? ` (host ${e.host})` : ""}${e.iocValues.length ? ` — IOCs: ${e.iocValues.join(", ")}` : ""}`),
      steps: steps.map((s) => ({
        stepOrder: s.stepOrder,
        title: s.title,
        objective: s.objective,
        target: plan?.target ?? s.target,
        reason: s.reason,
        instructions: s.instructions.map((i) => ({ order: i.order, instruction: i.instruction, target: i.target, expectedResult: i.expectedResult })),
        expectedResult: s.expectedResult,
        verificationCriteria: s.verificationCriteria,
      })),
    };
  }
}
