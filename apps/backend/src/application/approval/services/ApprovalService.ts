import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { IRecommendationContextRepository, IncidentContextRow } from "../../recommendation/ports/IRecommendationContextRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { PolicyEvaluator } from "../../../infrastructure/policy-engine/PolicyEvaluator";
import { ActionImpactLevel, Severity } from "../../../domain/policy/entities/PolicyEvaluationTypes";
import { incidentSeverity } from "../../../domain/incident/severity";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Approval, ApprovalRole } from "../../../domain/approval/entities/Approval.entity";
import { Recommendation } from "../../../domain/recommendation/entities/Recommendation.entity";
import { INotificationDispatcherPort } from "../../notification/ports/INotificationDispatcherPort";
import { buildApprovalRequiredEvent } from "../../notification/services/NotificationEventBuilder";
import { AssetCriticalityResolution, IAssetCriticalityProvider } from "../ports/IAssetCriticalityProvider";

export type PolicyOutcome = Awaited<ReturnType<PolicyEvaluator["evaluate"]>>;

export interface PolicyDecision {
  policy: PolicyOutcome;
  incidentContext: IncidentContextRow | null;
  /** The severity Policy evaluated (incident severity, human-validated when an analyst changed it). */
  severity: Severity;
  /** How assetCriticality was derived (null when no provider is configured). */
  assets: AssetCriticalityResolution | null;
}

type ApprovalStepRefs = Parameters<typeof buildApprovalRequiredEvent>[0]["stepsRequiringApproval"];

/**
 * ApprovalService — the ONE place that (a) builds the Policy Engine input
 * for a response/approval decision and (b) opens an Approval. Both
 * CreateResponsePlan and RequestApproval go through `evaluate`, so the two
 * can never disagree about whether approval is required or by whom: same
 * inputs (the incident SEVERITY — human-validated when an analyst corrected
 * it — the asset criticality and the action's impact level when a concrete
 * action is known), same PolicyEvaluator. No risk score is ever an input.
 * Policy rules themselves live only in the Policy Engine — nothing here
 * hardcodes an approval role or a required/not-required outcome.
 *
 * assetCriticality comes from the shared asset catalog
 * (IAssetCriticalityProvider) for the hosts named by the incident's own
 * current-cycle evidence — never from AI output. Without it the APPROVAL
 * rules that key on a CRITICAL asset (RULE-P04, RULE-P06) could never fire.
 * The AI's per-step `requiresApproval` hint is not an input here.
 */
export class ApprovalService {
  constructor(
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly actionRepository: IActionRepository,
    private readonly policyEvaluator: PolicyEvaluator,
    private readonly approvalRepository: IApprovalRepository,
    private readonly auditLogger: AuditLogger,
    private readonly notificationDispatcher: INotificationDispatcherPort,
    private readonly vigixBaseUrl: string,
    private readonly assetCriticalityProvider?: IAssetCriticalityProvider
  ) {}

  async evaluate(input: { tenantId: string; incidentId: string; actionId?: string | null }): Promise<PolicyDecision> {
    const incidentContext = await this.contextRepository.getIncidentContext(input.incidentId, input.tenantId);
    const action = input.actionId ? await this.actionRepository.findById(input.actionId, input.tenantId) : null;

    let assets: AssetCriticalityResolution | null = null;
    if (this.assetCriticalityProvider && incidentContext) {
      const evidence = await this.contextRepository.getEvidence(input.incidentId, incidentContext.investigationNumber);
      assets = this.assetCriticalityProvider.resolve(evidence.map((e) => e.host).filter((h): h is string => !!h));
    }

    const severity = incidentSeverity(incidentContext);
    const policyInput = {
      severity,
      assetCriticality: assets?.criticality,
      actionImpactLevel: action?.impactLevel as ActionImpactLevel | undefined,
    };
    const policy = await this.policyEvaluator.evaluate(input.tenantId, policyInput);

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: "policy-engine",
      action: "POLICY_EVALUATED",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: {
        input: { ...policyInput, actionCode: action?.code ?? null },
        assets: assets?.assets ?? [],
        matchedPolicies: policy.matchedPolicies,
        responsibleRole: policy.responsibleRole,
        reviewRequired: policy.reviewRequired,
        reviewRole: policy.reviewRole,
        approvalRequired: policy.approvalRequired,
        approvalRole: policy.approvalRole,
        approvalChain: policy.approvalChain,
        executorRole: policy.executorRole,
        approvalReason: policy.approvalReason,
        priority: policy.priority,
        sla: policy.sla,
      },
    });

    return { policy, incidentContext, severity, assets };
  }

  /**
   * Opens the IR decision for one Response Ticket: exactly one IR_TEAM approval step ("pending"). There is no
   * approval chain and no other approver. Policy's matched rules and reason tags are recorded on the approval so IR
   * sees WHY the ticket is sensitive; they never add or skip the IR decision. Audits APPROVAL_REQUESTED.
   * `notify` (default true) emits APPROVAL_REQUIRED; CreateResponsePlan passes false and sends ONE ticket notification
   * (with the ticket link) itself, after the ticket exists. Notification failure never fails the approval.
   */
  async open(input: {
    tenantId: string;
    recommendation: Recommendation;
    responseId: string | null;
    decision: PolicyDecision;
    steps: ApprovalStepRefs;
    notify?: boolean;
  }): Promise<Approval> {
    const { policy, incidentContext, severity } = input.decision;
    const approvalRole: ApprovalRole = "IR_TEAM";
    const reason = `IR decision required (matched: ${policy.matchedPolicies.join(", ") || "none"}; ${policy.approvalReason.join(", ") || "no reason tag"}; severity=${severity}, assetCriticality=${input.decision.assets?.criticality ?? "not supplied"})`;
    const approval = await this.approvalRepository.create({
      tenantId: input.tenantId,
      recommendationId: input.recommendation.id,
      responseId: input.responseId,
      approvalRole,
      reason,
      stepOrder: 1,
      status: "pending",
    });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: "system",
      action: "APPROVAL_REQUESTED",
      entity: "Approval",
      entityId: approval.id,
      metadata: {
        origin: "IR_DECISION",
        policyApprovalRequired: policy.approvalRequired,
        incidentId: input.recommendation.incidentId,
        recommendationId: input.recommendation.id,
        responseId: input.responseId,
        approvalRole: approval.approvalRole,
        approvalChain: [approvalRole],
        matchedPolicies: policy.matchedPolicies,
        approvalReason: policy.approvalReason,
      },
    });

    if (input.notify === false) return approval;
    try {
      await this.notificationDispatcher.emit(
        buildApprovalRequiredEvent({
          tenantId: input.tenantId,
          baseUrl: this.vigixBaseUrl,
          incident: {
            id: input.recommendation.incidentId,
            title: incidentContext?.title ?? "",
            priority: incidentContext?.priority ?? "medium",
            investigationNumber: incidentContext?.investigationNumber ?? input.recommendation.investigationNumber,
          },
          recommendation: input.recommendation,
          approval,
          stepsRequiringApproval: input.steps,
        })
      );
    } catch (err) {
      console.error("Failed to emit APPROVAL_REQUIRED notification for approval", approval.id, err);
    }

    return approval;
  }
}
