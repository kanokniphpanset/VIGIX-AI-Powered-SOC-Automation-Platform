import { incidentSeverity } from "../../../domain/incident/severity";
import { IRecommendationContextRepository } from "../ports/IRecommendationContextRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { RecommendationContextActionProcedure, RecommendationContextDto, RecommendationContextPolicy } from "../dto/RecommendationContextDto";
import { PlaybookSelector } from "./PlaybookSelector";
import { evaluateActionEvidence } from "./ActionEvidence";
import { attackTypeForIncidentType } from "../../../domain/knowledge/attackKnowledge";
import { findActionKnowledge } from "../../../domain/knowledge/actionKnowledge";
import type { PolicyEvaluator } from "../../../infrastructure/policy-engine/PolicyEvaluator";
import type { ApprovalService } from "../../approval/services/ApprovalService";
import type { IncidentResponseSetupService } from "../../incident/services/IncidentResponseSetupService";
import { Result } from "../../../shared/result/Result";

/**
 * RecommendationContextBuilder — assembles the ONE authoritative
 * RecommendationContextDto handed to the RecommendationAgent. Maps only
 * what actually exists in Postgres today (Incident+Alert, ThreatIntelIoc,
 * MitreMapping, the current cycle's Evidence, the latest RiskScore, the AI
 * pipeline's LlmAnalyst analysis, the enabled Action Catalog, the active
 * Runbook Catalog).
 * Fields with no backing data are left empty — never fabricated to make
 * the context look richer than the evidence actually is.
 *
 * Task 10.3 (Response Process Recommendation v2): also selects the
 * incident-level Playbook deterministically (PlaybookSelector, from the
 * recorded MITRE techniques) and, for every Action that playbook allows,
 * attaches the Action's own Runbook procedure and the Policy Engine result
 * for (incident, action) via ApprovalService.evaluate — the same single
 * Policy path CreateResponsePlan uses. The AI only ever sees these; it never
 * picks the playbook, the role or the approval requirement itself.
 *
 * Knowledge Expansion (Step 9): each allowed Action also carries whether it applies to the incident's attack type
 * (domain/knowledge), the ACTION_COMPLIANCE policies in force for it, and the deterministic evidence check
 * (ActionEvidence.ts) — which recorded targets satisfy every required evidence item. An Action that is not
 * applicable or whose evidence is not recorded is shown to the AI as not recommendable; the validator enforces it.
 */
export class RecommendationContextBuilder {
  constructor(
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly actionRepository: IActionRepository,
    private readonly runbookRepository: IRunbookRepository,
    private readonly playbookRepository?: IPlaybookRepository,
    private readonly policyService?: Pick<ApprovalService, "evaluate">,
    private readonly playbookSelector: PlaybookSelector = new PlaybookSelector(),
    /** SOC response setup: confirmed incident type (-> playbook) and the case / group guidance (-> allowed actions). */
    private readonly responseSetup?: Pick<IncidentResponseSetupService, "resolve">,
    /** ACTION_COMPLIANCE policies (evidence an Action requires). Absent -> only the Action's own knowledge applies. */
    private readonly compliancePolicy?: Pick<PolicyEvaluator, "actionCompliance">
  ) {}

  async build(incidentId: string, tenantId: string): Promise<Result<RecommendationContextDto, "INCIDENT_NOT_FOUND">> {
    const incident = await this.contextRepository.getIncidentContext(incidentId, tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");

    const [iocs, mitreMappings, actions, runbooks, evidence, aiAnalysis, previousSteps] = await Promise.all([
      // Only this investigation cycle's IOCs: a later cycle starts from its own evidence, not the previous one's.
      this.contextRepository.getIocs(incidentId, incident.investigationNumber),
      this.contextRepository.getMitreMappings(incidentId),
      this.actionRepository.findAll(tenantId),
      this.runbookRepository.findAll(tenantId),
      this.contextRepository.getEvidence(incidentId, incident.investigationNumber),
      this.contextRepository.getLatestAiAnalysis(incidentId),
      // Earlier Recommendations (all rounds): a new one must add at least one Action + target pair not proposed before.
      this.contextRepository.getPreviousRecommendationSteps?.(incidentId, tenantId) ?? Promise.resolve([]),
    ]);

    // With the SOC setup: the SOC-confirmed type picks the playbook, and only the actions its guidance allows are
    // offered (RecommendationValidator rejects any other). Without it: the MITRE match and all playbook actions.
    const setup = this.responseSetup ? await this.responseSetup.resolve(incidentId, tenantId) : null;
    const playbooks = setup ? [] : this.playbookRepository ? await this.playbookRepository.findAll(tenantId) : [];
    const selected = setup?.isSuccess ? setup.value.selected : this.playbookSelector.select(playbooks, mitreMappings.map((m) => m.techniqueId));
    const guidance = setup?.isSuccess ? setup.value.effective : null;
    const playbook = selected && guidance ? { ...selected, allowedActions: selected.allowedActions.filter((a) => guidance.allowedActions.includes(a)) } : selected;
    const runbookById = new Map(runbooks.map((r) => [r.id, r]));
    const actionProcedures: RecommendationContextActionProcedure[] = [];
    for (const code of playbook?.allowedActions ?? []) {
      const action = actions.find((a) => a.code === code && a.enabled && a.category === "CONTAINMENT");
      if (!action) continue;
      const runbook = action.runbookId ? runbookById.get(action.runbookId) : undefined;
      actionProcedures.push({
        actionCode: action.code,
        actionName: action.name,
        description: action.description,
        impactLevel: action.impactLevel,
        runbookCode: runbook?.isActive ? runbook.code : null,
        runbookObjective: runbook?.isActive ? runbook.objective : null,
        procedure: runbook?.isActive ? runbook.procedure : [],
        expectedResult: runbook?.isActive ? runbook.expectedResult : null,
        verificationCriteria: runbook?.isActive ? runbook.verificationCriteria : [],
        policy: await this.policyFor(tenantId, incidentId, action.id),
        compliance: this.compliancePolicy
          ? await this.compliancePolicy.actionCompliance(tenantId, { actionCode: action.code })
          : { policies: [], requiredEvidence: [], rules: [] },
      });
    }

    const context: RecommendationContextDto = {
      incidentId: incident.incidentId,
      investigationNumber: incident.investigationNumber,
      incidentTitle: incident.title,
      incidentStatus: incident.status,
      incidentPriority: incident.priority,
      alertSeverity: incident.alertSeverity,
      // Stable citation ids (E<n>/I<n>, in repository order) — the AI cites these instead of reproducing values.
      iocs: iocs.map((i, n) => ({
        iocType: i.iocType,
        iocValue: i.iocValue,
        source: i.source,
        reputationScore: i.reputationScore,
        manual: i.manual ?? false,
        ref: `I${n + 1}`,
        ...(i.networkRole ? { networkRole: i.networkRole } : {}),
      })),
      mitreMappings: mitreMappings.map((m) => ({
        techniqueId: m.techniqueId,
        tactic: m.tactic,
        confidence: m.confidence,
      })),
      severity: incidentSeverity(incident),
      evidence: evidence.map((e, n) => ({
        ref: `E${n + 1}`,
        type: e.type,
        source: e.source,
        origin: e.origin,
        title: e.title,
        timestamp: e.timestamp.toISOString(),
        host: e.host,
        ruleId: e.ruleId,
        iocValues: e.iocValues,
      })),
      affectedHosts: [...new Set(evidence.map((e) => e.host).filter((h): h is string => !!h))],
      // Only a grounded AI analysis may inform the recommendation; an UNGROUNDED one (names an indicator the incident
      // does not hold) is kept for human review but never becomes trusted input.
      aiAnalysis: aiAnalysis?.grounding.status === "GROUNDED" ? { summary: aiAnalysis.summary, keyFindings: aiAnalysis.keyFindings } : null,
      availableActions: actions
        .filter((a) => a.enabled)
        .map((a) => ({
          code: a.code,
          name: a.name,
          category: a.category,
          impactLevel: a.impactLevel,
          defaultApprovalRequired: a.defaultApprovalRequired,
        })),
      availableRunbooks: runbooks
        .filter((r) => r.status === "ACTIVE")
        .map((r) => ({
          code: r.code,
          name: r.name,
          trigger: r.trigger,
          objective: r.objective,
          procedure: r.procedure,
          verificationCriteria: r.verificationCriteria,
        })),
      incidentType: playbook?.incidentType ?? null,
      attackType: attackTypeForIncidentType(playbook?.incidentType),
      playbook,
      actionProcedures,
      socGuidance: guidance ? { source: guidance.source, allowedActions: playbook?.allowedActions ?? [], instructions: guidance.instructions } : null,
      previousSteps,
    };

    // Applicability + evidence need the finished context (this cycle's IOCs, evidence rows, affected hosts).
    for (const p of actionProcedures) {
      const knowledge = findActionKnowledge(p.actionCode);
      p.applicable = context.attackType ? !!knowledge?.applicableAttackTypes.includes(context.attackType as never) : true;
      p.evidence = { ...evaluateActionEvidence(context, p.actionCode, p.compliance?.requiredEvidence ?? []), analystConfirmed: knowledge?.analystConfirmed ?? [] };
    }

    return Result.ok(context);
  }

  private async policyFor(tenantId: string, incidentId: string, actionId: string): Promise<RecommendationContextPolicy> {
    if (!this.policyService) {
      return { responsibleRole: null, reviewRequired: false, reviewRole: null, approvalRequired: false, approvalRole: null, matchedRules: [] };
    }
    const { policy } = await this.policyService.evaluate({ tenantId, incidentId, actionId });
    return {
      responsibleRole: policy.responsibleRole ?? null,
      reviewRequired: policy.reviewRequired,
      reviewRole: policy.reviewRole ?? null,
      approvalRequired: policy.approvalRequired,
      approvalRole: policy.approvalRole ?? null,
      matchedRules: policy.matchedRules ?? [],
    };
  }
}
