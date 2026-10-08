import { applicableProcedure, contextSignals } from "../../application/recommendation/services/ProcedureApplicability";
import { spreadResponseOptions } from "../../application/recommendation/services/SpreadResponseCoverage";
import { ASSUMPTION_RULES, ATTACK_SPECIFIC_CONTROLS } from "../../domain/knowledge/evidenceSignals";
import { IActionRepository } from "../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../domain/runbook/repositories/IRunbookRepository";
import {
  RecommendationContextActionProcedure,
  RecommendationContextDto,
  RecommendationContextProcedureStep,
  citableEvidence,
  newStepOptions,
  noveltyHistory,
  stepKey,
  targetableIocValues,
} from "../../application/recommendation/dto/RecommendationContextDto";
import {
  recommendationCandidateSchema,
  RecommendationCandidateStepDto,
} from "../../application/recommendation/dto/RecommendationCandidateDto";
import {
  CreateRecommendationStepData,
  RecommendationSnapshotData,
} from "../../domain/recommendation/repositories/IRecommendationRepository";
import { ACTION_KNOWLEDGE, findActionKnowledge } from "../../domain/knowledge/actionKnowledge";
import { attackTypeForIncidentType } from "../../domain/knowledge/attackKnowledge";
import { TargetKind, iocKind } from "../../domain/knowledge/knowledgeTypes";
import { missingEvidenceForTarget } from "../../application/recommendation/services/ActionEvidence";
import { compatibleIocRole } from "../../application/recommendation/services/IocRole";

export interface RecommendationValidationOutcome {
  status: "VALIDATED" | "INVALID";
  summary: string;
  steps: CreateRecommendationStepData[];
  violations: string[];
  /** What the validated recommendation was grounded in (persisted as a PlaybookSnapshot). Null when INVALID. */
  snapshot: RecommendationSnapshotData | null;
}

/**
 * Violation codes (Response Process Recommendation v2, Task 10.3). ANY
 * violation makes the whole candidate INVALID: nothing is persisted, no
 * ResponsePlan can be created, and the use case audits the failure. There is
 * no partial repair/downgrade — a recommendation that needed fixing is not
 * the AI's recommendation any more.
 */
export type RecommendationViolationCode =
  | "SCHEMA"
  | "NO_PLAYBOOK"
  | "PLAYBOOK_MISMATCH"
  | "INVENTED_ACTION"
  | "DISABLED_ACTION"
  | "ACTION_NOT_IN_PLAYBOOK"
  | "ACTION_NOT_APPLICABLE"
  | "INSUFFICIENT_EVIDENCE"
  | "RUNBOOK_MISMATCH"
  | "INVENTED_TARGET"
  | "TARGET_TYPE_MISMATCH"
  | "IOC_ROLE_MISMATCH"
  | "INVENTED_IOC"
  | "INVENTED_HOST"
  | "INVENTED_COMMAND"
  | "INVENTED_EVIDENCE"
  | "NO_EVIDENCE"
  | "WRONG_RESPONSIBLE_ROLE"
  | "POLICY_UNAVAILABLE"
  | "POLICY_BYPASS"
  | "CORE_FLOW_REPETITION"
  | "EMPTY_INSTRUCTIONS"
  | "INVALID_INSTRUCTIONS"
  | "DUPLICATE_STEP"
  | "NO_NEW_STEP"
  | "STEP_TYPE_MISMATCH"
  | "UNGROUNDED_STEP"
  | "PROCEDURE_REQUIREMENT_MISSING"
  | "CONDITION_MISSING"
  | "NO_ACTION_STEP"
  | "SPREAD_RESPONSE_MISSING"
  | "IRRELEVANT_PHASE"
  | "STATUS_MISMATCH"
  | "UNSUPPORTED_ASSUMPTION"
  | "UNRELATED_ATTACK_CONTROL";

/**
 * What kind of target each containment Action operates on (domain/knowledge/actionKnowledge.ts). A target must be a
 * recorded value of that kind — e.g. Block Source IP on a hostname, or Disable Account on an IP, is rejected even
 * though both values are "known".
 */
const ACTION_TARGET_KIND: Record<string, TargetKind> = Object.fromEntries(
  ACTION_KNOWLEDGE.filter((a) => a.targetKind).map((a) => [a.code, a.targetKind as TargetKind])
);

/** Core Flow phases the platform itself performs — an action-level instruction must never restate them. */
const CORE_FLOW_INSTRUCTION_PATTERNS: RegExp[] = [
  /\bre-?hunt/i,
  /\bmonitor(?:ing)?\b/i,
  /\b(?:request|obtain|seek|await|get)\b[^.]{0,30}\bapproval\b/i,
  /\b(?:close|resolve|mark)\b[^.]{0,20}\b(?:incident|case)\b/i,
  /\bvalidate (?:the )?(?:incident|alert)\b/i,
  /\bassess (?:the )?containment need\b/i,
  /\bprepare (?:a |the )?response plan\b/i,
  /\bcollect (?:additional |more )?evidence\b/i,
];
/** A summary naming 4+ Core Flow phases is the generic flow, not an action-level recommendation. */
const CORE_FLOW_PHASES: RegExp[] = [/\bvalidat/i, /\bcheck/i, /\bblock/i, /\bmonitor/i, /\bre-?hunt/i, /\bverif/i];

const BYPASS_PATTERNS: RegExp[] = [
  /\b(?:without|skip(?:ping)?|bypass(?:ing)?|no need (?:for|to)|override|circumvent)\b[^.]{0,30}\b(?:approval|policy|authori[sz]ation)\b/i,
  /\b(?:pre-?approved|already (?:been )?approved|auto(?:matic(?:ally)?)?[- ]?(?:execut|approv|contain|clos)\w*)\b/i,
];
/** Only a bypass when Policy DOES require approval for the action. */
const APPROVAL_DENIAL_PATTERN = /\bapproval (?:is )?not (?:required|needed)\b|\bno approval\b/i;

/** A sentence that asks, conditions or hedges (checks, "if ...", "whether ...") is not an assertion of fact. */
const CONDITIONAL_SENTENCE = /\b(?:if|when|whether|unless|in case|until|should|would|could|may|might|possible|possibly|determine|check|verify|confirm|assess|investigate|review|ensure|rule out|look for)\b/i;

const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const HASH = /\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi;
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]]+/gi;
const EMAIL = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g;
const DOMAIN =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|co|uk|de|local|onion|gov|edu|mil|int|tk|su|cc|me|us|th|online|site|club)\b/gi;
const PORT = /\b(?:ports?|tcp|udp)\s*[:/#=]?\s*(\d{1,5})\b|\b(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b/gi;
const HOST_TOKEN = /\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b/g;
const NON_HOST_PREFIXES = /^(?:ACT|RB|PB|RULE|POL|STC|ATK|CVE|SNAP|SHA|MD|UTF|RFC|TLS|SSL|ISO|NIST)-/;
const COMMAND =
  /`[^`]+`|\b(?:iptables|ip6tables|nft|ufw|firewall-cmd|netsh|pfctl|sudo|chmod|systemctl|taskkill|wmic|Stop-Process|Set-ADUser|Disable-ADAccount|Remove-Item|New-NetFirewallRule|Set-NetFirewallRule|Invoke-[A-Za-z]+|net\s+user|reg\s+(?:add|delete)|kill\s+-9)\b/gi;

/**
 * RecommendationValidator — the ONLY place AI output for a Recommendation is
 * allowed to become trusted data. Pure, deterministic, no LLM. Re-resolves
 * every Action/Runbook code against the live catalogs (tenant-scoped,
 * RULE-011) and checks every other field against the backend-built context:
 * the selected incident-level Playbook, each Action's own Runbook, and the
 * Policy Engine result per Action.
 *
 * v2 (Task 10.3) — a Recommendation is 1..N action-level steps, each ONE
 * containment Action on ONE recorded target with ordered operational
 * instructions for the Policy-assigned role. Rejected (whole candidate):
 *   invented/disabled action, action outside the selected playbook,
 *   INVESTIGATION/VERIFICATION action or Core-Flow wording (Core Flow
 *   repetition), runbook ≠ the action's linked runbook, playbook ≠ the
 *   selected playbook, target not a recorded value of the right kind,
 *   IP/hash/URL/domain/e-mail/port/host/command in free text that the
 *   evidence does not contain, fabricated or missing evidence refs,
 *   responsibleRole ≠ Policy, any attempt to waive/skip/pre-empt approval,
 *   empty or mis-ordered instructions, duplicate action+target steps.
 * requiresApproval is taken from Policy, never from the AI (RULE-006/010).
 *
 * Knowledge Expansion (Step 9) — also rejected:
 *   ACTION_NOT_APPLICABLE  the Action does not apply to the incident's attack type (domain/knowledge), or has no
 *                          attack-type knowledge at all while the attack type is known — the AI can never extend
 *                          the attack -> action mapping;
 *   INSUFFICIENT_EVIDENCE  the target lacks evidence the Action requires (its own knowledge) or an ACTION_COMPLIANCE
 *                          Policy requires (POL-A02 / POL-A03) — ActionEvidence.ts, deterministic.
 *
 * Attack-specific containment procedure (context.containmentProcedure) — steps are typed CHECK / ACTION / MANUAL:
 *   STEP_TYPE_MISMATCH     a CHECK / MANUAL step names an action (checks are never executable Actions);
 *   UNGROUNDED_STEP        a CHECK / MANUAL step does not derive from a procedure step holding an item of its type
 *                          (or there is no procedure), or an ACTION step cites a procedure step without that Action;
 *   CONDITION_MISSING      an ACTION step drops the condition the procedure attaches to the Action;
 *   NO_ACTION_STEP         no ACTION step at all — checks and manual controls alone contain nothing.
 *   The ACTION checks above apply unchanged; CHECK / MANUAL steps get the same free-text, evidence-reference,
 *   instruction and approval-bypass checks, are persisted with no actionId and are never ticketed or executed.
 *
 * New round / regenerate — also rejected:
 *   NO_NEW_STEP            every step repeats an Action + target pair an earlier Recommendation of this incident
 *                          already proposed. The same Action on a new target is new; a repeated pair is fine next to
 *                          at least one new one.
 */
export class RecommendationValidator {
  constructor(
    private readonly actionRepository: IActionRepository,
    private readonly runbookRepository: IRunbookRepository
  ) {}

  async validate(rawCandidate: unknown, context: RecommendationContextDto, tenantId: string): Promise<RecommendationValidationOutcome> {
    const parsed = recommendationCandidateSchema.safeParse(rawCandidate);
    if (!parsed.success) {
      const emptyInstructions = parsed.error.issues.some((i) => i.path.includes("instructions"));
      return invalid(
        "The AI-proposed candidate failed schema validation and produced no usable recommendation.",
        [`${emptyInstructions ? "EMPTY_INSTRUCTIONS" : "SCHEMA"}: candidate failed schema validation: ${parsed.error.message}`]
      );
    }
    const candidate = parsed.data;
    const violations: string[] = [];
    const flag = (code: RecommendationViolationCode, message: string) => violations.push(`${code}: ${message}`);

    const playbook = context.playbook ?? null;
    const investigationOnly = context.investigationOnly === true;
    if (!playbook && !investigationOnly) flag("NO_PLAYBOOK", "no incident-level playbook matches this incident's MITRE techniques, so no response action can be recommended");

    const procedures = new Map<string, RecommendationContextActionProcedure>((context.actionProcedures ?? []).map((p) => [p.actionCode, p]));
    const actionCodes = [...new Set(candidate.steps.map((s) => s.action).filter((a): a is string => !!a))];
    const actions = await this.actionRepository.findByCodes(actionCodes, tenantId);
    const actionByCode = new Map(actions.map((a) => [a.code, a]));

    // Ground truth for free-text checks: only what the incident actually recorded.
    const hosts = context.affectedHosts ?? [];
    // Only IOCs linked to this cycle's evidence or added by an analyst are actionable targets. An IOC the
    // pipeline merely extracted (e.g. the victim agent's own IP) is context, not something to contain.
    const targetable = targetableIocValues(context);
    // One value can be several kinds at once (a binary's path is both a FILE_PATH and a PROCESS_NAME): keep every kind.
    const iocKindsByValue = new Map<string, Set<TargetKind>>();
    for (const i of context.iocs) {
      if (!targetable.has(i.iocValue)) continue;
      const kinds = iocKindsByValue.get(i.iocValue) ?? new Set<TargetKind>();
      kinds.add(iocKind(i.iocType));
      iocKindsByValue.set(i.iocValue, kinds);
    }
    const evidenceText = [
      context.incidentTitle,
      ...context.iocs.map((i) => i.iocValue),
      ...hosts,
      ...context.evidence.flatMap((e) => [e.title, e.host ?? "", ...e.iocValues]),
    ]
      .join("\n")
      .toLowerCase();
    // Evidence is cited ONLY by the stable ids the backend assigned (E<n> evidence row, I<n> IOC, recorded MITRE
    // technique id), resolved exactly here to the recorded value that is persisted. Any other string — an unknown
    // id, a free-text title, a value — is invented evidence. The AI never reproduces long titles.
    const citable = citableEvidence(context);

    // A containment procedure legitimately spans check -> block -> verify, so its summary is not the generic Core Flow.
    const procedure = applicableProcedure(context.containmentProcedure, context);
    const summaryPhases = CORE_FLOW_PHASES.filter((p) => p.test(candidate.summary)).length;
    if (!procedure && summaryPhases >= 4) flag("CORE_FLOW_REPETITION", `summary restates the VIGIX Core Flow (${summaryPhases} lifecycle phases) instead of the selected action(s)`);
    this.checkFreeText("summary", candidate.summary, evidenceText, hosts, flag);
    for (const p of BYPASS_PATTERNS) if (p.test(candidate.summary)) flag("POLICY_BYPASS", "summary claims approval/authorization is waived or automatic");

    // Response quality contract: attack-specific, evidence-grounded, never an assumption presented as fact.
    const signals = contextSignals(context);
    const incidentAttackType = context.attackType ?? null;
    const retrieved = new Map((context.retrievedKnowledge ?? []).map((k) => [k.ref, k]));
    const checkClaims = (label: string, text: string, groundedByKnowledge: boolean) => {
      for (const sentence of text.split(/(?<=[.!?])\s+/)) {
        if (CONDITIONAL_SENTENCE.test(sentence)) continue;
        for (const rule of ASSUMPTION_RULES) {
          if (rule.pattern.test(sentence) && !rule.requires.some((s) => signals.has(s)) && !(incidentAttackType && rule.types.includes(incidentAttackType))) {
            flag("UNSUPPORTED_ASSUMPTION", `${label}: states ${rule.claim} as fact, but the incident evidence does not establish it ("${sentence.slice(0, 120)}")`);
          }
        }
        if (groundedByKnowledge) continue;
        for (const control of ATTACK_SPECIFIC_CONTROLS) {
          if (control.pattern.test(sentence) && !(incidentAttackType && control.onlyFor.includes(incidentAttackType))) {
            flag("UNRELATED_ATTACK_CONTROL", `${label}: ${control.description} does not belong to ${incidentAttackType ?? "an unclassified"} incident ("${sentence.slice(0, 120)}")`);
          }
        }
      }
    };
    checkClaims("summary", candidate.summary, false);
    const quality = (label: string, step: RecommendationCandidateStepDto, source: { phase: string } | null, groundedByKnowledge: boolean) => {
      if (step.phase && source?.phase && step.phase !== source.phase) {
        flag("IRRELEVANT_PHASE", `${label}: phase "${step.phase}" is not the phase of the knowledge it derives from (${source.phase}) — the step does not belong in this response`);
      }
      if (step.status === "CONFIRMED" && (step.evidenceRefs.length === 0 || step.condition)) {
        flag("STATUS_MISMATCH", `${label}: status CONFIRMED needs cited evidence and no open condition`);
      }
      if (step.status === "CONDITIONAL" && !step.condition) flag("CONDITION_MISSING", `${label}: a CONDITIONAL step must state its condition`);
      for (const ref of step.knowledgeRefs) {
        if (!retrieved.has(ref)) flag("INVENTED_EVIDENCE", `${label}: knowledge reference "${ref}" was not retrieved for this incident`);
      }
      // An ACTION's instructions are its runbook's own wording and a conditional ACTION carries a human-confirmed
      // precondition instead of a claim, so only the AI-authored reason of an unconditional ACTION is checked.
      if (step.type === "ACTION" && step.condition) return;
      const prose = step.type === "ACTION" ? [step.reason] : [step.objective, step.reason, step.expectedResult ?? "", ...step.instructions.map((i) => i.instruction)];
      for (const text of prose) checkClaims(label, text, groundedByKnowledge);
    };
    /** UNKNOWN_INCIDENT only: a step grounded in retrieved knowledge instead of a procedure step. */
    const knowledgeStep = (step: RecommendationCandidateStepDto): RecommendationContextProcedureStep | null => {
      if (!investigationOnly || step.knowledgeRefs.length === 0) return null;
      const items = step.knowledgeRefs.map((r) => retrieved.get(r));
      if (items.some((k) => !k)) return null;
      const k = items[0]!;
      return {
        stepOrder: 0, phase: k.phase, title: k.title, objective: k.guidance, reason: k.guidance, expectedResult: "", decisionRef: null, responsibleRole: "IR_TEAM", approvalRequired: k.requiresApproval,
        items: [{ type: k.kind, text: k.guidance, actionCode: null, condition: null, requiresApproval: k.requiresApproval, approver: null }],
      };
    };

    const steps: CreateRecommendationStepData[] = [];
    const seen = new Set<string>();
    const snapshotRunbooks: { actionCode: string; runbookCode: string; version: string; procedure: string[]; verificationCriteria: string[] }[] = [];
    const snapshotPolicy: Record<string, unknown> = {};
    const ordered = [...candidate.steps].sort((a, b) => a.stepOrder - b.stepOrder);
    // A CHECK must precede the control it informs; the model cannot reorder the knowledge strategy.
    if (procedure && ordered.some((s, i) => i > 0 && s.procedureStep != null && ordered[i - 1].procedureStep != null && s.procedureStep < ordered[i - 1].procedureStep!)) {
      flag("UNGROUNDED_STEP", "containment steps must preserve the applicable procedure's decision/control/verification order");
    }
    const procedureStep = (n: number | null | undefined) => (procedure && n ? procedure.steps.find((s) => s.stepOrder === n) ?? null : null);
    const recordedValues = new Set([...hosts, ...context.iocs.map((i) => i.iocValue)]);

    for (const [index, step] of ordered.entries()) {
      // ---- CHECK / MANUAL: grounded in the containment procedure, never an executable Action ---------------------
      if (step.type !== "ACTION") {
        const label = `step ${step.stepOrder} (${step.type})`;
        const before = violations.length;
        if (step.action) {
          flag(
            "STEP_TYPE_MISMATCH",
            actionByCode.has(step.action)
              ? `${label}: ${step.action} is a catalog Action — a ${step.type} step must not carry an executable action; use an ACTION step`
              : `${label}: a ${step.type} step must not name an action ("${step.action}")`
          );
        }
        if (!procedure) {
          flag("UNGROUNDED_STEP", `${label}: no containment procedure is available for this incident, so a ${step.type} step cannot be grounded in knowledge`);
          continue;
        }
        const fromKnowledge = step.procedureStep == null ? knowledgeStep(step) : null;
        const source = procedureStep(step.procedureStep) ?? fromKnowledge;
        quality(label, step, source, !!fromKnowledge);
        if (!source) {
          flag("UNGROUNDED_STEP", `${label}: procedureStep ${step.procedureStep ?? "(missing)"} is not a step of the ${procedure.procedureCode} procedure${investigationOnly ? ", and no retrieved knowledge (knowledgeRefs) supports it" : ""}`);
        } else if (!source.items.some((i) => i.type === step.type)) {
          flag("UNGROUNDED_STEP", `${label}: procedure step ${source.stepOrder} "${source.title}" has no ${step.type} item — the step is not supported by the knowledge`);
        }
        if (playbook && step.playbook && step.playbook !== playbook.code) {
          flag("PLAYBOOK_MISMATCH", `${label}: playbook "${step.playbook}" does not match the playbook selected for this ${playbook.incidentType} incident (${playbook.code})`);
        }
        if (source && step.responsibleRole !== source.responsibleRole) {
          flag("WRONG_RESPONSIBLE_ROLE", `${label}: responsibleRole "${step.responsibleRole}" differs from the procedure (${source.responsibleRole})`);
        }
        if (step.target && !recordedValues.has(step.target)) {
          flag("INVENTED_TARGET", `${label}: target "${step.target}" is not a recorded IOC or affected host`);
        }
        // A manual control the procedure puts under an owner's approval stays under it — the AI cannot waive it.
        const manualCondition = step.type === "MANUAL" ? source?.items.find(i => i.type === "MANUAL" && i.condition)?.condition : null;
        if (manualCondition && !step.condition) flag("CONDITION_MISSING", `${label}: manual control requires condition "${manualCondition}"`);
        const manualApproval = step.type === "MANUAL" && !!source?.items.some((i) => i.type === "MANUAL" && i.requiresApproval);
        const freeText = [step.objective, step.reason, step.condition ?? "", step.expectedResult ?? "", step.verificationCriteria, ...step.instructions.flatMap((i) => [i.instruction, i.expectedResult ?? ""])];
        for (const text of freeText) {
          if (BYPASS_PATTERNS.some((p) => p.test(text)) || (manualApproval && APPROVAL_DENIAL_PATTERN.test(text))) {
            flag("POLICY_BYPASS", `${label}: text waives, skips or pre-empts approval/authorization ("${text.slice(0, 120)}")`);
            break;
          }
        }
        if (manualApproval && step.requiresApprovalSuggested === false) {
          flag("POLICY_BYPASS", `${label}: candidate marks approval as not required, but the procedure puts this manual control under approval`);
        }
        const fabricated = step.evidenceRefs.filter((ref) => !citable.has(ref));
        for (const ref of fabricated) flag("INVENTED_EVIDENCE", `${label}: evidence reference "${ref}" is not one of this cycle's evidence ids (E<n>/I<n>/MITRE technique)`);
        const evidence = [...new Set(step.evidenceRefs.map((ref) => citable.get(ref)).filter((r): r is string => !!r))];
        const instructions = [...step.instructions].sort((x, y) => x.order - y.order);
        if (instructions.some((ins, i) => ins.order !== i + 1)) {
          flag("INVALID_INSTRUCTIONS", `${label}: instruction order must be 1..${instructions.length} without gaps or duplicates`);
        }
        for (const ins of instructions) {
          if (ins.target && !recordedValues.has(ins.target)) {
            flag("INVENTED_TARGET", `${label}: instruction ${ins.order} targets "${ins.target}", which is not a recorded IOC or affected host`);
          }
        }
        for (const text of freeText) this.checkFreeText(label, text, evidenceText, hosts, flag);
        if (violations.length > before || !source) continue;

        steps.push({
          stepOrder: index + 1,
          stepType: step.type,
          title: `${step.type === "CHECK" ? "Check" : "Manual control"} — ${source.title}`,
          objective: step.objective,
          actionId: null,
          target: step.target ?? null,
          reason: step.missingEvidence.length ? `${step.reason} Missing evidence: ${step.missingEvidence.join(", ")}.` : step.reason,
          evidence,
          sourceRunbookId: null,
          precondition: manualCondition ?? step.condition ?? null,
          expectedResult: step.expectedResult ?? source.expectedResult ?? null,
          requiresApproval: manualApproval,
          instructions: instructions.map((i) => ({ order: i.order, instruction: i.instruction, target: i.target ?? step.target ?? null, expectedResult: i.expectedResult ?? null })),
          verificationCriteria: step.verificationCriteria,
        });
        continue;
      }

      const label = `step ${step.stepOrder} (${step.action ?? "no action"})`;
      if (investigationOnly) {
        flag("NO_PLAYBOOK", `${label}: no attack-specific playbook applies to this incident, so no catalog Action can be recommended — investigate first`);
        continue;
      }
      quality(label, step, procedureStep(step.procedureStep), false);
      if (!step.action || !step.target || !step.runbook || !step.playbook) {
        flag("SCHEMA", `${label}: an ACTION step needs action, target, runbook and playbook`);
        continue;
      }
      const a = step as RecommendationCandidateStepDto & { action: string; target: string; runbook: string; playbook: string };
      const before = violations.length;

      // ---- Action ------------------------------------------------------------------------------
      const action = actionByCode.get(a.action);
      if (!action) {
        flag("INVENTED_ACTION", `${label}: action "${a.action}" does not exist in the Action Catalog`);
        continue;
      }
      if (!action.enabled) flag("DISABLED_ACTION", `${label}: action is disabled`);
      if (action.category !== "CONTAINMENT") {
        flag("CORE_FLOW_REPETITION", `${label}: ${action.category} is a VIGIX Core Flow phase performed by the platform, not a response action to expand`);
      }
      const procedureOfAction = procedures.get(action.code);
      if (playbook && !procedureOfAction) flag("ACTION_NOT_IN_PLAYBOOK", `${label}: action is not allowed by playbook ${playbook.code} (${playbook.allowedActions.join(", ") || "none"})`);
      const attackType = attackTypeForIncidentType(playbook?.incidentType);
      if (attackType) {
        const knowledge = findActionKnowledge(action.code);
        if (!knowledge) flag("ACTION_NOT_APPLICABLE", `${label}: ${action.code} has no attack-type knowledge, so it cannot be recommended for ${attackType}`);
        else if (!knowledge.applicableAttackTypes.includes(attackType)) {
          flag("ACTION_NOT_APPLICABLE", `${label}: ${action.code} does not apply to ${attackType} (applies to ${knowledge.applicableAttackTypes.join(", ") || "none"})`);
        }
      }

      // ---- Containment procedure: the Action's condition is never dropped -----------------------
      const knowledgeCondition = procedure?.candidateActions.find((c) => c.actionCode === action.code)?.condition ?? null;
      if (knowledgeCondition && !a.condition) {
        flag("CONDITION_MISSING", `${label}: the ${procedure!.procedureCode} procedure makes ${action.code} conditional ("${knowledgeCondition}") — the step must carry that condition`);
      }
      if (procedure) {
        const source = procedureStep(a.procedureStep);
        if (!source || !source.items.some((i) => i.actionCode === action.code)) {
          flag("UNGROUNDED_STEP", `${label}: procedure step ${a.procedureStep} of ${procedure.procedureCode} does not contain ${action.code}`);
        }
      }

      // ---- Playbook / Runbook --------------------------------------------------------------------
      if (playbook && a.playbook !== playbook.code) {
        flag("PLAYBOOK_MISMATCH", `${label}: playbook "${a.playbook}" does not match the playbook selected for this ${playbook.incidentType} incident (${playbook.code})`);
      }
      const runbook = action.runbookId ? await this.runbookRepository.findById(action.runbookId, tenantId) : null;
      if (!runbook || !runbook.isActive) {
        flag("RUNBOOK_MISMATCH", `${label}: action has no ACTIVE action-level runbook, so it cannot be expanded`);
      } else if (a.runbook !== runbook.code) {
        flag("RUNBOOK_MISMATCH", `${label}: runbook "${a.runbook}" is not the runbook of ${action.code} (${runbook.code})`);
      }

      // ---- Target --------------------------------------------------------------------------------
      const targetKinds: ReadonlySet<TargetKind> | undefined = hosts.includes(a.target) ? new Set<TargetKind>(["host"]) : iocKindsByValue.get(a.target);
      const requiredKind = ACTION_TARGET_KIND[action.code];
      if (targetKinds?.has("ip") && !compatibleIocRole(context, action.code, a.target)) {
        flag("IOC_ROLE_MISMATCH", `${label}: target "${a.target}" has an incompatible, unknown or ambiguous network role for ${action.code}; use only explicitly recorded source/destination roles`);
      }
      if (!targetKinds) {
        flag("INVENTED_TARGET", `${label}: target "${a.target}" is not an evidence-linked/analyst-added IOC or an affected host`);
      } else if (requiredKind && !targetKinds.has(requiredKind)) {
        flag("TARGET_TYPE_MISMATCH", `${label}: target "${a.target}" is a ${[...targetKinds].join("/")}, but ${action.code} operates on a ${requiredKind}`);
      }
      // Required evidence (Action knowledge + ACTION_COMPLIANCE policy). VALIDATED_IOC_TARGET is reported by the
      // INVENTED_TARGET / TARGET_TYPE_MISMATCH checks above with a more precise message.
      if (targetKinds) {
        const compliance = procedureOfAction?.compliance;
        const missing = missingEvidenceForTarget(context, action.code, a.target, compliance?.requiredEvidence ?? []).filter((r) => r !== "VALIDATED_IOC_TARGET");
        if (missing.length) {
          const source = (r: string) => compliance?.rules.filter((x) => x.requiredEvidence.includes(r)).map((x) => x.policy) ?? [];
          const detail = missing.map((r) => (source(r).length ? `${r} (${source(r).join(", ")})` : r)).join(", ");
          flag("INSUFFICIENT_EVIDENCE", `${label}: required evidence is not recorded for target "${a.target}": ${detail}`);
        }
      }
      const pairKey = `${action.code}|${a.target}`;
      if (seen.has(pairKey)) flag("DUPLICATE_STEP", `${label}: the same action on the same target appears more than once`);
      seen.add(pairKey);

      // ---- Policy (authoritative role / approval) ------------------------------------------------
      const policy = procedureOfAction?.policy ?? null;
      if (procedureOfAction && (!policy || !policy.responsibleRole)) {
        flag("POLICY_UNAVAILABLE", `${label}: no Policy result for this action — responsible role cannot be established`);
      } else if (policy && a.responsibleRole !== policy.responsibleRole) {
        flag("WRONG_RESPONSIBLE_ROLE", `${label}: responsibleRole "${a.responsibleRole}" differs from Policy (${policy.responsibleRole})`);
      }
      const freeText = [a.objective, a.reason, a.condition ?? "", a.expectedResult ?? "", a.verificationCriteria, ...a.instructions.flatMap((i) => [i.instruction, i.expectedResult ?? ""])];
      for (const text of freeText) {
        if (BYPASS_PATTERNS.some((p) => p.test(text)) || (policy?.approvalRequired && APPROVAL_DENIAL_PATTERN.test(text))) {
          flag("POLICY_BYPASS", `${label}: text waives, skips or pre-empts approval/authorization ("${text.slice(0, 120)}")`);
          break;
        }
      }
      if (policy?.approvalRequired && a.requiresApprovalSuggested === false) {
        flag("POLICY_BYPASS", `${label}: candidate marks approval as not required, but Policy requires ${policy.approvalRole ?? "an"} approval`);
      }

      // ---- Evidence ------------------------------------------------------------------------------
      const fabricated = a.evidenceRefs.filter((ref) => !citable.has(ref));
      for (const ref of fabricated) flag("INVENTED_EVIDENCE", `${label}: evidence reference "${ref}" is not one of this cycle's evidence ids (E<n>/I<n>/MITRE technique)`);
      const evidence = [...new Set(a.evidenceRefs.map((ref) => citable.get(ref)).filter((r): r is string => !!r))];
      if (evidence.length === 0) flag("NO_EVIDENCE", `${label}: no traceable evidence reference`);

      // ---- Instructions --------------------------------------------------------------------------
      const instructions = [...a.instructions].sort((x, y) => x.order - y.order);
      if (instructions.some((ins, i) => ins.order !== i + 1)) {
        flag("INVALID_INSTRUCTIONS", `${label}: instruction order must be 1..${instructions.length} without gaps or duplicates`);
      }
      for (const ins of instructions) {
        if (ins.target && ins.target !== a.target && !hosts.includes(ins.target) && !iocKindsByValue.has(ins.target)) {
          flag("INVENTED_TARGET", `${label}: instruction ${ins.order} targets "${ins.target}", which is not an evidence-linked/analyst-added IOC or an affected host`);
        }
      }
      for (const text of [a.objective, ...instructions.map((i) => i.instruction)]) {
        const phase = CORE_FLOW_INSTRUCTION_PATTERNS.find((p) => p.test(text));
        if (phase) {
          flag("CORE_FLOW_REPETITION", `${label}: "${text.slice(0, 120)}" restates a VIGIX Core Flow phase instead of an operational instruction for ${action.code}`);
          break;
        }
      }
      for (const text of freeText) this.checkFreeText(label, text, evidenceText, hosts, flag);

      if (violations.length > before) continue;

      steps.push({
        stepOrder: index + 1,
        stepType: "ACTION",
        title: `${action.name} — ${a.target}`,
        objective: a.objective,
        actionId: action.id,
        target: a.target,
        reason: a.missingEvidence.length ? `${a.reason} Missing evidence: ${a.missingEvidence.join(", ")}.` : a.reason,
        evidence,
        sourceRunbookId: runbook!.id,
        // The procedure's own condition is authoritative; the AI's wording is kept only when the procedure has none.
        precondition: knowledgeCondition ?? a.condition ?? null,
        expectedResult: a.expectedResult ?? runbook!.expectedResult ?? null,
        // Policy decides approval — the AI's advisory hint is never used here.
        requiresApproval: policy?.approvalRequired ?? false,
        instructions: instructions.map((i) => ({
          order: i.order,
          instruction: i.instruction,
          target: i.target ?? a.target,
          expectedResult: i.expectedResult ?? null,
        })),
        verificationCriteria: a.verificationCriteria,
      });
      snapshotRunbooks.push({
        actionCode: action.code,
        runbookCode: runbook!.code,
        version: runbook!.version,
        procedure: runbook!.procedure,
        verificationCriteria: runbook!.verificationCriteria,
      });
      snapshotPolicy[action.code] = policy;
    }

    for (const required of procedure?.steps ?? []) {
      for (const type of required.requiredTypes ?? []) {
        if (!ordered.some(s => s.procedureStep === required.stepOrder && s.type === type))
          flag("PROCEDURE_REQUIREMENT_MISSING", `procedure step ${required.stepOrder} requires ${type} for the recorded evidence`);
      }
    }
    // A response whose applicable procedure holds no executable step (every gated Action step was dropped for lack of
    // evidence, or the incident is unknown) is investigation-first and needs no ACTION.
    const procedureHasActions = !!procedure?.steps.some((s) => s.items.some((i) => i.type === "ACTION"));
    if (ordered.length && procedureHasActions && !investigationOnly && !ordered.some((s) => s.type === "ACTION")) {
      flag("NO_ACTION_STEP", "a containment recommendation needs at least one ACTION step (a catalog Action the evidence supports); CHECK / MANUAL steps alone contain nothing");
    }
    const actionSteps = ordered.filter((s) => s.type === "ACTION" && s.action && s.target);
    const previous = noveltyHistory(context);
    if (previous.length && actionSteps.length) {
      const proposed = new Set(previous.map((s) => stepKey(s.actionCode, s.target)));
      if (actionSteps.every((s) => proposed.has(stepKey(s.action!, s.target!)))) {
        const options = newStepOptions(context);
        flag(
          "NO_NEW_STEP",
          `every step repeats an Action + target pair an earlier Recommendation of this incident already proposed; include at least one new pair${options?.length ? ` (the evidence supports: ${options.map((o) => `${o.actionCode} -> ${o.target}`).join(", ")})` : ""}`
        );
      }
    }

    for (const group of spreadResponseOptions(context)) {
      if (group.options.length && !actionSteps.some(step => group.options.some(option => option.actionCode === step.action && option.target === step.target) &&
          (step.target === group.host || step.instructions.some(instruction => instruction.instruction.includes(group.host))))) {
        flag("SPREAD_RESPONSE_MISSING", `newly affected host "${group.host}" needs an evidence-supported action; eligible pairs: ${group.options.map(option => `${option.actionCode} -> ${JSON.stringify(option.target)}`).join(", ")}`);
      }
    }

    if (violations.length > 0 || steps.length === 0 || (!playbook && !investigationOnly)) {
      if (steps.length === 0 && violations.length === 0) violations.push("SCHEMA: no usable steps remained after validation");
      return invalid(candidate.summary, violations);
    }

    return {
      status: "VALIDATED",
      summary: candidate.summary,
      steps,
      violations: [],
      snapshot: {
        playbookCode: playbook?.code ?? "UNKNOWN_INCIDENT",
        playbookVersion: playbook?.version ?? "1",
        procedureCode: [...new Set(snapshotRunbooks.map((r) => r.runbookCode))].join(","),
        procedureVersion: [...new Set(snapshotRunbooks.map((r) => r.version))].join(","),
        procedureContent: {
          incidentType: playbook?.incidentType ?? "UNKNOWN",
          matchedTechniques: playbook?.matchedTechniques ?? context.mitreMappings.map((m) => m.techniqueId),
          strategy: playbook?.strategy ?? procedure?.strategy ?? [],
          runbooks: snapshotRunbooks,
          rehunt: context.rehunt ?? null,
          spreadResponse: context.spreadResponse ?? null,
          containmentProcedure: procedure
            ? { procedureCode: procedure.procedureCode, version: procedure.version, objective: procedure.objective, strategy: procedure.strategy, successCriteria: procedure.verification.successCriteria }
            : null,
        },
        policyResult: snapshotPolicy,
      },
    };
  }

  /** Every IP/hash/URL/e-mail/domain/port/host/command in AI free text must already exist in the incident's evidence. */
  private checkFreeText(
    label: string,
    text: string,
    evidenceText: string,
    hosts: string[],
    flag: (code: RecommendationViolationCode, message: string) => void
  ): void {
    if (!text) return;
    const known = (value: string) => evidenceText.includes(value.toLowerCase());
    const report = (code: RecommendationViolationCode, kind: string, value: string) =>
      flag(code, `${label}: ${kind} "${value}" is not present in the incident evidence`);

    for (const m of text.match(URL_RE) ?? []) {
      const url = m.replace(/[.,;:]+$/, "");
      if (!known(url)) report("INVENTED_IOC", "URL", url);
    }
    const withoutUrls = text.replace(URL_RE, " ");
    for (const ip of withoutUrls.match(IPV4) ?? []) if (!known(ip)) report("INVENTED_IOC", "IP address", ip);
    for (const h of withoutUrls.match(HASH) ?? []) if (!known(h)) report("INVENTED_IOC", "hash", h);
    for (const e of withoutUrls.match(EMAIL) ?? []) if (!known(e)) report("INVENTED_IOC", "e-mail address", e);
    const withoutEmails = withoutUrls.replace(EMAIL, " ");
    for (const d of withoutEmails.match(DOMAIN) ?? []) if (!known(d)) report("INVENTED_IOC", "domain", d);
    for (const m of text.matchAll(PORT)) {
      const port = m[1] ?? m[2];
      if (port && !new RegExp(`(?:port\\D{0,3}|:)${port}\\b`, "i").test(evidenceText)) report("INVENTED_IOC", "port", port);
    }
    for (const token of text.match(HOST_TOKEN) ?? []) {
      if (!/\d/.test(token) || NON_HOST_PREFIXES.test(token)) continue;
      if (!hosts.includes(token) && !known(token)) report("INVENTED_HOST", "host", token);
    }
    for (const c of text.match(COMMAND) ?? []) if (!known(c.replace(/`/g, ""))) report("INVENTED_COMMAND", "command", c);
  }
}

function invalid(summary: string, violations: string[]): RecommendationValidationOutcome {
  return { status: "INVALID", summary, steps: [], violations, snapshot: null };
}
