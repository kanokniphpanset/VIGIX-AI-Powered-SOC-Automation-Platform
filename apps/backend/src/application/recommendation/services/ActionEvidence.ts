import { RecommendationContextDto, targetableIocValues } from "../dto/RecommendationContextDto";
import { findActionKnowledge } from "../../../domain/knowledge/actionKnowledge";
import { EvidenceRequirementId, TargetKind, iocKind } from "../../../domain/knowledge/knowledgeTypes";
import { compatibleIocRole } from "./IocRole";

type EvidenceContext = Pick<RecommendationContextDto, "iocs" | "evidence" | "affectedHosts">;

export interface ActionEvidenceResult {
  /** Every requirement in force: the Action's own (actionKnowledge) plus what ACTION_COMPLIANCE policies add. */
  requirements: EvidenceRequirementId[];
  satisfied: boolean;
  /** Requirements no candidate target satisfies (empty when satisfied). */
  missing: EvidenceRequirementId[];
  /** Recorded values of the Action's target kind for which every requirement holds — the only sensible targets. */
  targets: string[];
}

/**
 * ActionEvidence — deterministic "is the Action's required evidence recorded?" check (Knowledge Expansion, Step 9).
 * Pure: reads only the backend-built recommendation context (this cycle's IOCs, evidence rows and affected hosts),
 * never an AI output. Used by RecommendationContextBuilder (to tell the AI which Actions it may recommend and on
 * which targets), by GenerateRecommendationUseCase (no AI call when no Action has its evidence) and by
 * RecommendationValidator (a step whose target lacks the evidence is rejected).
 */
export function requirementsFor(actionCode: string, policyRequired: string[] = []): EvidenceRequirementId[] {
  const own = findActionKnowledge(actionCode)?.requiredEvidence ?? [];
  return [...new Set([...own, ...(policyRequired as EvidenceRequirementId[])])];
}

export function targetKindOf(actionCode: string): TargetKind | null {
  return findActionKnowledge(actionCode)?.targetKind ?? null;
}

function targetableOfKind(context: EvidenceContext, kind: TargetKind): string[] {
  const targetable = targetableIocValues(context);
  return context.iocs.filter((i) => targetable.has(i.iocValue) && iocKind(i.iocType) === kind).map((i) => i.iocValue);
}

function citedByEvidence(context: EvidenceContext, value: string): boolean {
  return context.evidence.some((e) => e.host === value || e.iocValues.includes(value));
}

/** One requirement for one (possibly absent) target. */
export function checkRequirement(context: EvidenceContext, requirement: EvidenceRequirementId, target: string | null, kind: TargetKind | null): boolean {
  switch (requirement) {
    case "VALIDATED_IOC_TARGET": {
      if (!target) return false;
      if (kind === "host") return context.affectedHosts.includes(target);
      const targetable = targetableIocValues(context);
      if (kind === null) return targetable.has(target) || context.affectedHosts.includes(target);
      return context.iocs.some((i) => i.iocValue === target && targetable.has(target) && iocKind(i.iocType) === kind);
    }
    case "RELATED_EVENT":
      return !!target && (citedByEvidence(context, target) || context.iocs.some((i) => i.iocValue === target && i.manual));
    case "SUPPORTING_EVIDENCE":
      return context.evidence.length > 0;
    case "AFFECTED_ENDPOINT":
      return context.affectedHosts.length > 0;
    case "SUSPICIOUS_ACTIVITY_EVIDENCE":
      return kind === "host" && target ? context.evidence.some((e) => e.host === target) : context.evidence.some((e) => !!e.host);
    case "FILE_HASH":
      return targetableOfKind(context, "hash").length > 0;
    case "FILE_PATH":
      return targetableOfKind(context, "file").length > 0;
    case "PROCESS_IDENTIFIER":
      return targetableOfKind(context, "process").length > 0;
    case "COMMAND_LINE":
      return targetableOfKind(context, "command").length > 0;
    case "ACCOUNT_IDENTIFIER":
      return targetableOfKind(context, "account").length > 0;
    case "EMAIL_MESSAGE":
      return targetableOfKind(context, "email").length > 0;
    case "AUTHENTICATION_EVIDENCE": {
      const accounts = kind === "account" && target ? [target] : targetableOfKind(context, "account");
      return context.evidence.some((e) => e.iocValues.some((v) => accounts.includes(v)));
    }
    default:
      return false;
  }
}

/** Requirements the given target does not satisfy for this Action. */
export function missingEvidenceForTarget(context: EvidenceContext, actionCode: string, target: string, policyRequired: string[] = []): EvidenceRequirementId[] {
  const kind = targetKindOf(actionCode);
  const missing = requirementsFor(actionCode, policyRequired).filter((r) => !checkRequirement(context, r, target, kind));
  if (!compatibleIocRole(context, actionCode, target) && !missing.includes("VALIDATED_IOC_TARGET")) missing.push("VALIDATED_IOC_TARGET");
  return missing;
}

/** Is there at least one recorded target for which every requirement of the Action holds? */
export function evaluateActionEvidence(context: EvidenceContext, actionCode: string, policyRequired: string[] = []): ActionEvidenceResult {
  const requirements = requirementsFor(actionCode, policyRequired);
  const kind = targetKindOf(actionCode);
  const candidates = kind === null ? [] : kind === "host" ? [...context.affectedHosts] : targetableOfKind(context, kind);

  const targets: string[] = [];
  let fewestMissing: EvidenceRequirementId[] | null = null;
  for (const candidate of candidates) {
    const missing = missingEvidenceForTarget(context, actionCode, candidate, policyRequired);
    if (missing.length === 0) targets.push(candidate);
    else if (!fewestMissing || missing.length < fewestMissing.length) fewestMissing = missing;
  }
  if (targets.length) return { requirements, satisfied: true, missing: [], targets };
  // No candidate at all: the target itself is what is missing, plus every other requirement that fails without one.
  const missing = fewestMissing ?? requirements.filter((r) => !checkRequirement(context, r, null, kind));
  return { requirements, satisfied: false, missing, targets: [] };
}
