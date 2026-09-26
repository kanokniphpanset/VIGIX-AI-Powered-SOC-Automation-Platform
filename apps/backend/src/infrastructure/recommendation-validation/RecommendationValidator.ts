import { IActionRepository } from "../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../domain/runbook/repositories/IRunbookRepository";
import {
  RecommendationContextActionProcedure,
  RecommendationContextDto,
  citableEvidence,
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
  | "RUNBOOK_MISMATCH"
  | "INVENTED_TARGET"
  | "TARGET_TYPE_MISMATCH"
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
  | "DUPLICATE_STEP";

/**
 * What kind of target each containment Action operates on. A target must be a
 * recorded value of that kind — e.g. Block Source IP on a hostname, or Disable
 * Account on an IP, is rejected even though both values are "known".
 */
const ACTION_TARGET_KIND: Record<string, TargetKind> = {
  "ACT-BLOCK-SOURCE-IP": "ip",
  "ACT-BLOCK-DOMAIN": "domain",
  "ACT-BLOCK-URL": "url",
  "ACT-DISABLE-ACCOUNT": "account",
  "ACT-ISOLATE-ENDPOINT": "host",
  "ACT-QUARANTINE-EMAIL": "email",
};
type TargetKind = "ip" | "domain" | "url" | "account" | "host" | "email" | "hash" | "other";

function iocKind(iocType: string): TargetKind {
  const t = iocType.toLowerCase();
  if (["ipv4", "ipv6", "ip", "srcip", "src_ip"].includes(t)) return "ip";
  if (["domain", "fqdn"].includes(t)) return "domain";
  if (t === "url") return "url";
  if (["username", "user", "account"].includes(t)) return "account";
  if (t === "email") return "email";
  if (["hostname", "host"].includes(t)) return "host";
  if (["md5", "sha1", "sha256", "hash"].includes(t)) return "hash";
  return "other";
}

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
    if (!playbook) flag("NO_PLAYBOOK", "no incident-level playbook matches this incident's MITRE techniques, so no response action can be recommended");

    const procedures = new Map<string, RecommendationContextActionProcedure>((context.actionProcedures ?? []).map((p) => [p.actionCode, p]));
    const actionCodes = [...new Set(candidate.steps.map((s) => s.action))];
    const actions = await this.actionRepository.findByCodes(actionCodes, tenantId);
    const actionByCode = new Map(actions.map((a) => [a.code, a]));

    // Ground truth for free-text checks: only what the incident actually recorded.
    const hosts = context.affectedHosts ?? [];
    // Only IOCs linked to this cycle's evidence or added by an analyst are actionable targets. An IOC the
    // pipeline merely extracted (e.g. the victim agent's own IP) is context, not something to contain.
    const targetable = targetableIocValues(context);
    const iocKindByValue = new Map<string, TargetKind>(
      context.iocs.filter((i) => targetable.has(i.iocValue)).map((i) => [i.iocValue, iocKind(i.iocType)])
    );
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

    const summaryPhases = CORE_FLOW_PHASES.filter((p) => p.test(candidate.summary)).length;
    if (summaryPhases >= 4) flag("CORE_FLOW_REPETITION", `summary restates the VIGIX Core Flow (${summaryPhases} lifecycle phases) instead of the selected action(s)`);
    this.checkFreeText("summary", candidate.summary, evidenceText, hosts, flag);
    for (const p of BYPASS_PATTERNS) if (p.test(candidate.summary)) flag("POLICY_BYPASS", "summary claims approval/authorization is waived or automatic");

    const steps: CreateRecommendationStepData[] = [];
    const seen = new Set<string>();
    const snapshotRunbooks: { actionCode: string; runbookCode: string; version: string; procedure: string[]; verificationCriteria: string[] }[] = [];
    const snapshotPolicy: Record<string, unknown> = {};
    const ordered = [...candidate.steps].sort((a, b) => a.stepOrder - b.stepOrder);

    for (const [index, step] of ordered.entries()) {
      const label = `step ${step.stepOrder} (${step.action})`;
      const before = violations.length;

      // ---- Action ------------------------------------------------------------------------------
      const action = actionByCode.get(step.action);
      if (!action) {
        flag("INVENTED_ACTION", `${label}: action "${step.action}" does not exist in the Action Catalog`);
        continue;
      }
      if (!action.enabled) flag("DISABLED_ACTION", `${label}: action is disabled`);
      if (action.category !== "CONTAINMENT") {
        flag("CORE_FLOW_REPETITION", `${label}: ${action.category} is a VIGIX Core Flow phase performed by the platform, not a response action to expand`);
      }
      const procedure = procedures.get(action.code);
      if (playbook && !procedure) flag("ACTION_NOT_IN_PLAYBOOK", `${label}: action is not allowed by playbook ${playbook.code} (${playbook.allowedActions.join(", ") || "none"})`);

      // ---- Playbook / Runbook --------------------------------------------------------------------
      if (playbook && step.playbook !== playbook.code) {
        flag("PLAYBOOK_MISMATCH", `${label}: playbook "${step.playbook}" does not match the playbook selected for this ${playbook.incidentType} incident (${playbook.code})`);
      }
      const runbook = action.runbookId ? await this.runbookRepository.findById(action.runbookId, tenantId) : null;
      if (!runbook || !runbook.isActive) {
        flag("RUNBOOK_MISMATCH", `${label}: action has no ACTIVE action-level runbook, so it cannot be expanded`);
      } else if (step.runbook !== runbook.code) {
        flag("RUNBOOK_MISMATCH", `${label}: runbook "${step.runbook}" is not the runbook of ${action.code} (${runbook.code})`);
      }

      // ---- Target --------------------------------------------------------------------------------
      const targetKind: TargetKind | undefined = hosts.includes(step.target) ? "host" : iocKindByValue.get(step.target);
      if (!targetKind) {
        flag("INVENTED_TARGET", `${label}: target "${step.target}" is not an evidence-linked/analyst-added IOC or an affected host`);
      } else if (ACTION_TARGET_KIND[action.code] && ACTION_TARGET_KIND[action.code] !== targetKind) {
        flag("TARGET_TYPE_MISMATCH", `${label}: target "${step.target}" is a ${targetKind}, but ${action.code} operates on a ${ACTION_TARGET_KIND[action.code]}`);
      }
      const pairKey = `${action.code}|${step.target}`;
      if (seen.has(pairKey)) flag("DUPLICATE_STEP", `${label}: the same action on the same target appears more than once`);
      seen.add(pairKey);

      // ---- Policy (authoritative role / approval) ------------------------------------------------
      const policy = procedure?.policy ?? null;
      if (procedure && (!policy || !policy.responsibleRole)) {
        flag("POLICY_UNAVAILABLE", `${label}: no Policy result for this action — responsible role cannot be established`);
      } else if (policy && step.responsibleRole !== policy.responsibleRole) {
        flag("WRONG_RESPONSIBLE_ROLE", `${label}: responsibleRole "${step.responsibleRole}" differs from Policy (${policy.responsibleRole})`);
      }
      const freeText = [step.objective, step.reason, step.expectedResult ?? "", step.verificationCriteria, ...step.instructions.flatMap((i) => [i.instruction, i.expectedResult ?? ""])];
      for (const text of freeText) {
        if (BYPASS_PATTERNS.some((p) => p.test(text)) || (policy?.approvalRequired && APPROVAL_DENIAL_PATTERN.test(text))) {
          flag("POLICY_BYPASS", `${label}: text waives, skips or pre-empts approval/authorization ("${text.slice(0, 120)}")`);
          break;
        }
      }
      if (policy?.approvalRequired && step.requiresApprovalSuggested === false) {
        flag("POLICY_BYPASS", `${label}: candidate marks approval as not required, but Policy requires ${policy.approvalRole ?? "an"} approval`);
      }

      // ---- Evidence ------------------------------------------------------------------------------
      const fabricated = step.evidenceRefs.filter((ref) => !citable.has(ref));
      for (const ref of fabricated) flag("INVENTED_EVIDENCE", `${label}: evidence reference "${ref}" is not one of this cycle's evidence ids (E<n>/I<n>/MITRE technique)`);
      const evidence = [...new Set(step.evidenceRefs.map((ref) => citable.get(ref)).filter((r): r is string => !!r))];
      if (evidence.length === 0) flag("NO_EVIDENCE", `${label}: no traceable evidence reference`);

      // ---- Instructions --------------------------------------------------------------------------
      const instructions = [...step.instructions].sort((a, b) => a.order - b.order);
      if (instructions.some((ins, i) => ins.order !== i + 1)) {
        flag("INVALID_INSTRUCTIONS", `${label}: instruction order must be 1..${instructions.length} without gaps or duplicates`);
      }
      for (const ins of instructions) {
        if (ins.target && ins.target !== step.target && !hosts.includes(ins.target) && !iocKindByValue.has(ins.target)) {
          flag("INVENTED_TARGET", `${label}: instruction ${ins.order} targets "${ins.target}", which is not an evidence-linked/analyst-added IOC or an affected host`);
        }
      }
      for (const text of [step.objective, ...instructions.map((i) => i.instruction)]) {
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
        title: `${action.name} — ${step.target}`,
        objective: step.objective,
        actionId: action.id,
        target: step.target,
        reason: step.missingEvidence.length ? `${step.reason} Missing evidence: ${step.missingEvidence.join(", ")}.` : step.reason,
        evidence,
        sourceRunbookId: runbook!.id,
        precondition: null,
        expectedResult: step.expectedResult ?? runbook!.expectedResult ?? null,
        // Policy decides approval — the AI's advisory hint is never used here.
        requiresApproval: policy?.approvalRequired ?? false,
        instructions: instructions.map((i) => ({
          order: i.order,
          instruction: i.instruction,
          target: i.target ?? step.target,
          expectedResult: i.expectedResult ?? null,
        })),
        verificationCriteria: step.verificationCriteria,
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

    if (violations.length > 0 || steps.length === 0 || !playbook) {
      if (steps.length === 0 && violations.length === 0) violations.push("SCHEMA: no usable steps remained after validation");
      return invalid(candidate.summary, violations);
    }

    return {
      status: "VALIDATED",
      summary: candidate.summary,
      steps,
      violations: [],
      snapshot: {
        playbookCode: playbook.code,
        playbookVersion: playbook.version,
        procedureCode: [...new Set(snapshotRunbooks.map((r) => r.runbookCode))].join(","),
        procedureVersion: [...new Set(snapshotRunbooks.map((r) => r.version))].join(","),
        procedureContent: { incidentType: playbook.incidentType, matchedTechniques: playbook.matchedTechniques, strategy: playbook.strategy, runbooks: snapshotRunbooks },
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
