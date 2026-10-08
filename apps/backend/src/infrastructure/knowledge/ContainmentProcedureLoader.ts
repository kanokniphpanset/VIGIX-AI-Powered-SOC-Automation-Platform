import * as fs from "node:fs";
import * as path from "node:path";
import { safeLoad } from "js-yaml";
import { EVIDENCE_SIGNALS } from "../../domain/knowledge/evidenceSignals";
import { IContainmentProcedureReader } from "../../application/recommendation/ports/IContainmentProcedureReader";
import {
  RecommendationContextContainmentProcedure,
  RecommendationContextProcedureItem,
} from "../../application/recommendation/dto/RecommendationContextDto";

/** repo-root/apps/knowledge/playbooks/PB-STC-001, from src/ (ts-node) or dist/ (node). */
export const DEFAULT_PLAYBOOK_DIR = path.resolve(__dirname, "../../../../knowledge/playbooks/PB-STC-001");

/** Item markers of steps.yaml (same convention ai-orchestrator runbook/procedure_loader.py extracts). */
const ACTION_MARKER = /\(see containment\.yaml:\s*([A-Z0-9-]+)\s*\)/;
const MANUAL_MARKER = /\(manual\b[^)]*\)/i;
const APPROVER = /requires ([^)]+?) approval/i;

export class ContainmentProcedureError extends Error {}

type Yaml = Record<string, unknown>;

const str = (v: unknown): string => (typeof v === "string" ? v.trim().replace(/\s+/g, " ") : "");
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

/** Parses one steps.yaml recommendedAction string into a typed procedure item. */
export function parseProcedureItem(raw: string, conditions: Map<string, string | null>): RecommendationContextProcedureItem {
  const text = raw.trim().replace(/\s+/g, " ");
  const action = ACTION_MARKER.exec(text);
  if (action) {
    const code = action[1];
    return { type: "ACTION", text: text.replace(ACTION_MARKER, "").trim(), actionCode: code, condition: conditions.get(code) ?? null, requiresApproval: false, approver: null };
  }
  const manual = MANUAL_MARKER.exec(text);
  if (manual) {
    const approver = APPROVER.exec(manual[0])?.[1]?.trim() ?? null;
    return { type: "MANUAL", text: text.replace(MANUAL_MARKER, "").trim(), actionCode: null, condition: null, requiresApproval: !!approver, approver };
  }
  return { type: "CHECK", text, actionCode: null, condition: null, requiresApproval: false, approver: null };
}

/**
 * ContainmentProcedureLoader — the backend's reader for the attack-specific containment procedures
 * (apps/knowledge/playbooks/PB-STC-001/procedures/<ATTACK_TYPE>/{procedure,steps,containment,decisions,verification}.yaml).
 * The AI orchestrator reads the same files with its own loader (runbook/procedure_loader.py, resolver.py); the
 * backend cannot call that Python code, so it parses the same files with the same item convention.
 *
 * Read-only, no caching (five small files per generation, so an edited procedure is picked up without a restart).
 * A procedure that exists but is inconsistent (code mismatch, an ACTION item naming an Action that is not a
 * containment.yaml candidate, a decision pointing at a missing step) throws ContainmentProcedureError — it is never
 * silently half-loaded. A missing procedure directory returns null.
 */
export class ContainmentProcedureLoader implements IContainmentProcedureReader {
  constructor(private readonly playbookDir: string = process.env.VIGIX_KNOWLEDGE_PLAYBOOK_DIR ?? DEFAULT_PLAYBOOK_DIR) {}

  read(attackType: string): RecommendationContextContainmentProcedure | null {
    const code = attackType.trim().toUpperCase();
    if (!/^[A-Z_]+$/.test(code)) return null;
    const dir = path.join(this.playbookDir, "procedures", code);
    if (!fs.existsSync(path.join(dir, "steps.yaml"))) return null;

    const procedure = this.load(dir, "procedure.yaml");
    const steps = this.load(dir, "steps.yaml");
    const containment = this.load(dir, "containment.yaml");
    const decisions = this.load(dir, "decisions.yaml");
    const verification = this.load(dir, "verification.yaml");

    for (const [file, value] of [["procedure.yaml", str(procedure.code)], ["steps.yaml", str(steps.procedureCode)], ["containment.yaml", str(containment.procedureCode)], ["decisions.yaml", str(decisions.procedureCode)], ["verification.yaml", str(verification.procedureCode)]] as const) {
      if (value.toUpperCase() !== code) throw new ContainmentProcedureError(`${code}/${file}: procedure code "${value}" does not match ${code}`);
    }

    const candidateActions = list(containment.candidateActions)
      .filter((a): a is Yaml => !!a && typeof a === "object")
      .map((a) => ({ actionCode: str(a.actionCode), condition: str(a.condition) || null, runbookRef: str(a.runbookRef) || null }))
      .filter((a) => a.actionCode);
    const conditions = new Map(candidateActions.map((a) => [a.actionCode, a.condition]));

    const parsedSteps = list(steps.steps)
      .filter((s): s is Yaml => !!s && typeof s === "object")
      .map((s) => ({
        stepOrder: Number(s.stepOrder),
        ...(Array.isArray(s.appliesWhenTechniques) ? { appliesWhenTechniques: s.appliesWhenTechniques.map(str) } : {}),
        ...(Array.isArray(s.appliesWhenSignals) ? { appliesWhenSignals: s.appliesWhenSignals.map(str) } : {}),
        ...(str(s.escalatesTo) ? { escalatesTo: str(s.escalatesTo).toUpperCase() } : {}),
        ...(Array.isArray(s.requiredTypes) ? { requiredTypes: s.requiredTypes.filter((t): t is "CHECK" | "ACTION" | "MANUAL" => ["CHECK", "ACTION", "MANUAL"].includes(String(t))) } : {}),
        ...(s.conditionalActions === true ? { conditionalActions: true } : {}),
        phase: str(s.phase),
        title: str(s.title),
        objective: str(s.objective),
        items: list(s.recommendedAction).map((i) => {
          const item = parseProcedureItem(String(i), conditions);
          return item.type === "MANUAL" && str(s.manualCondition) ? { ...item, condition: str(s.manualCondition) } : item;
        }),
        reason: str(s.reason),
        expectedResult: str(s.expectedResult),
        decisionRef: str(s.decisionRef) || null,
        responsibleRole: str(s.responsibleRole) || "IR_TEAM",
        approvalRequired: s.approvalRequired === true,
      }))
      .sort((a, b) => a.stepOrder - b.stepOrder);
    for (const s of parsedSteps) {
      for (const signal of s.appliesWhenSignals ?? []) {
        if (!(EVIDENCE_SIGNALS as readonly string[]).includes(signal)) throw new ContainmentProcedureError(`${code}/steps.yaml step ${s.stepOrder}: unknown evidence signal "${signal}"`);
      }
      for (const item of s.items) {
        if (item.type === "ACTION" && !conditions.has(item.actionCode!)) {
          throw new ContainmentProcedureError(`${code}/steps.yaml step ${s.stepOrder}: ${item.actionCode} is not a containment.yaml candidate`);
        }
      }
    }

    const parsedDecisions = list(decisions.decisions)
      .filter((d): d is Yaml => !!d && typeof d === "object")
      .map((d) => ({
        id: str(d.id),
        stepRef: Number(d.stepRef),
        question: str(d.question),
        options: list(d.options)
          .filter((o): o is Yaml => !!o && typeof o === "object")
          .map((o) => ({ value: str(o.value), label: str(o.label), leadsTo: str(o.leadsTo) })),
      }));
    for (const d of parsedDecisions) {
      const step = parsedSteps.find((s) => s.stepOrder === d.stepRef);
      if (!step || step.decisionRef !== d.id) throw new ContainmentProcedureError(`${code}/decisions.yaml: ${d.id} stepRef ${d.stepRef} does not match a step with that decisionRef`);
    }

    const v = (verification.verification ?? {}) as Yaml;
    return {
      procedureCode: code,
      version: str(procedure.version) || "1",
      objective: str(procedure.objective),
      strategy: str(procedure.strategy),
      steps: parsedSteps,
      decisions: parsedDecisions,
      candidateActions,
      verification: {
        type: str(v.type),
        queryTemplate: str(v.queryTemplate) || null,
        successCriteria: list(v.successCriteria).map(str).filter(Boolean),
        additionalChecks: list(v.additionalChecks).map(str).filter(Boolean),
      },
    };
  }

  private load(dir: string, file: string): Yaml {
    const parsed = safeLoad(fs.readFileSync(path.join(dir, file), "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new ContainmentProcedureError(`${path.basename(dir)}/${file}: not a YAML mapping`);
    return parsed as Yaml;
  }
}
