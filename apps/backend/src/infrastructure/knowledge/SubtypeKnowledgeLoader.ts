import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { safeLoad } from "js-yaml";
import { collectLeaves } from "../../domain/subtype/predicate";
import { ActionDef, EvidenceDef, KnowledgeBase, OrganizationContext, PlaybookDef, PolicyDef, Predicate, ReviewStatus, RunbookDef, StepDef, TargetTypeDef } from "../../domain/subtype/types";

/** repo-root/apps/knowledge/subtype-playbooks, from src/ (ts-node) or dist/ (node). */
export const DEFAULT_SUBTYPE_KNOWLEDGE_DIR = path.resolve(__dirname, "../../../../knowledge/subtype-playbooks");

type Y = Record<string, unknown>;
const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
const read = (file: string): Y => (safeLoad(fs.readFileSync(file, "utf8")) ?? {}) as Y;
const PH = /\{\{\s*([a-z_]+)\.([a-z_]+)\s*\}\}/g;
const OPS = new Set(["equals", "not_equals", "in", "not_in", "gte", "lte"]);

/**
 * SubtypeKnowledgeLoader - loads apps/knowledge/subtype-playbooks, VALIDATES it and stamps a version (`2.0.0+<sha256 prefix of
 * every knowledge file>`). A knowledge base with any structural error has status INVALID and the runtime opens NO action from it
 * (fail closed). The same checks run in tools/validate.mjs; here they run in the production path.
 *
 * Deployment policy (contracts/deployment-policy.yaml): knowledge is `deployable` for enforcement only when no action/runbook
 * is still IR_REVIEW_PENDING/DRAFT, unless explicitly overridden by SUBTYPE_ALLOW_UNREVIEWED=true.
 */
export class SubtypeKnowledgeLoader {
  private cache: { stamp: string; kb: KnowledgeBase } | null = null;

  constructor(
    private readonly dir: string = process.env.VIGIX_SUBTYPE_KNOWLEDGE_DIR ?? DEFAULT_SUBTYPE_KNOWLEDGE_DIR,
    private readonly orgFile: string | undefined = process.env.VIGIX_ORG_CONTEXT_FILE
  ) {}

  load(): KnowledgeBase {
    const files = this.files();
    const stamp = files.map((f) => `${f}:${fs.statSync(f).mtimeMs}`).join("|");
    if (this.cache?.stamp === stamp) return this.cache.kb;
    const kb = this.build(files);
    this.cache = { stamp, kb };
    return kb;
  }

  private files(): string[] {
    const out: string[] = [];
    const add = (rel: string) => { const f = path.join(this.dir, rel); if (fs.existsSync(f)) out.push(f); };
    if (fs.existsSync(path.join(this.dir, "families"))) for (const f of fs.readdirSync(path.join(this.dir, "families")).filter((x) => x.endsWith(".yaml")).sort()) add(`families/${f}`);
    for (const rel of ["contracts/target-types.yaml", "contracts/field-dictionary.yaml", "organization/organization-context.yaml", "contracts/deployment-policy.yaml", "migration-map.yaml", "reference/reference-registry.yaml"]) add(rel);
    if (this.orgFile && fs.existsSync(this.orgFile)) out.push(this.orgFile);
    return out;
  }

  private build(files: string[]): KnowledgeBase {
    const errors: string[] = [];
    const empty: KnowledgeBase = {
      version: "unavailable", hash: "", status: "INVALID", errors, evidence: new Map(), actions: new Map(), policies: new Map(), playbooks: new Map(), runbooks: new Map(),
      targetTypes: new Map(), scopeFlags: new Set(), capabilities: new Set(), authorities: new Set(), organization: emptyOrg(), unreviewed: [], legacyActionMap: new Map(),
    };
    if (!fs.existsSync(path.join(this.dir, "families"))) { errors.push(`knowledge directory not found: ${this.dir}`); return empty; }
    const h = crypto.createHash("sha256");
    for (const f of files) h.update(f.replace(this.dir, "")).update(fs.readFileSync(f));
    const hash = h.digest("hex");
    let docs: { family: string; file: string; y: Y }[] = [];
    try { docs = files.filter((f) => f.includes(`${path.sep}families${path.sep}`)).map((f) => ({ family: path.basename(f), file: f, y: read(f) })); } catch (e) { errors.push(`YAML parse error: ${(e as Error).message}`); return { ...empty, hash }; }

    const kb: KnowledgeBase = { ...empty, hash, version: `2.0.0+${hash.slice(0, 8)}` };
    const dup = (kind: string, id: string) => errors.push(`duplicate ${kind} ${id}`);
    try {
      for (const d of docs) {
        for (const e of arr<EvidenceDef>(d.y.evidence)) kb.evidence.has(e.id) ? dup("evidence", e.id) : kb.evidence.set(e.id, e);
        for (const a of arr<ActionDef>(d.y.actions)) kb.actions.has(a.action_id) ? dup("action", a.action_id) : kb.actions.set(a.action_id, a);
        for (const p of arr<PolicyDef>(d.y.policies)) kb.policies.has(p.policy_id) ? dup("policy", p.policy_id) : kb.policies.set(p.policy_id, p);
        for (const p of arr<PlaybookDef>(d.y.playbooks)) kb.playbooks.has(p.subtype_id) ? dup("playbook", p.subtype_id) : kb.playbooks.set(p.subtype_id, p);
        for (const r of arr<RunbookDef>(d.y.runbooks)) kb.runbooks.has(r.runbook_id) ? dup("runbook", r.runbook_id) : kb.runbooks.set(r.runbook_id, r);
      }
      const tt = read(path.join(this.dir, "contracts/target-types.yaml")).target_types as Record<string, TargetTypeDef>;
      for (const [k, v] of Object.entries(tt ?? {})) kb.targetTypes.set(k, v);
      const dict = read(path.join(this.dir, "contracts/field-dictionary.yaml"));
      kb.scopeFlags = new Set(Object.keys((dict.scope_flags ?? {}) as Y).map((k) => k.replace(/^scope\./, "")));
      kb.capabilities = new Set(Object.keys((dict.capabilities ?? {}) as Y));
      kb.authorities = new Set(Object.keys((dict.authorities ?? {}) as Y));
      kb.organization = this.organization(files);
      const mm = fs.existsSync(path.join(this.dir, "migration-map.yaml")) ? read(path.join(this.dir, "migration-map.yaml")) : {};
      for (const e of arr<Y>(mm.actions)) if (typeof e.old === "string" && Array.isArray(e.new)) kb.legacyActionMap.set(e.old.split(" ")[0], e.new as string[]);
    } catch (e) { errors.push(`knowledge load error: ${(e as Error).message}`); }

    validate(kb, errors);
    kb.unreviewed = [...kb.actions.values()].filter((a) => reviewOf(a.review_status) !== "IR_REVIEWED").map((a) => a.action_id)
      .concat([...kb.runbooks.values()].filter((r) => reviewOf(r.review_status) !== "IR_REVIEWED").map((r) => r.runbook_id));
    kb.status = errors.length ? "INVALID" : "VALID";
    return kb;
  }

  private organization(files: string[]): OrganizationContext {
    const org = emptyOrg();
    const apply = (y: Y) => {
      Object.assign(org, { status: String(y.status ?? org.status) });
      for (const [k, v] of Object.entries((y.authority ?? {}) as Y)) org.authority[k] = typeof v === "boolean" ? v : null;
      for (const [k, v] of Object.entries((y.capability ?? {}) as Y)) org.capability[k] = typeof v === "boolean" ? v : null;
      for (const key of ["approved_access", "approved_automation", "trusted_rmm"] as const) {
        const target = key === "approved_access" ? org.approvedAccess : key === "approved_automation" ? org.approvedAutomation : org.trustedRmm;
        for (const e of arr<Y>(y[key])) if (typeof e.match === "string") target.push({ match: e.match, note: typeof e.note === "string" ? e.note : undefined });
      }
      for (const e of arr<Y>(y.enforcement_points)) if (typeof e.host === "string" && typeof e.enforcement_point === "string") org.enforcementPoints.push({ host: e.host, service: typeof e.service === "string" ? e.service : undefined, enforcement_point: e.enforcement_point });
      // named contacts per authority role: shown to the user ONLY when configured (an authority role is never mapped to a person by guess)
      for (const [k, v] of Object.entries((y.authority_contacts ?? {}) as Y)) if (typeof v === "string" && v.trim()) org.authorityContacts[k] = v.trim();
      const id = (y.identity ?? null) as Y | null;
      if (id && (typeof id.provider === "string" || typeof id.tenant_or_scope === "string")) org.identity = { provider: typeof id.provider === "string" ? id.provider : undefined, tenant_or_scope: typeof id.tenant_or_scope === "string" ? id.tenant_or_scope : undefined };
    };
    for (const f of files) if (f.endsWith(`${path.sep}organization-context.yaml`) && f.includes(`${path.sep}organization${path.sep}`)) apply(read(f));
    if (this.orgFile && fs.existsSync(this.orgFile)) apply(read(this.orgFile));
    return org;
  }
}

const reviewOf = (r: ReviewStatus | undefined): ReviewStatus => r ?? "IR_REVIEW_PENDING";
const emptyOrg = (): OrganizationContext => ({ status: "UNKNOWN", authority: { ir_execute: true }, capability: {}, approvedAccess: [], approvedAutomation: [], trustedRmm: [], enforcementPoints: [], identity: null, authorityContacts: {} });

/** Deployment policy: enforcement is allowed only for reviewed knowledge (or an explicit operator override). */
export function deployability(kb: KnowledgeBase): { deployable: boolean; reason: string | null } {
  if (kb.status !== "VALID") return { deployable: false, reason: `knowledge INVALID (${kb.errors.length} error(s))` };
  if (kb.unreviewed.length && process.env.SUBTYPE_ALLOW_UNREVIEWED !== "true") return { deployable: false, reason: `${kb.unreviewed.length} action/runbook item(s) await IR review` };
  return { deployable: true, reason: null };
}

function validate(kb: KnowledgeBase, errors: string[]): void {
  const err = (m: string) => errors.push(m);
  const checkPred = (pred: Predicate | undefined, where: string) => {
    for (const l of collectLeaves(pred)) {
      const p = l.field.split(".");
      if (!OPS.has(l.operator)) err(`${where}: bad operator ${l.operator}`);
      if (l.value === undefined) err(`${where}: leaf ${l.field} has no value`);
      switch (p[0]) {
        case "evidence": if (!kb.evidence.has(p[1]) || !["status", "authorization_status"].includes(p[2])) err(`${where}: bad evidence field ${l.field}`); break;
        case "targets": if (!kb.targetTypes.has(p[1]) || p[2] !== "validated") err(`${where}: bad target field ${l.field}`); break;
        case "scope": if (!kb.scopeFlags.has(p[1])) err(`${where}: undefined scope flag ${l.field}`); break;
        case "authority": if (!kb.authorities.has(p[1]) || p[2] !== "granted") err(`${where}: bad authority field ${l.field}`); break;
        case "capability": if (!kb.capabilities.has(p.slice(1, -1).join(".")) || p.at(-1) !== "supported") err(`${where}: bad capability field ${l.field}`); break;
        case "context": if (!["context.asset_criticality", "context.environment", "context.alternative_containment_available", "context.active_damage_ongoing"].includes(l.field)) err(`${where}: undefined context field ${l.field}`); break;
        default: err(`${where}: field outside dictionary ${l.field}`);
      }
    }
  };
  for (const a of kb.actions.values()) {
    if (!a.runbook_refs?.length) err(`action ${a.action_id}: no runbook`);
    for (const r of a.runbook_refs ?? []) if (!kb.runbooks.get(r)?.supported_action_ids.includes(a.action_id)) err(`action ${a.action_id}: runbook ${r} missing or does not list the action`);
    if (!([...kb.policies.values()].some((p) => p.rule_type === "ACTION_GATE" && p.action_id === a.action_id))) err(`action ${a.action_id}: no ACTION_GATE policy`);
  }
  for (const p of kb.policies.values()) {
    if (p.rule_type === "ACTION_GATE") {
      if (!kb.actions.has(p.action_id!)) err(`policy ${p.policy_id}: unknown action ${p.action_id}`);
      for (const s of p.applicable_subtypes ?? []) if (s !== "*" && !kb.playbooks.has(s)) err(`policy ${p.policy_id}: unknown subtype ${s}`);
      checkPred(p.required_evidence, p.policy_id); checkPred(p.required_targets, p.policy_id); checkPred(p.authority_requirements, p.policy_id);
      for (const x of p.prohibitions ?? []) checkPred(x.when, `${p.policy_id}/${x.id}`);
      for (const c of p.criticality_constraints ?? []) checkPred(c.when, p.policy_id);
      for (const c of [...(p.tool_capability_requirements ?? []), ...(p.tool_capability_any_of ?? [])]) if (!kb.capabilities.has(c)) err(`policy ${p.policy_id}: unknown capability ${c}`);
    } else if (p.rule_type === "GLOBAL_PROHIBITION") for (const x of p.prohibitions ?? []) checkPred(x.when, `${p.policy_id}/${x.id}`);
    else if (p.rule_type === "BRANCH_GATE") { checkPred(p.required_evidence, p.policy_id); for (const x of p.prohibitions ?? []) checkPred(x.when, `${p.policy_id}/${x.id}`); }
  }
  for (const r of kb.runbooks.values()) {
    for (const aid of r.supported_action_ids) if (!kb.actions.has(aid)) err(`runbook ${r.runbook_id}: unknown action ${aid}`);
    const ids = new Set<string>();
    const variants = new Set(["standard", ...(r.variants ?? []).map((v) => v.variant_id)]);
    for (const s of r.ordered_steps ?? []) {
      const w = `${r.runbook_id}/${s.step_id}`;
      if (ids.has(s.step_id)) err(`${w}: duplicate step id`); ids.add(s.step_id);
      for (const k of ["instruction", "expected_result", "verify", "on_failure"] as const) if (!s[k]) err(`${w}: missing ${k}`);
      if (s.variant && !variants.has(s.variant)) err(`${w}: variant ${s.variant} not declared`);
      if (s.include_runbook && !kb.runbooks.has(s.include_runbook)) err(`${w}: include_runbook ${s.include_runbook} missing`);
      if (/ดำเนินการตาม\s*RB-/.test(s.instruction)) err(`${w}: instruction defers to a runbook id`);
      // step readiness data (the runtime refuses a malformed step rather than guessing): operational steps carry method_basis,
      // a step is ready only with a method, and a step with no method states what is missing
      const operational = !s.include_runbook && !s.fold && s.kind !== "verify" && !/^ตรวจ/.test(s.instruction ?? "");
      if (operational) {
        if (!["EXISTING", "NEUTRAL_DERIVED", "ORG_INPUT_REQUIRED", "IR_REVIEW_REQUIRED"].includes(s.method_basis as string)) err(`${w}: operational step has no valid method_basis`);
        else if (s.method_basis === "ORG_INPUT_REQUIRED" || s.method_basis === "IR_REVIEW_REQUIRED") { if (!s.method_requires) err(`${w}: ${s.method_basis} step must state method_requires`); if (s.method) err(`${w}: ${s.method_basis} step must not carry a method`); }
        else if (!s.method) err(`${w}: ${s.method_basis} step has no method`);
      }
      const order = r.ordered_steps.map((x) => x.step_id);
      for (const pid of s.needs_prior ?? []) if (!order.includes(pid) || order.indexOf(pid) >= order.indexOf(s.step_id)) err(`${w}: needs_prior ${pid} must be an earlier step`);
      checkPred(s.condition, w);
      const guarded = new Set(collectLeaves(s.condition).filter((l) => l.field.startsWith("targets.")).map((l) => l.field.split(".")[1]));
      for (const m of s.instruction.matchAll(PH)) {
        if (m[1] === "missing") continue;
        const t = kb.targetTypes.get(m[1]);
        if (!t) { err(`${w}: placeholder target ${m[1]} unknown`); continue; }
        if (![...t.required_identity_fields, ...(t.optional_fields ?? [])].includes(m[2])) err(`${w}: placeholder ${m[1]}.${m[2]} not defined`);
        if (!r.required_targets.includes(m[1]) && !guarded.has(m[1])) err(`${w}: placeholder target ${m[1]} is neither required nor guarded by a condition`);
      }
    }
  }
  for (const pb of kb.playbooks.values()) {
    checkPred(pb.classification_evidence, pb.playbook_id);
    for (const br of pb.related_branches ?? []) { if (!kb.playbooks.has(br.subtype_id)) err(`${pb.playbook_id}: related branch ${br.subtype_id} missing`); checkPred(br.open_when, pb.playbook_id); if (br.gate_policy && !kb.policies.has(br.gate_policy)) err(`${pb.playbook_id}: gate ${br.gate_policy} missing`); }
    for (const sc of pb.scenarios) {
      checkPred(sc.when, `${pb.playbook_id}/${sc.scenario_id}`);
      const ids = new Set(sc.ordered_action_refs.map((x) => x.action_id));
      const color = new Map<string, number>();
      const dfs = (n: string): void => {
        color.set(n, 1);
        for (const d of sc.ordered_action_refs.find((x) => x.action_id === n)?.depends_on ?? []) { if (color.get(d) === 1) err(`${pb.playbook_id}/${sc.scenario_id}: cyclic dependency at ${d}`); else if (!color.get(d)) dfs(d); }
        color.set(n, 2);
      };
      for (const ref of sc.ordered_action_refs) {
        if (!kb.actions.has(ref.action_id)) err(`${pb.playbook_id}/${sc.scenario_id}: unknown action ${ref.action_id}`);
        if (ref.condition !== "POLICY_ELIGIBLE") checkPred(ref.condition as Predicate, pb.playbook_id);
        for (const d of ref.depends_on ?? []) if (!ids.has(d)) err(`${pb.playbook_id}/${sc.scenario_id}: depends_on ${d} not in scenario`);
        const ok = [...kb.policies.values()].some((p) => p.rule_type === "ACTION_GATE" && p.action_id === ref.action_id && (p.applicable_subtypes!.includes("*") || p.applicable_subtypes!.includes(pb.subtype_id)));
        if (!ok) err(`${pb.playbook_id}/${sc.scenario_id}: no policy for ${ref.action_id}`);
      }
      for (const id of ids) if (!color.get(id)) dfs(id);
    }
  }
}

export type { StepDef };
