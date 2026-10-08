import { Facts, Leaf, Predicate, Tri } from "./types";

/**
 * 3-valued predicate evaluation. A missing field / UNKNOWN status / unresolved target is UNKNOWN - never a pass:
 * requirements pass only on TRUE and prohibitions fire only on TRUE (contracts/field-dictionary.yaml).
 * `inst` = the target types validated for THIS action instance (so targets.<type>.validated is per-instance).
 */
export function fieldValue(field: string, facts: Facts, inst?: Set<string>): unknown {
  const p = field.split(".");
  switch (p[0]) {
    case "evidence": {
      const e = facts.evidence.get(p[1]);
      if (!e) return undefined;
      return p[2] === "status" ? e.status : p[2] === "authorization_status" ? e.authorization : undefined;
    }
    case "targets": {
      const validated = inst ?? new Set(facts.targets.filter((t) => t.validated).map((t) => t.type));
      return validated.has(p[1]);
    }
    case "scope": return facts.scope.has(p[1]);
    case "authority": { const v = facts.authority.get(p[1]); return v === null || v === undefined ? undefined : v; }
    case "capability": {
      const id = p.slice(1, -1).join(".");
      const v = facts.capability.get(id);
      if (v !== null && v !== undefined) return v;
      // platform-neutral mode: an unknown capability keeps the (role-level) step; strict mode stays UNKNOWN.
      return facts.mode === "strict" ? undefined : true;
    }
    case "context": return facts.context[field];
    default: return undefined;
  }
}

export function evalLeaf(leaf: Leaf, facts: Facts, inst?: Set<string>): Tri {
  const v = fieldValue(leaf.field, facts, inst);
  if (v === undefined || v === null || v === "UNKNOWN") return "UNKNOWN";
  const want = leaf.value;
  switch (leaf.operator) {
    case "equals": return v === want ? "TRUE" : "FALSE";
    case "not_equals": return v !== want ? "TRUE" : "FALSE";
    case "in": return (want as unknown[]).includes(v) ? "TRUE" : "FALSE";
    case "not_in": return !(want as unknown[]).includes(v) ? "TRUE" : "FALSE";
    case "gte": return (v as number) >= (want as number) ? "TRUE" : "FALSE";
    case "lte": return (v as number) <= (want as number) ? "TRUE" : "FALSE";
    default: throw new Error(`unknown operator ${String(leaf.operator)}`);
  }
}

export function evalPred(pred: Predicate | undefined | null, facts: Facts, inst?: Set<string>): Tri {
  if (pred === undefined || pred === null) return "TRUE";
  if ("field" in pred) return evalLeaf(pred, facts, inst);
  if ("all_of" in pred) { const r = pred.all_of.map((p) => evalPred(p, facts, inst)); return r.includes("FALSE") ? "FALSE" : r.includes("UNKNOWN") ? "UNKNOWN" : "TRUE"; }
  if ("any_of" in pred) { const r = pred.any_of.map((p) => evalPred(p, facts, inst)); return r.includes("TRUE") ? "TRUE" : r.includes("UNKNOWN") ? "UNKNOWN" : "FALSE"; }
  const r = pred.none_of.map((p) => evalPred(p, facts, inst));
  return r.includes("TRUE") ? "FALSE" : r.includes("UNKNOWN") ? "UNKNOWN" : "TRUE";
}

export function collectLeaves(pred: Predicate | undefined | null, out: Leaf[] = []): Leaf[] {
  if (!pred) return out;
  if ("field" in pred) { out.push(pred); return out; }
  const kids = "all_of" in pred ? pred.all_of : "any_of" in pred ? pred.any_of : pred.none_of;
  for (const k of kids) collectLeaves(k, out);
  return out;
}
