/**
 * Pure scoring functions of the evaluation kit. They know nothing about the runtime: they compare an OBSERVED recommendation with a Ground Truth case.
 * The Ground Truth is never produced from observed output (see ground-truth.draft.json _meta); a score is only as good as that reference, and the
 * reference is DRAFT until IR accepts it.
 */
export interface GtExpectedAction { action: string; target_parts: string[]; scope_required: string[]; scope_forbidden: string[] }
export interface GtCase {
  case_id: string; round: 1 | 2; title: string; basis: string[];
  expected_actions: GtExpectedAction[];
  expected_approval?: { action: string; authority_label: string }[];
  expected_rehunt?: Record<string, string>;
  prohibited_actions: string[];
  process: { ordered_pairs?: [string, string][]; must_not_be_ready?: string[]; must_be_in_missing?: string[] };
}
export interface ObservedAction { action: string; target: string | null; text: string }
export interface Observed {
  system: "subtype" | "legacy";
  ready: ObservedAction[];
  /** rendered user text (numbered steps + sections); empty for legacy (it has none) */
  text: string;
  numberedLines: string[];
  missingText: string;
  approvalText: string;
  /** structural facts (subtype only) */
  statusValidated: boolean | null;
  onlyActionStepsHaveActionId: boolean | null;
  /** target -> next-step decision chosen after a re-hunt (subtype only) */
  rehunt: Record<string, string>;
  error: string | null;
}

export type Canon = (action: string) => string[];
const asList = (c: Canon, a: string) => [...new Set([a, ...c(a)])];
export const expandProhibited = (gt: GtCase, groups: Record<string, string[]>): Set<string> => new Set(gt.prohibited_actions.flatMap((x) => (x.startsWith("@") ? groups[x.slice(1)] ?? [] : [x])));

export interface MatchResult { tp: { exp: GtExpectedAction; obs: ObservedAction }[]; fp: ObservedAction[]; fn: GtExpectedAction[] }
/** Greedy one-to-one match on (action, target identity parts). A legacy action matches through the migration map. */
export function matchActions(gt: GtCase, obs: Observed, canon: Canon): MatchResult {
  const used = new Set<number>(); const tp: MatchResult["tp"] = []; const fn: GtExpectedAction[] = [];
  for (const exp of gt.expected_actions) {
    const i = obs.ready.findIndex((o, k) => !used.has(k) && asList(canon, o.action).includes(exp.action) && exp.target_parts.every((p) => (o.target ?? "").includes(p)));
    if (i >= 0) { used.add(i); tp.push({ exp, obs: obs.ready[i] }); } else fn.push(exp);
  }
  return { tp, fp: obs.ready.filter((_, k) => !used.has(k)), fn };
}

export interface CaseScore {
  caseId: string; round: number; system: string;
  tp: number; fp: number; fn: number;
  scopeCorrect: number; scopeTotal: number; scopeFailures: string[];
  /** ready actions of the right action but at a target that is not in the Ground Truth */
  wrongTarget: number;
  prohibited: number; readyTotal: number;
  processPassed: number; processTotal: number; processFailures: string[];
  rehuntExact: number; rehuntCoarse: number; rehuntTotal: number; rehuntDetail: { target: string; expected: string; actual: string }[];
}
const coarse = (d: string) => (d === "PROPOSE" || d === "REPEAT" || d === "ADD" || d === "NEW" ? "PROPOSE" : "HOLD");

export function scoreCase(gt: GtCase, obs: Observed, canon: Canon, groups: Record<string, string[]>): CaseScore {
  const m = matchActions(gt, obs, canon);
  const prohibited = expandProhibited(gt, groups);
  const s: CaseScore = { caseId: gt.case_id, round: gt.round, system: obs.system, tp: m.tp.length, fp: m.fp.length, fn: m.fn.length, scopeCorrect: 0, scopeTotal: gt.expected_actions.length, scopeFailures: [], wrongTarget: 0, prohibited: 0, readyTotal: obs.ready.length, processPassed: 0, processTotal: 0, processFailures: [], rehuntExact: 0, rehuntCoarse: 0, rehuntTotal: 0, rehuntDetail: [] };

  // Target & scope: every expected action needs a matching prediction whose text has all required and none of the forbidden scope strings.
  for (const { exp, obs: o } of m.tp) {
    const missing = exp.scope_required.filter((x) => !o.text.includes(x)); const forbidden = exp.scope_forbidden.filter((x) => o.text.includes(x));
    if (!missing.length && !forbidden.length) s.scopeCorrect++;
    else s.scopeFailures.push(`${exp.action}: ${missing.length ? `missing [${missing.join(" | ")}]` : ""}${forbidden.length ? ` forbidden present [${forbidden.join(" | ")}]` : ""}`.trim());
  }
  for (const e of m.fn) s.scopeFailures.push(`${e.action}: not proposed (target ${e.target_parts.join(" + ")})`);
  const expectedActionIds = new Set(gt.expected_actions.map((e) => e.action));
  s.wrongTarget = m.fp.filter((o) => asList(canon, o.action).some((a) => expectedActionIds.has(a))).length;

  // Prohibited: a ready action the reference forbids (any target)
  for (const o of obs.ready) if (asList(canon, o.action).some((a) => prohibited.has(a)) && !m.tp.some((t) => t.obs === o)) s.prohibited++;
  for (const t of m.tp) if (prohibited.has(t.exp.action)) s.prohibited++;

  // Response process correctness (subtype only: the legacy output has no ready / approval / missing sections)
  if (obs.system === "subtype") {
    const check = (name: string, ok: boolean) => { s.processTotal++; if (ok) s.processPassed++; else s.processFailures.push(name); };
    check("nothing executed by generation (status VALIDATED)", obs.statusValidated === true);
    check("only ACTION steps are ticketable", obs.onlyActionStepsHaveActionId === true);
    for (const [a, b] of gt.process.ordered_pairs ?? []) { const ia = obs.text.indexOf(a), ib = obs.text.indexOf(b); check(`order: "${a}" before "${b}"`, ia >= 0 && ib >= 0 && ia < ib); }
    for (const x of gt.process.must_not_be_ready ?? []) check(`not a ready step: "${x}"`, !obs.numberedLines.some((l) => l.includes(x)));
    for (const x of gt.process.must_be_in_missing ?? []) check(`listed as information needed: "${x}"`, obs.missingText.includes(x));
    for (const ap of gt.expected_approval ?? []) {
      check(`approval request present: ${ap.action}`, obs.approvalText.includes(ap.authority_label));
      check(`approval-needed action is not a ready step: ${ap.action}`, !obs.ready.some((o) => asList(canon, o.action).includes(ap.action)));
    }
  }

  // Re-hunt recommendation correctness
  for (const [target, expected] of Object.entries(gt.expected_rehunt ?? {})) {
    let actual: string;
    if (obs.system === "subtype") actual = Object.entries(obs.rehunt).find(([t]) => t.includes(target))?.[1] ?? "MISSING";
    else actual = obs.ready.some((o) => (o.target ?? "").includes(target)) ? "PROPOSE" : "HOLD";
    s.rehuntTotal++;
    if (obs.system === "subtype" && actual === expected) s.rehuntExact++;
    if (coarse(actual) === coarse(expected)) s.rehuntCoarse++;
    s.rehuntDetail.push({ target, expected, actual });
  }
  return s;
}

export interface Aggregate {
  cases: number; tp: number; fp: number; fn: number; precision: string; recall: string;
  scopeCorrect: number; scopeTotal: number; scopeAccuracy: string;
  processPassed: number; processTotal: number; processCorrectness: string;
  prohibited: number; readyTotal: number; prohibitedRate: string; casesWithProhibited: number;
  rehuntExact: number; rehuntCoarse: number; rehuntTotal: number; rehuntExactRate: string; rehuntCoarseRate: string; wrongTarget: number;
}
const frac = (n: number, d: number) => (d === 0 ? "n/a (0/0)" : `${(100 * n / d).toFixed(1)}% (${n}/${d})`);
export function aggregate(scores: CaseScore[], opts: { processApplicable: boolean }): Aggregate {
  const sum = (f: (s: CaseScore) => number) => scores.reduce((a, s) => a + f(s), 0);
  const a: Aggregate = {
    cases: scores.length, tp: sum((s) => s.tp), fp: sum((s) => s.fp), fn: sum((s) => s.fn), precision: "", recall: "",
    scopeCorrect: sum((s) => s.scopeCorrect), scopeTotal: sum((s) => s.scopeTotal), scopeAccuracy: "",
    processPassed: sum((s) => s.processPassed), processTotal: sum((s) => s.processTotal), processCorrectness: "",
    prohibited: sum((s) => s.prohibited), readyTotal: sum((s) => s.readyTotal), prohibitedRate: "", casesWithProhibited: scores.filter((s) => s.prohibited > 0).length,
    rehuntExact: sum((s) => s.rehuntExact), rehuntCoarse: sum((s) => s.rehuntCoarse), rehuntTotal: sum((s) => s.rehuntTotal), rehuntExactRate: "", rehuntCoarseRate: "", wrongTarget: sum((s) => s.wrongTarget),
  };
  a.precision = frac(a.tp, a.tp + a.fp); a.recall = frac(a.tp, a.tp + a.fn);
  a.scopeAccuracy = frac(a.scopeCorrect, a.scopeTotal);
  a.processCorrectness = opts.processApplicable ? frac(a.processPassed, a.processTotal) : "N/A (legacy output has no ready / approval / missing sections)";
  a.prohibitedRate = `${frac(a.prohibited, a.readyTotal)} of ready actions; ${a.casesWithProhibited}/${scores.length} cases`;
  a.rehuntExactRate = opts.processApplicable ? frac(a.rehuntExact, a.rehuntTotal) : "N/A (legacy has no decision classes)";
  a.rehuntCoarseRate = frac(a.rehuntCoarse, a.rehuntTotal);
  return a;
}
