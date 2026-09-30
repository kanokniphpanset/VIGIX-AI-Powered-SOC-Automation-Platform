// Policy create form (Knowledge → Policies → Add). Pure; runs under `node --test`. Mirrors the stored Policy format
// (code, name, description, type, precedence, rules[{ condition, result }]) and only the condition fields / operators /
// result fields the backend accepts (CreatePolicyDto). The backend validates the same rules again — this only gives
// clear messages before sending.
import type { MsgKey } from '../i18n/messages.ts'

export const POLICY_TYPES = ['INTAKE', 'PRIORITY', 'ASSIGNMENT', 'APPROVAL', 'VERIFICATION', 'ESCALATION', 'TRIAGE_SLA'] as const
export const CONDITION_OPERATORS = ['eq', 'neq', 'gte', 'lte', 'gt', 'lt'] as const
const LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const FLAG = ['true', 'false']
/** Condition field → the values it can take (every field of PolicyEvaluationInput). */
export const CONDITION_VALUES: Record<string, string[]> = {
  severity: LEVELS,
  assetCriticality: LEVELS,
  actionImpactLevel: LEVELS,
  verificationResult: ['RESOLVED', 'NOT_RESOLVED'],
  spreadDetected: FLAG,
  threatContained: FLAG,
}
export const CONDITION_FIELDS = Object.keys(CONDITION_VALUES)

const ROLES = ['SOC', 'IR_TEAM']
export type ResultFieldKind = 'select' | 'boolean' | 'number' | 'text' | 'list'
/** Result fields a rule can set (PolicyResultFragment), in the order the form shows them. */
export const RESULT_FIELDS: { key: string; kind: ResultFieldKind; options?: string[] }[] = [
  { key: 'autoCreateIncident', kind: 'boolean' },
  { key: 'priority', kind: 'select', options: ['P0', 'P1', 'P2', 'P3'] },
  { key: 'responsibleRole', kind: 'select', options: ROLES },
  { key: 'executorRole', kind: 'select', options: ROLES },
  { key: 'reviewRequired', kind: 'boolean' },
  { key: 'reviewRole', kind: 'select', options: ROLES },
  { key: 'approvalRequired', kind: 'boolean' },
  { key: 'approvalRole', kind: 'select', options: ROLES },
  { key: 'approvalChain', kind: 'list', options: ROLES },
  { key: 'approvalReason', kind: 'list' },
  { key: 'investigationRequired', kind: 'boolean' },
  { key: 'requireNewInvestigation', kind: 'boolean' },
  { key: 'requireNewRecommendation', kind: 'boolean' },
  { key: 'requireEscalation', kind: 'boolean' },
  { key: 'requireAdditionalEvidence', kind: 'boolean' },
  { key: 'incidentStatus', kind: 'text' },
  { key: 'triageSlaMinutes', kind: 'number' },
  { key: 'firstResponseSlaMinutes', kind: 'number' },
]

export interface ConditionDraft { field: string; operator: string; value: string }
/** Every result value is kept as text in the form; '' = not set. Booleans are 'true' / 'false'. */
export interface RuleDraft { conditions: ConditionDraft[]; result: Record<string, string> }
export interface PolicyDraft { code: string; name: string; description: string; type: string; precedence: string; rules: RuleDraft[] }

export const emptyCondition = (): ConditionDraft => ({ field: 'severity', operator: 'eq', value: '' })
export const emptyRule = (): RuleDraft => ({ conditions: [emptyCondition()], result: {} })
export const emptyPolicyDraft = (): PolicyDraft => ({ code: '', name: '', description: '', type: '', precedence: '0', rules: [emptyRule()] })

export type PolicyDraftErrors = Partial<Record<'code' | 'name' | 'type' | 'precedence', MsgKey>> & {
  /** rule index → message */
  rules?: Record<number, MsgKey>
}

const splitList = (text: string) => text.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean)

/** Field → message key; empty when the draft can be sent. */
export function validatePolicyDraft(d: PolicyDraft, existingCodes: string[] = []): PolicyDraftErrors {
  const e: PolicyDraftErrors = {}
  const code = d.code.trim().toUpperCase()
  if (!code) e.code = 'polf.err.codeRequired'
  else if (!/^[A-Z0-9-]+$/.test(code)) e.code = 'polf.err.codeFormat'
  else if (existingCodes.some((c) => c.toUpperCase() === code)) e.code = 'polf.err.codeDuplicate'
  if (!d.name.trim()) e.name = 'polf.err.nameRequired'
  if (!(POLICY_TYPES as readonly string[]).includes(d.type)) e.type = 'polf.err.typeRequired'
  if (!/^-?\d+$/.test(d.precedence.trim())) e.precedence = 'polf.err.precedence'
  const rules: Record<number, MsgKey> = {}
  d.rules.forEach((r, i) => {
    if (!r.conditions.length || r.conditions.some((c) => !CONDITION_VALUES[c.field]?.includes(c.value) || !(CONDITION_OPERATORS as readonly string[]).includes(c.operator))) rules[i] = 'polf.err.condition'
    else if (!Object.keys(resultPayload(r.result)).length) rules[i] = 'polf.err.resultRequired'
    else if (RESULT_FIELDS.some((f) => f.kind === 'number' && r.result[f.key]?.trim() && !(Number(r.result[f.key]) > 0))) rules[i] = 'polf.err.number'
    else if ((r.result.approvalChain ?? '') && splitList(r.result.approvalChain).some((x) => !ROLES.includes(x.toUpperCase()))) rules[i] = 'polf.err.chain'
  })
  if (!d.rules.length) rules[0] = 'polf.err.condition'
  if (Object.keys(rules).length) e.rules = rules
  return e
}

export const hasPolicyErrors = (e: PolicyDraftErrors) => Object.keys(e).length > 0

/** The set result fields of one rule, typed as the backend expects (unset fields are left out). */
export function resultPayload(result: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const f of RESULT_FIELDS) {
    const raw = (result[f.key] ?? '').trim()
    if (!raw) continue
    if (f.kind === 'boolean') out[f.key] = raw === 'true'
    else if (f.kind === 'number') out[f.key] = Number(raw)
    else if (f.kind === 'list') {
      const items = splitList(raw).map((x) => (f.options ? x.toUpperCase() : x))
      if (items.length) out[f.key] = items
    } else out[f.key] = raw
  }
  return out
}

const conditionPayload = (c: ConditionDraft) => ({ field: c.field, operator: c.operator, value: CONDITION_VALUES[c.field] === FLAG ? c.value === 'true' : c.value })

/** POST /api/policies body. One condition → a leaf; several → { all: [...] } (every condition must hold). */
export function policyPayload(d: PolicyDraft): Record<string, unknown> {
  return {
    code: d.code.trim().toUpperCase(),
    name: d.name.trim(),
    description: d.description.trim() || null,
    type: d.type,
    precedence: Number(d.precedence.trim()),
    rules: d.rules.map((r) => ({
      condition: r.conditions.length === 1 ? conditionPayload(r.conditions[0]) : { all: r.conditions.map(conditionPayload) },
      result: resultPayload(r.result),
    })),
  }
}
