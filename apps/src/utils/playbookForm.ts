// Playbook create/edit form (Knowledge → Playbooks). Pure; runs under `node --test`. Only fields the existing Playbook
// domain has: code (create only), name, description, status, steps and the selector keys the seeded playbooks carry in
// triggerConditions — incidentType, mitreTechniques[] and allowedActions[] (the recommendation only selects a playbook
// whose MITRE techniques match the incident, and may only expand its allowed actions).
// The backend validates the same rules again (PlaybookDto) — this only gives clear messages before sending.
import type { MsgKey } from '../i18n/messages.ts'

export type PlaybookStatus = 'ACTIVE' | 'DEPRECATED'
export interface PlaybookStepDraft { title: string; description: string }
export interface PlaybookDraft {
  code: string
  name: string
  description: string
  incidentType: string
  /** MITRE technique ids, comma / space / newline separated (e.g. "T1110, T1110.001"). */
  mitreTechniques: string
  /** Action catalog codes (e.g. ACT-BLOCK-SOURCE-IP). */
  allowedActions: string[]
  status: PlaybookStatus
  steps: PlaybookStepDraft[]
}

export const emptyPlaybookDraft = (): PlaybookDraft => ({ code: '', name: '', description: '', incidentType: '', mitreTechniques: '', allowedActions: [], status: 'ACTIVE', steps: [{ title: '', description: '' }] })

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [])

/** "T1110, t1110.001" → ["T1110", "T1110.001"] (uppercased, deduplicated, order kept). */
export const parseTechniques = (text: string): string[] => [...new Set(text.split(/[\s,;]+/).map((x) => x.trim().toUpperCase()).filter(Boolean))]
export const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/

/** A stored playbook (GET /api/playbooks/:id) as an editable draft. */
export function draftFromPlaybook(p: Record<string, unknown>): PlaybookDraft {
  const trigger = (p.triggerConditions ?? {}) as Record<string, unknown>
  const steps = (Array.isArray(p.steps) ? (p.steps as { stepOrder: number; title: string; description?: string | null }[]) : [])
    .slice()
    .sort((a, b) => a.stepOrder - b.stepOrder)
    .map((s) => ({ title: s.title, description: s.description ?? '' }))
  return {
    code: String(p.code ?? ''),
    name: String(p.name ?? ''),
    description: typeof p.description === 'string' ? p.description : '',
    incidentType: typeof trigger.incidentType === 'string' ? trigger.incidentType : '',
    mitreTechniques: strings(trigger.mitreTechniques).join(', '),
    allowedActions: strings(trigger.allowedActions),
    status: p.status === 'DEPRECATED' ? 'DEPRECATED' : 'ACTIVE',
    steps: steps.length ? steps : [{ title: '', description: '' }],
  }
}

export type DraftErrors = Partial<Record<'code' | 'name' | 'incidentType' | 'mitreTechniques' | 'steps', MsgKey>> & { stepTitles?: number[] }

/** Field → message key; empty when the draft can be sent. `creating` adds the code rules. */
export function validatePlaybookDraft(d: PlaybookDraft, creating: boolean, existingCodes: string[] = []): DraftErrors {
  const e: DraftErrors = {}
  const code = d.code.trim().toUpperCase()
  if (creating) {
    if (!code) e.code = 'pbf.err.codeRequired'
    else if (!/^[A-Z0-9-]+$/.test(code)) e.code = 'pbf.err.codeFormat'
    else if (existingCodes.some((c) => c.toUpperCase() === code)) e.code = 'pbf.err.codeDuplicate'
  }
  if (!d.name.trim()) e.name = 'pbf.err.nameRequired'
  const type = d.incidentType.trim().toUpperCase()
  if (type && (!/^[A-Z0-9_]+$/.test(type) || type.length > 64)) e.incidentType = 'pbf.err.incidentType'
  if (parseTechniques(d.mitreTechniques).some((id) => !TECHNIQUE_ID.test(id))) e.mitreTechniques = 'pbf.err.mitre'
  const filled = d.steps.filter((s) => s.title.trim() || s.description.trim())
  if (!filled.some((s) => s.title.trim())) e.steps = 'pbf.err.stepsRequired'
  const blank = d.steps.map((s, i) => (!s.title.trim() && s.description.trim() ? i : -1)).filter((i) => i >= 0)
  if (blank.length) e.stepTitles = blank
  return e
}

export const hasErrors = (e: DraftErrors) => Object.keys(e).length > 0

/** Request body for POST (creating) or PUT; empty step rows are dropped and steps renumbered 1..n. */
export function playbookPayload(d: PlaybookDraft, creating: boolean): Record<string, unknown> {
  const steps = d.steps
    .filter((s) => s.title.trim())
    .map((s, i) => ({ stepOrder: i + 1, title: s.title.trim(), description: s.description.trim() || null }))
  const body: Record<string, unknown> = {
    name: d.name.trim(),
    description: d.description.trim() || null,
    incidentType: d.incidentType.trim().toUpperCase() || null,
    mitreTechniques: parseTechniques(d.mitreTechniques),
    allowedActions: [...new Set(d.allowedActions)],
    status: d.status,
    steps,
  }
  if (creating) body.code = d.code.trim().toUpperCase()
  return body
}
