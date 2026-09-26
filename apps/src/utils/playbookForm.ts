// Playbook create/edit form (Knowledge → Playbooks). Pure; runs under `node --test`. Only fields the existing Playbook
// domain has: code (create only), name, description, incident type (triggerConditions.incidentType), status, steps.
// The backend validates the same rules again (PlaybookDto) — this only gives clear messages before sending.
import type { MsgKey } from '../i18n/messages.ts'

export type PlaybookStatus = 'ACTIVE' | 'DEPRECATED'
export interface PlaybookStepDraft { title: string; description: string }
export interface PlaybookDraft {
  code: string
  name: string
  description: string
  incidentType: string
  status: PlaybookStatus
  steps: PlaybookStepDraft[]
}

export const emptyPlaybookDraft = (): PlaybookDraft => ({ code: '', name: '', description: '', incidentType: '', status: 'ACTIVE', steps: [{ title: '', description: '' }] })

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
    status: p.status === 'DEPRECATED' ? 'DEPRECATED' : 'ACTIVE',
    steps: steps.length ? steps : [{ title: '', description: '' }],
  }
}

export type DraftErrors = Partial<Record<'code' | 'name' | 'incidentType' | 'steps', MsgKey>> & { stepTitles?: number[] }

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
    status: d.status,
    steps,
  }
  if (creating) body.code = d.code.trim().toUpperCase()
  return body
}
