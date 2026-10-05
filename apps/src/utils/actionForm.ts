// Action create form (Knowledge → Actions → Add). Pure; runs under `node --test`. Mirrors the stored Action format
// (code, name, description, category, impactLevel, defaultApprovalRequired, runbookId) and the values the backend
// accepts (ActionDto). The backend validates the same rules again — this only gives clear messages before sending.
import type { MsgKey } from '../i18n/messages.ts'

export const ACTION_CATEGORIES = ['CONTAINMENT', 'INVESTIGATION', 'VERIFICATION'] as const
export const IMPACT_LEVELS = ['LOW', 'MEDIUM', 'HIGH'] as const

export interface ActionDraft {
  code: string
  name: string
  description: string
  category: string
  impactLevel: string
  defaultApprovalRequired: boolean
  /** Runbook id ('' = none). */
  runbookId: string
}

export const emptyActionDraft = (): ActionDraft => ({ code: '', name: '', description: '', category: '', impactLevel: '', defaultApprovalRequired: false, runbookId: '' })

export type ActionDraftErrors = Partial<Record<'code' | 'name' | 'category' | 'impactLevel', MsgKey>>

export function validateActionDraft(d: ActionDraft, existingCodes: string[] = []): ActionDraftErrors {
  const e: ActionDraftErrors = {}
  const code = d.code.trim().toUpperCase()
  if (!code) e.code = 'actf.err.codeRequired'
  else if (!/^[A-Z0-9-]+$/.test(code)) e.code = 'actf.err.codeFormat'
  else if (existingCodes.some((c) => c.toUpperCase() === code)) e.code = 'actf.err.codeDuplicate'
  if (!d.name.trim()) e.name = 'actf.err.nameRequired'
  if (!(ACTION_CATEGORIES as readonly string[]).includes(d.category)) e.category = 'actf.err.categoryRequired'
  if (!(IMPACT_LEVELS as readonly string[]).includes(d.impactLevel)) e.impactLevel = 'actf.err.impactRequired'
  return e
}

export const hasActionErrors = (e: ActionDraftErrors) => Object.keys(e).length > 0

/** POST /api/actions body. */
export function actionPayload(d: ActionDraft): Record<string, unknown> {
  return {
    code: d.code.trim().toUpperCase(),
    name: d.name.trim(),
    description: d.description.trim() || null,
    category: d.category,
    impactLevel: d.impactLevel,
    defaultApprovalRequired: d.defaultApprovalRequired,
    runbookId: d.runbookId || null,
  }
}
