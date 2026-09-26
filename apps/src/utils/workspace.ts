// Role workspaces for the two operational roles — SOC (alerts, investigation, Send to IR) and IR_TEAM (IR decision,
// execution, verification) — plus admin: which screens each role sees, the ticket-queue tabs, the incident lifecycle
// stepper and readable audit labels. Visibility only — every action is enforced by the backend.
import type { TicketQueue, WorkTicketStage } from '@/api/work'
import { currentLang, labelMap, tr } from '../i18n/locale.ts'
import { hasMsg, type MsgKey } from '../i18n/messages.ts'

export type NavKey =
  | 'dashboard'
  | 'alerts'
  | 'incidents'
  | 'tickets'
  | 'verification'
  | 'escalated'
  | 'reports'
  | 'knowledge'
  | 'settings'

export interface NavItem {
  key: NavKey
  label: string
  to: string
}

const ITEM: Record<NavKey, NavItem> = {
  dashboard: { key: 'dashboard', label: 'Dashboard', to: '/dashboard' },
  alerts: { key: 'alerts', label: 'Alert Inbox', to: '/alerts' },
  incidents: { key: 'incidents', label: 'Incidents', to: '/incidents' },
  tickets: { key: 'tickets', label: 'Response Tickets', to: '/tickets' },
  verification: { key: 'verification', label: 'Verification', to: '/verification' },
  escalated: { key: 'escalated', label: 'Escalated', to: '/incidents?view=escalated' },
  reports: { key: 'reports', label: 'Reports', to: '/reports' },
  knowledge: { key: 'knowledge', label: 'Knowledge', to: '/knowledge' },
  settings: { key: 'settings', label: 'Settings', to: '/settings' },
}

const NAV_BY_ROLE: Record<string, NavKey[]> = {
  SOC: ['dashboard', 'alerts', 'incidents', 'reports', 'knowledge', 'settings'],
  IR_TEAM: ['dashboard', 'incidents', 'tickets', 'verification', 'reports', 'knowledge', 'settings'],
  admin: ['dashboard', 'alerts', 'incidents', 'tickets', 'verification', 'escalated', 'reports', 'knowledge', 'settings'],
}

export function navFor(role: string | null): NavItem[] {
  return (NAV_BY_ROLE[role ?? ''] ?? ['dashboard', 'incidents', 'knowledge', 'settings']).map((k) => ITEM[k])
}

export const ROLE_LABEL: Record<string, string> = labelMap({ SOC: 'role.name.SOC', IR_TEAM: 'role.name.IR_TEAM', admin: 'role.name.admin' })

/** Incident list presets (server-side filters of /api/v1/work/incidents). */
/** Incident list presets (server-side filters of /api/v1/work/incidents); title and description follow the language. */
const view = (k: string, filter: { status?: string; priority?: string } = {}) => ({
  get title() { return tr(`iv.${k}.title` as MsgKey) },
  get description() { return tr(`iv.${k}.desc` as MsgKey) },
  ...filter,
})
export const INCIDENT_VIEWS: Record<string, { title: string; description: string; status?: string; priority?: string }> = {
  all: view('all'),
  investigation: view('investigation', { status: 'open,investigating' }),
  recommendation: view('recommendation', { status: 'open,investigating' }),
  critical: view('critical', { priority: 'critical', status: 'open,investigating,escalated' }),
  escalated: view('escalated', { status: 'escalated' }),
}

export interface QueueTab {
  queue: TicketQueue
  label: string
}

/** Response Ticket tabs (spec order). Counts come from the backend; labels follow the language. */
export const TICKET_TABS: QueueTab[] = (['my-work', 'awaiting-decision', 'ready', 'in-progress', 'awaiting-rehunt', 'completed', 'rejected', 'failed', 'escalated', 'all'] as TicketQueue[]).map((queue) => ({
  queue,
  get label() { return tr(`tq.${queue}` as MsgKey) },
}))

export const WORK_STAGE_LABEL: Record<WorkTicketStage, string> = labelMap({
  AWAITING_IR_DECISION: 'stage.AWAITING_IR_DECISION',
  READY_FOR_EXECUTION: 'stage.READY_FOR_EXECUTION',
  IN_PROGRESS: 'stage.IN_PROGRESS',
  AWAITING_REHUNT: 'stage.AWAITING_REHUNT',
  COMPLETED: 'stage.COMPLETED',
  NOT_RESOLVED: 'stage.NOT_RESOLVED',
  ESCALATED: 'stage.ESCALATED',
  FAILED: 'stage.FAILED',
  REJECTED: 'stage.REJECTED',
  CLOSED: 'stage.CLOSED',
})

// ---------------------------------------------------------------- Incident 360 lifecycle

export type StepState = 'done' | 'current' | 'todo' | 'blocked'
export interface LifecycleStep {
  key: string
  label: string
  state: StepState
}

export interface LifecycleFacts {
  hasAlert: boolean
  incidentStatus: string
  hasInvestigation: boolean
  hasAiAnalysis: boolean
  hasRecommendation: boolean
  /** Policy evaluated for at least one ticket (a ticket exists). */
  ticketCount: number
  /** Any ticket waiting on an approval step / any ticket rejected or sent back for evidence. */
  approvalPending: boolean
  approvalBlocked: boolean
  anyReadyOrLater: boolean
  anyCompleted: boolean
  anyVerification: boolean
}

/**
 * Alert → Incident → Investigation → AI Analysis → Recommendation → Send to IR → IR decision → Response → Verification → Resolution.
 * Derived from stored records only; the first step that is not done is "current". Resolution is done ONLY when the
 * incident is resolved (Verification NO MATCH) and "blocked" when escalated.
 */
export function lifecycle(f: LifecycleFacts): LifecycleStep[] {
  const done: [string, string, boolean][] = [
    ['alert', tr('lc.alert'), f.hasAlert],
    ['incident', tr('lc.incident'), true],
    ['investigation', tr('lc.investigation'), f.hasInvestigation],
    ['ai', tr('lc.ai'), f.hasAiAnalysis],
    ['recommendation', tr('lc.recommendation'), f.hasRecommendation],
    ['policy', tr('lc.policy'), f.ticketCount > 0],
    ['approval', tr('lc.approval'), f.ticketCount > 0 && !f.approvalPending && (f.anyReadyOrLater || !f.approvalBlocked)],
    ['response', tr('lc.response'), f.anyCompleted],
    ['verification', tr('lc.verification'), f.anyVerification],
    ['resolution', tr(f.incidentStatus === 'escalated' ? 'lc.escalated' : 'lc.resolution'), f.incidentStatus === 'resolved'],
  ]
  let currentSet = false
  return done.map(([key, label, isDone]) => {
    if (key === 'resolution' && f.incidentStatus === 'escalated') return { key, label, state: 'blocked' as StepState }
    if (key === 'approval' && f.approvalBlocked && !f.anyReadyOrLater) return { key, label, state: 'blocked' as StepState }
    if (isDone) return { key, label, state: 'done' as StepState }
    if (!currentSet) {
      currentSet = true
      return { key, label, state: 'current' as StepState }
    }
    return { key, label, state: 'todo' as StepState }
  })
}

// ---------------------------------------------------------------- Audit

/** Readable audit action in the current language (unknown actions: the code made readable). */
export function auditLabel(action: string): string {
  const key = `aud.a.${action}`
  return hasMsg(key) ? tr(key) : action.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase())
}

export type AuditGroup = 'triage' | 'ai' | 'policy' | 'approval' | 'response' | 'verification' | 'email' | 'incident'
export function auditGroup(action: string): AuditGroup {
  if (/^ALERT/.test(action)) return 'triage'
  if (/^AI_|RECOMMENDATION/.test(action)) return 'ai'
  if (/POLICY|ASSIGNED|RISK_VALIDATED|SEVERITY_VALIDATED/.test(action)) return 'policy'
  if (/APPROVAL/.test(action)) return 'approval'
  if (/^RESPONSE|PLAN/.test(action)) return 'response'
  if (/REHUNT|VERIFICATION|RESOLVED|ESCALATED|REOPENED/.test(action)) return 'verification'
  if (/EMAIL|SENT_TO_IR/.test(action)) return 'email'
  return 'incident'
}

/** Well-known enum values in audit metadata (approved, RESOLVED, IR_TEAM…) in Thai; English keeps them as stored. */
function valueLabel(v: string): string {
  if (currentLang() === 'en') return v
  for (const key of [`vr.${v}`, `tst.${v}`, `st.${v.toLowerCase()}`, `role.name.${v}`, `sev.${v.toUpperCase()}`]) if (hasMsg(key)) return tr(key)
  return v
}

/** A short, readable result line from audit metadata (only well-known keys; raw JSON stays expandable). */
export function auditOutcome(metadata: Record<string, unknown> | null): string | null {
  if (!metadata) return null
  const m = metadata
  const parts: string[] = []
  const pick = (k: string, label = k) => {
    const v = m[k]
    if (v === undefined || v === null || v === '' || typeof v === 'object') return
    const name = `aud.k.${label}`
    parts.push(`${hasMsg(name) ? tr(name) : label}: ${valueLabel(String(v))}`)
  }
  pick('status')
  pick('outcome')
  pick('result')
  pick('disposition')
  pick('approvalRole', 'role')
  pick('stepOrder', 'step')
  pick('responsibleRole', 'responsible')
  pick('severity')
  pick('previous', 'from')
  pick('recipientRole', 'to')
  pick('deliveryStatus', 'delivery')
  pick('reason')
  pick('error')
  pick('comment')
  return parts.length ? parts.join(' · ') : null
}

/** Readable actor: signed-in users by email + role; system actors by name (never a bare UUID). */
export function actorName(e: { actor: string; actorEmail: string | null; actorRole: string | null }): string {
  if (e.actorEmail) return `${e.actorEmail}${e.actorRole ? ` (${e.actorRole})` : ''}`
  return /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(e.actor) ? tr('c.unknownUser') : e.actor
}
