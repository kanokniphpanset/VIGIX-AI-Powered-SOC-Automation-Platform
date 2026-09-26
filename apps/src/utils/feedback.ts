// What to tell the user after an action (pure; runs under `node --test`): what just happened, what comes next, and —
// when the next step is on another screen — one link there. Shown as a toast; the backend result decides which kind.
import { translate, type Lang, type MsgKey, type Params } from '../i18n/messages.ts'

export type FeedbackKind =
  | 'alertIncident' | 'alertClosed'
  | 'severityConfirmed' | 'severityChanged'
  | 'aiDone' | 'aiFailed' | 'recDone' | 'recFailed' | 'sentToIr'
  | 'approved' | 'rejected' | 'started' | 'completed'
  | 'rhResolved' | 'rhNotResolved' | 'rhEscalated'

export interface Feedback {
  type: 'success' | 'error' | 'info' | 'warning'
  title: string
  /** "ขั้นต่อไป: …" plus any backend detail. */
  message: string
  link: { label: string; to: string } | null
}

interface Spec { type: Feedback['type']; next: MsgKey; link?: { label: MsgKey; to: (p: Params) => string } }

const SPEC: Record<FeedbackKind, Spec> = {
  alertIncident: { type: 'success', next: 'fb.alertIncident.next' },
  alertClosed: { type: 'success', next: 'fb.alertClosed.next', link: { label: 'fb.alertClosed.link', to: () => '/alerts?status=needs-review' } },
  severityConfirmed: { type: 'success', next: 'fb.severity.next' },
  severityChanged: { type: 'success', next: 'fb.severity.next' },
  aiDone: { type: 'success', next: 'fb.aiDone.next' },
  aiFailed: { type: 'error', next: 'fb.aiFailed.next' },
  recDone: { type: 'success', next: 'fb.recDone.next' },
  recFailed: { type: 'error', next: 'fb.recFailed.next' },
  sentToIr: { type: 'success', next: 'fb.sentToIr.next', link: { label: 'fb.sentToIr.link', to: () => '/dashboard' } },
  approved: { type: 'success', next: 'fb.approved.next' },
  rejected: { type: 'info', next: 'fb.rejected.next', link: { label: 'fb.rejected.link', to: () => '/tickets?queue=awaiting-decision' } },
  started: { type: 'success', next: 'fb.started.next' },
  completed: { type: 'success', next: 'fb.completed.next' },
  rhResolved: { type: 'success', next: 'fb.rhResolved.next', link: { label: 'fb.rhResolved.link', to: () => '/dashboard' } },
  rhNotResolved: { type: 'info', next: 'fb.rhNotResolved.next', link: { label: 'fb.rhNotResolved.link', to: (p) => `/incidents/${p.incidentId}` } },
  rhEscalated: { type: 'warning', next: 'fb.rhEscalated.next', link: { label: 'fb.rhEscalated.link', to: (p) => `/incidents/${p.incidentId}` } },
}

const TITLE: Record<FeedbackKind, MsgKey> = {
  alertIncident: 'fb.alertIncident.title', alertClosed: 'fb.alertClosed.title',
  severityConfirmed: 'fb.severityConfirmed.title', severityChanged: 'fb.severityChanged.title',
  aiDone: 'fb.aiDone.title', aiFailed: 'fb.aiFailed.title', recDone: 'fb.recDone.title', recFailed: 'fb.recFailed.title',
  sentToIr: 'fb.sentToIr.title', approved: 'fb.approved.title', rejected: 'fb.rejected.title',
  started: 'fb.started.title', completed: 'fb.completed.title',
  rhResolved: 'fb.rhResolved.title', rhNotResolved: 'fb.rhNotResolved.title', rhEscalated: 'fb.rhEscalated.title',
}

/**
 * @param params values for the title (sev, inc, n) and link (incidentId)
 * @param detail optional backend message, appended as-is (e.g. why the AI analysis did not run)
 */
export function feedback(kind: FeedbackKind, lang: Lang = 'th', params: Params = {}, detail?: string | null): Feedback {
  const spec = SPEC[kind]
  const next = translate(lang, 'fb.next', { text: translate(lang, spec.next, params) })
  return {
    type: spec.type,
    title: translate(lang, TITLE[kind], params),
    message: detail ? `${detail} · ${next}` : next,
    link: spec.link ? { label: translate(lang, spec.link.label), to: spec.link.to(params) } : null,
  }
}

/** Re-hunt verdict → feedback kind (RESOLVED / escalated after the last round / a new investigation round). */
export function rehuntKind(result: string | null | undefined, incidentStatus: string | null | undefined): FeedbackKind {
  if (result === 'RESOLVED') return 'rhResolved'
  return incidentStatus === 'escalated' ? 'rhEscalated' : 'rhNotResolved'
}
