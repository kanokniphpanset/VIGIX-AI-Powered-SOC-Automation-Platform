// Display helpers for real backend data (lower-case backend enums -> the UI's badges and labels).
import type { Severity } from '@/types'
import { dateLocale, tr } from '../i18n/locale.ts'
import { hasMsg } from '../i18n/messages.ts'

export function toSeverity(s: string | null | undefined): Severity {
  const u = (s ?? '').toUpperCase()
  return u === 'CRITICAL' || u === 'HIGH' || u === 'MEDIUM' || u === 'LOW' ? u : 'LOW'
}

/** Short, stable label for a UUID incident id. */
export function incidentLabel(id: string): string {
  return `INC-${id.slice(0, 8).toUpperCase()}`
}

const STATUS_CLASS: Record<string, string> = {
  open: 'bg-sky-50 text-sky-700 ring-sky-200',
  investigating: 'bg-amber-50 text-amber-700 ring-amber-200',
  resolved: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  dismissed: 'bg-slate-100 text-slate-500 ring-slate-200',
  received: 'bg-sky-50 text-sky-700 ring-sky-200',
  analyzing: 'bg-violet-50 text-violet-700 ring-violet-200',
  closed: 'bg-slate-100 text-slate-500 ring-slate-200',
  validated: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  superseded: 'bg-slate-100 text-slate-500 ring-slate-200',
  invalid: 'bg-rose-50 text-rose-700 ring-rose-200',
  completed: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  ready_for_execution: 'bg-sky-50 text-sky-700 ring-sky-200',
  pending_approval: 'bg-amber-50 text-amber-700 ring-amber-200',
  in_progress: 'bg-violet-50 text-violet-700 ring-violet-200',
  rejected: 'bg-rose-50 text-rose-700 ring-rose-200',
  failed: 'bg-rose-50 text-rose-700 ring-rose-200',
  not_resolved: 'bg-rose-50 text-rose-700 ring-rose-200',
  active: 'bg-amber-50 text-amber-700 ring-amber-200',
  in_incident: 'bg-amber-50 text-amber-700 ring-amber-200',
  escalated: 'bg-rose-50 text-rose-700 ring-rose-200',
  pending: 'bg-amber-50 text-amber-700 ring-amber-200',
  approved: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  not_required: 'bg-slate-100 text-slate-500 ring-slate-200',
  // SLA clocks
  breached: 'bg-rose-50 text-rose-700 ring-rose-200',
  at_risk: 'bg-amber-50 text-amber-800 ring-amber-200',
  on_track: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  met: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
}

export function statusClass(status: string): string {
  return STATUS_CLASS[status.toLowerCase()] ?? 'bg-slate-100 text-slate-600 ring-slate-200'
}

/** An ALERT's "escalated" status means "linked into an incident" — not the incident-level ESCALATED state. */
export function alertStatus(status: string): string {
  return status === 'escalated' ? 'in_incident' : status
}

/** A stored status in the current language ("dismissed" incidents in the P0 flow were closed by a Set Group merge). */
export function statusLabel(status: string): string {
  const s = status.toLowerCase()
  const key = `st.${s}`
  if (hasMsg(key)) return tr(key)
  return s.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
}

/** Relative time against the REAL clock (the demo screens' timeAgo in formatters.ts uses the fixed DEMO_NOW). */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const diff = now - new Date(iso).getTime()
  const future = diff < 0
  const mins = Math.round(Math.abs(diff) / 60000)
  let text: string
  if (mins < 1) return tr('time.justNow')
  else if (mins < 60) text = tr('time.min', { n: mins })
  else if (mins < 1440) text = tr('time.h', { n: Math.round(mins / 60) })
  else if (mins < 60 * 24 * 60) text = tr('time.d', { n: Math.round(mins / 1440) })
  else text = new Date(iso).toLocaleDateString(dateLocale(), { year: 'numeric', month: 'short', day: 'numeric' })
  return mins >= 60 * 24 * 60 ? text : tr(future ? 'time.in' : 'time.ago', { t: text })
}
