// Alert Inbox — SOC review (mirrors backend/src/domain/alert/triageWorkflow.ts). No claim, no owner: any SOC analyst
// reviews an open alert. Severity comes from the Wazuh rule level; AI never provides one.
//   LOW       never shown (outside the SOC workflow)
//   MEDIUM    SOC reviews: create an incident, or close it (False positive / Informational, optional reason)
//   HIGH/CRIT incident opened automatically at ingestion; a legacy one without an incident can only become one
import { labelMap, tr } from '../i18n/locale.ts'

export type InboxStatus = 'all' | 'needs-review' | 'in-incident' | 'closed'
export type ReviewDecision = 'CREATE_INCIDENT' | 'FALSE_POSITIVE' | 'INFORMATIONAL'

/** [tab, label]: the label is read in the current language each time (a getter), so a render follows the language. */
export const STATUS_TABS: readonly [InboxStatus, string][] = (['all', 'needs-review', 'in-incident', 'closed'] as const).map((k) => {
  const tab: [InboxStatus, string] = [k, '']
  Object.defineProperty(tab, 1, { enumerable: true, get: () => tr(`tri.tab.${k}`) })
  return tab
})
export const DECISION_LABEL: Record<ReviewDecision, string> = labelMap({ CREATE_INCIDENT: 'tri.dec.CREATE_INCIDENT', FALSE_POSITIVE: 'tri.dec.FALSE_POSITIVE', INFORMATIONAL: 'tri.dec.INFORMATIONAL' })
export const STATUS_LABEL: Record<string, string> = labelMap({ NEEDS_REVIEW: 'tri.st.NEEDS_REVIEW', MONITORING: 'tri.st.MONITORING', CLOSED: 'tri.st.CLOSED', IN_INCIDENT: 'tri.st.IN_INCIDENT' })

export interface ReviewFacts { severity: string; actionable: boolean }

/** Decisions the SOC may take on this alert (empty when it is decided, in an incident, or not in the SOC workflow). */
export function reviewDecisions(a: ReviewFacts): ReviewDecision[] {
  if (!a.actionable) return []
  return a.severity.toLowerCase() === 'medium' ? ['CREATE_INCIDENT', 'FALSE_POSITIVE', 'INFORMATIONAL'] : ['CREATE_INCIDENT']
}
/** The reason is optional for every decision (mirrors backend validateTriageInput). */
export const reasonRequired = (_d: ReviewDecision) => false

export const available = (v: unknown): string => (v === null || v === undefined || v === '' ? tr('c.notAvailable') : String(v))

/** Minutes as a short duration: '25 นาที' / '3 ชม. 5 นาที' / '2 วัน 4 ชม.'. */
export function durationText(minutes: number): string {
  const m = Math.max(0, Math.round(minutes))
  if (m < 60) return tr('tri.dur.m', { m })
  if (m < 1440) return tr('tri.dur.hm', { h: Math.floor(m / 60), m: m % 60 })
  return tr('tri.dur.dh', { d: Math.floor(m / 1440), h: Math.floor((m % 1440) / 60) })
}
/** '22 นาทีที่แล้ว' / '3 ชม. 5 นาทีที่แล้ว' / '2 วัน 4 ชม.ที่แล้ว'. */
export const agoText = (minutes: number) => tr('tri.ago', { t: durationText(minutes) })

/**
 * An SLA target in the plainest unit: '15 นาที' / '4 ชม.' / '3 วัน' / '1 สัปดาห์' ('1 ชม. 30 นาที' / '40 ชม.' when it
 * is not a whole day or week).
 */
export function targetText(minutes: number): string {
  const m = Math.max(0, Math.round(minutes))
  if (m >= 10080 && m % 10080 === 0) return tr('tri.tgt.w', { n: m / 10080 })
  if (m >= 1440 && m % 1440 === 0) return tr('tri.tgt.d', { n: m / 1440 })
  if (m >= 60 && m % 60 === 0) return tr('tri.tgt.h', { n: m / 60 })
  if (m >= 60) return tr('tri.dur.hm', { h: Math.floor(m / 60), m: m % 60 })
  return tr('tri.dur.m', { m })
}

/**
 * An SLA as a target, never as "breached / missed": what should be done within how long, the deadline, and whether
 * it is done. `late` (deadline passed, not done) only colours the deadline — no overdue wording.
 */
export interface SlaTarget {
  text: string
  dueAt: string
  doneAt: string | null
  late: boolean
}

/**
 * Review target of an alert that still waits for SOC review ('ควรตรวจภายใน 4 ชม.'). The clock starts at receivedAt, or
 * at reviewAt for a (legacy) monitored alert back in the queue — as in the backend. Null once reviewed or with no target.
 */
export function reviewSla(a: { displayState: string; slaDueAt: string | null; receivedAt: string; reviewAt: string | null; workflowState: string }, now: Date): SlaTarget | null {
  if (a.displayState !== 'NEEDS_REVIEW' && a.displayState !== 'MONITORING') return null
  if (!a.slaDueAt) return null
  const start = (a.workflowState === 'NEW' || a.workflowState === 'IN_TRIAGE') && a.reviewAt ? a.reviewAt : a.receivedAt
  const due = Date.parse(a.slaDueAt)
  return { text: tr('tri.tgt.review', { t: targetText((due - Date.parse(start)) / 60_000) }), dueAt: a.slaDueAt, doneAt: null, late: due < now.getTime() }
}

type PolicyTarget = { value: number; unit: 'minute' | 'hour' | 'business_day' }
/** The Policy's own wording: '15 นาที' / '4 ชม.' / '3 วันทำการ' / '5 วันทำการ (1 สัปดาห์)'. */
export function policyTargetText(t: PolicyTarget): string {
  if (t.unit === 'minute') return tr('tri.dur.m', { m: t.value })
  if (t.unit === 'hour') return tr('tri.tgt.h', { n: t.value })
  return t.value === 5 ? tr('tri.tgt.bdWeek', { n: t.value }) : tr('tri.tgt.bd', { n: t.value })
}

interface SlaClockFacts { targetMinutes: number; target?: PolicyTarget | null; dueAt: string; at: string | null; status: string }
/**
 * Incident SLA targets from Policy: 'ควรเริ่มรับมือภายใน 4 ชม.' and 'ควรแก้ไขให้เสร็จภายใน 3 วันทำการ', each with its
 * deadline and when it was done. The Policy wording is used when given, else the plain duration. Empty when Policy sets
 * no SLA; a cancelled clock (dismissed incident) is left out.
 */
export function incidentSla(sla: { firstResponse: SlaClockFacts | null; resolution: SlaClockFacts | null } | null, now: Date): SlaTarget[] {
  if (!sla) return []
  const row = (c: SlaClockFacts | null, key: 'tri.tgt.respond' | 'tri.tgt.resolve'): SlaTarget | null =>
    !c || c.status === 'CANCELLED'
      ? null
      : { text: tr(key, { t: c.target ? policyTargetText(c.target) : targetText(c.targetMinutes) }), dueAt: c.dueAt, doneAt: c.at, late: !c.at && Date.parse(c.dueAt) < now.getTime() }
  return [row(sla.firstResponse, 'tri.tgt.respond'), row(sla.resolution, 'tri.tgt.resolve')].filter((r): r is SlaTarget => !!r)
}
