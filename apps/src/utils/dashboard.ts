// Dashboard view-model (pure; runs under `node --test`). Every number comes from the backend — this file only decides
// what each role sees first, how it is worded (one vocabulary, Thai by default, English on request) and where each item
// links. Nothing here invents a value: a count the backend did not return stays null and is shown as "no data".
import type { DashboardSummary, HealthItem } from '../api/vigix.ts'
import { translate, type Lang, type MsgKey, type Params } from '../i18n/messages.ts'

export type Tone = 'danger' | 'warning' | 'info' | 'ok'
/** Lane of the case flow: SOC work, IR work, outcome ('ผลลัพธ์' is an internal key; the lane title is translated). */
export type Who = 'SOC' | 'IR' | 'ผลลัพธ์'

const n = (v: number | undefined | null) => v ?? 0

/** Ticket statuses that mean "waiting for the IR decision" (PENDING_APPROVAL: tickets created before the two-role change). */
export const awaitingIrDecision = (d: DashboardSummary) => n(d.responses.byStatus.PENDING_IR_DECISION) + n(d.responses.byStatus.PENDING_APPROVAL)
export const approvedNotStarted = (d: DashboardSummary) => n(d.responses.byStatus.READY_FOR_EXECUTION) + n(d.responses.byStatus.APPROVED)
export const openIncidents = (d: DashboardSummary) => n(d.incidents.byStatus.open) + n(d.incidents.byStatus.investigating)

// ---------------------------------------------------------------- 1. my work now (per role, one button each)
export interface WorkCard {
  key: string
  title: string
  /** What the number means, in one line. */
  hint: string
  value: number | null
  to: string
  cta: string
}

type WorkKey = 'review' | 'investigate' | 'send' | 'decide' | 'ready' | 'progress' | 'rehunt'
const card = (lang: Lang, key: WorkKey, value: number | null, to: string): WorkCard => ({
  key,
  title: translate(lang, `work.${key}.title` as MsgKey),
  hint: translate(lang, `work.${key}.hint` as MsgKey),
  value,
  to,
  cta: translate(lang, `work.${key}.cta` as MsgKey),
})

/**
 * The work waiting for THIS role, in the order it is done. `needsReview` is the Alert Inbox's own "Needs review" total
 * (null while unknown) so the dashboard and the inbox always agree.
 */
export function myWork(role: string | null, d: DashboardSummary, needsReview: number | null, lang: Lang = 'th'): WorkCard[] {
  const soc = [
    card(lang, 'review', needsReview, '/alerts?status=needs-review'),
    card(lang, 'investigate', openIncidents(d), '/incidents?view=investigation'),
    card(lang, 'send', d.recommendationReady, '/incidents?view=recommendation'),
  ]
  const ir = [
    card(lang, 'decide', awaitingIrDecision(d), '/tickets?queue=awaiting-decision'),
    card(lang, 'ready', approvedNotStarted(d), '/tickets?queue=ready'),
    card(lang, 'progress', n(d.responses.byStatus.IN_PROGRESS), '/tickets?queue=in-progress'),
    card(lang, 'rehunt', d.verificationDetail.awaitingRehunt, '/tickets?queue=awaiting-rehunt'),
  ]
  if (role === 'SOC') return soc
  if (role === 'IR_TEAM') return ir
  // admin (system role): sees both sides, read-only links
  return [...soc, ...ir].map((c) => ({ ...c, cta: translate(lang, 'work.adminCta') }))
}

// ---------------------------------------------------------------- 2. case flow (the whole flow, clickable)
export interface Stage {
  key: string
  label: string
  who: Who
  value: number | null
  to: string
}

export function caseFlow(d: DashboardSummary, needsReview: number | null, lang: Lang = 'th'): Stage[] {
  const s = (key: string, who: Who, value: number | null, to: string): Stage => ({ key, label: translate(lang, `flow.${key}` as MsgKey), who, value, to })
  return [
    s('review', 'SOC', needsReview, '/alerts?status=needs-review'),
    s('investigate', 'SOC', openIncidents(d), '/incidents?view=investigation'),
    s('send', 'SOC', d.recommendationReady, '/incidents?view=recommendation'),
    s('decide', 'IR', awaitingIrDecision(d), '/tickets?queue=awaiting-decision'),
    s('execute', 'IR', approvedNotStarted(d) + n(d.responses.byStatus.IN_PROGRESS), '/tickets?queue=in-progress'),
    s('rehunt', 'IR', d.verificationDetail.awaitingRehunt, '/tickets?queue=awaiting-rehunt'),
    s('resolved', 'ผลลัพธ์', n(d.incidents.byStatus.resolved), '/incidents?status=resolved'),
    s('escalated', 'ผลลัพธ์', n(d.incidents.byStatus.escalated), '/incidents?view=escalated'),
  ]
}

// ---------------------------------------------------------------- 3. needs attention (only what needs action now)
export interface Attention {
  key: string
  tone: Tone
  text: string
  to: string | null
}

export function attention(d: DashboardSummary, lang: Lang = 'th'): Attention[] {
  const tx = (key: MsgKey, p: Params) => translate(lang, key, p)
  const out: Attention[] = []
  if (d.sla.breached) out.push({ key: 'sla-breached', tone: 'danger', text: tx('attn.slaBreached', { n: d.sla.breached }), to: '#sla' })
  if (d.sla.atRisk) out.push({ key: 'sla-risk', tone: 'warning', text: tx('attn.slaRisk', { n: d.sla.atRisk }), to: '#sla' })
  const esc = n(d.incidents.byStatus.escalated)
  if (esc) out.push({ key: 'escalated', tone: 'danger', text: tx('attn.escalated', { n: esc }), to: '/incidents?view=escalated' })
  const failed = n(d.responses.byStatus.FAILED)
  if (failed) out.push({ key: 'failed', tone: 'warning', text: tx('attn.failed', { n: failed }), to: '/tickets?queue=failed' })
  const aiFailed = n(d.aiJobs.byStatus.FAILED)
  if (aiFailed) out.push({ key: 'ai-failed', tone: 'warning', text: tx('attn.aiFailed', { n: aiFailed }), to: null })
  for (const h of d.systemHealth.filter((x) => x.status === 'DOWN')) out.push({ key: `down-${h.key}`, tone: 'danger', text: tx('attn.down', { name: h.label }), to: '#tech' })
  return out
}

// ---------------------------------------------------------------- system health, in one line
export function healthSummary(items: HealthItem[]): { ok: number; total: number; problems: string[]; tone: Tone } {
  const checkable = items.filter((h) => h.status !== 'UNKNOWN' && h.status !== 'NOT_CONFIGURED')
  const problems = checkable.filter((h) => h.status !== 'UP').map((h) => h.label)
  const tone: Tone = checkable.some((h) => h.status === 'DOWN') ? 'danger' : problems.length ? 'warning' : 'ok'
  return { ok: checkable.length - problems.length, total: checkable.length, problems, tone }
}

// ---------------------------------------------------------------- one vocabulary for the case's current step
export function caseStep(i: { status: string; responseStatus: string | null; lastVerification: string | null }, lang: Lang = 'th'): { label: string; tone: Tone } {
  const r = (key: MsgKey, tone: Tone) => ({ label: translate(lang, key), tone })
  if (i.status === 'resolved') return r('step.resolved', 'ok')
  if (i.status === 'escalated') return r('step.escalated', 'danger')
  if (i.status === 'dismissed') return r('step.dismissed', 'info')
  switch (i.responseStatus) {
    case 'PENDING_IR_DECISION':
    case 'PENDING_APPROVAL':
      return r('step.awaitingDecision', 'warning')
    case 'READY_FOR_EXECUTION':
    case 'APPROVED':
      return r('step.ready', 'info')
    case 'IN_PROGRESS':
      return r('step.inProgress', 'info')
    case 'COMPLETED':
      return i.lastVerification ? r('step.newCycle', 'warning') : r('step.awaitingRehunt', 'warning')
    case 'REJECTED':
      return r('step.rejected', 'danger')
    case 'FAILED':
      return r('step.failed', 'danger')
    default:
      return r('step.investigating', 'info')
  }
}

const SLA_STATES = ['BREACHED', 'AT_RISK', 'ON_TRACK', 'NOT_STARTED', 'MET', 'PAUSED', 'CANCELLED'] as const
/** SLA status in words; an unknown status is shown as-is. */
export const slaText = (status: string, lang: Lang = 'th') =>
  (SLA_STATES as readonly string[]).includes(status) ? translate(lang, `sla.${status}` as MsgKey) : status
/** Thai SLA wording (kept for callers that only need Thai). */
export const SLA_TEXT: Record<string, string> = Object.fromEntries(SLA_STATES.map((s) => [s, slaText(s)]))

/** "45 นาที" / "2 ชม. 5 นาที" / "1 วัน 1 ชม." (or the English equivalents). */
export function thaiDuration(min: number | null | undefined, lang: Lang = 'th'): string {
  if (min == null) return translate(lang, 'dur.none')
  min = Math.round(min)
  if (min < 1) return translate(lang, 'dur.lt1')
  if (min < 60) return translate(lang, 'dur.min', { m: min })
  if (min < 1440) return translate(lang, 'dur.hm', { h: Math.floor(min / 60), m: min % 60 })
  return translate(lang, 'dur.dh', { d: Math.floor(min / 1440), h: Math.floor((min % 1440) / 60) })
}

/** "ครบกำหนดอีก 2 ชม. 5 นาที" / "เกินมาแล้ว 40 นาที". */
export function dueText(iso: string, now = Date.now(), lang: Lang = 'th'): string {
  const ms = new Date(iso).getTime() - now
  const t = thaiDuration(Math.round(Math.abs(ms) / 60000), lang)
  return translate(lang, ms >= 0 ? 'due.in' : 'due.over', { t })
}

export type GlossaryKey = 'SLA' | 'MTTR' | 'CONTAINMENT' | 'REHUNT' | 'MITRE' | 'INVESTIGATION' | 'DECISION' | 'SEVERITY' | 'IOC'
/** Glossary for the (?) help tips — short and plain. */
export const glossary = (key: GlossaryKey, lang: Lang = 'th') => translate(lang, `gloss.${key}` as MsgKey)
/** Thai glossary (kept for callers that only need Thai). */
export const GLOSSARY: Record<GlossaryKey, string> = Object.fromEntries(
  (['SLA', 'MTTR', 'CONTAINMENT', 'REHUNT', 'MITRE', 'INVESTIGATION', 'DECISION', 'SEVERITY', 'IOC'] as const).map((k) => [k, glossary(k)]),
) as Record<GlossaryKey, string>

/** "เมื่อสักครู่" / "27 นาทีที่แล้ว" / "5 ชม.ที่แล้ว" / "3 วันที่แล้ว" (or the English equivalents). */
export function thaiAgo(iso: string, now = Date.now(), lang: Lang = 'th'): string {
  const mins = Math.max(0, Math.round((now - new Date(iso).getTime()) / 60000))
  if (mins < 1) return translate(lang, 'ago.now')
  if (mins < 60) return translate(lang, 'ago.min', { n: mins })
  if (mins < 1440) return translate(lang, 'ago.h', { n: Math.round(mins / 60) })
  if (mins < 60 * 24 * 60) return translate(lang, 'ago.d', { n: Math.round(mins / 1440) })
  return new Date(iso).toLocaleDateString(lang === 'th' ? 'th-TH' : 'en-GB', { year: 'numeric', month: 'short', day: 'numeric' })
}

/**
 * Timeline text in plain words for the dashboard feed. Known event types get a fixed sentence (the Wazuh rule/level is
 * kept because it is evidence); anything else keeps its own text minus internal Policy codes and legacy AI clauses
 * (decision=…, risk_score=…, suggested severity=…). Full technical text stays on the incident timeline.
 */
export function activityText(eventType: string, description: string, lang: Lang = 'th'): string {
  const wazuh = /\b(LOW|MEDIUM|HIGH|CRITICAL)\b[^()]*\(rule (\S+), level (\d+)\)/i.exec(description)
  switch (eventType) {
    case 'created':
      if (/automatic/i.test(description)) return wazuh ? translate(lang, 'act.autoCreated', { sev: wazuh[1].toUpperCase(), rule: wazuh[2], level: wazuh[3] }) : translate(lang, 'act.autoCreatedPlain')
      return translate(lang, 'act.socCreated')
    case 'ai_analysis_complete':
      return translate(lang, 'act.aiDone')
    case 'alert_added':
      return translate(lang, 'act.alertAdded')
    case 'merged':
      return translate(lang, 'act.merged')
    default:
      return description
        .replace(/\s*[—–-]\s*Policy\s+[A-Z]+-[A-Z0-9-]+(?:,\s*[A-Z]+-[A-Z0-9-]+)*\.?/g, '.')
        .replace(/\s*[,;]?\s*\b(?:decision|risk_score|suggested[ _]severity)\s*=\s*[\w.]+/gi, '')
        .replace(/\s*\(advisory\)/gi, '')
        .replace(/\.{2,}/g, '.')
        .trim()
  }
}
