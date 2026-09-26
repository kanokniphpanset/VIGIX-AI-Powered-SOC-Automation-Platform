// Text the backend writes in English (in-app notification titles/bodies, incident timeline descriptions) shown in the
// current UI language. Pure; runs under `node --test`. Each known template is rebuilt from the values it carries — the
// subject (incident title, Wazuh rule description), user notes and IDs are shown exactly as stored, never translated.
// Anything that does not match a known template is shown as stored, so no information is ever lost.
import { currentLang, tr } from '../i18n/locale.ts'
import { hasMsg, type MsgKey, type Params } from '../i18n/messages.ts'

const sev = (v: string) => (hasMsg(`sev.${v.toUpperCase()}`) ? tr(`sev.${v.toUpperCase()}` as MsgKey) : v)
const role = (v: string) => (hasMsg(`role.name.${v}`) ? tr(`role.name.${v}` as MsgKey) : v)

type Rule = [RegExp, MsgKey, (m: RegExpExecArray) => Params]

/** Title templates by notification event type (backend: InAppNotifier, CreateIncident, StartResponse, CreateVerification…). */
const TITLE: Record<string, Rule[]> = {
  NEW_INCIDENT: [[/^New incident \((\w+)\): ([\s\S]*)$/, 'nt.ev.NEW_INCIDENT', (m) => ({ sev: sev(m[1]), subject: m[2] })]],
  APPROVAL_APPROVED: [[/^IR APPROVED — response can be executed: ([\s\S]*)$/, 'nt.ev.APPROVAL_APPROVED', (m) => ({ subject: m[1] })]],
  APPROVAL_REJECTED: [[/^IR REJECTED — no response will be executed: ([\s\S]*)$/, 'nt.ev.APPROVAL_REJECTED', (m) => ({ subject: m[1] })]],
  APPROVAL_REQUIRED: [
    [/^Approval required \((\w+)\) — ([\s\S]*)$/, 'nt.ev.APPROVAL_REQUIRED', (m) => ({ role: role(m[1]), subject: m[2] })],
    [/^IR decision required — ([\s\S]*)$/, 'nt.ev.APPROVAL_REQUIRED', (m) => ({ role: role('IR_TEAM'), subject: m[1] })],
  ],
  RESPONSE_ASSIGNED: [[/^Response Ticket awaiting IR decision — ([\s\S]*)$/, 'nt.ev.RESPONSE_ASSIGNED', (m) => ({ subject: m[1] })]],
  RESPONSE_STARTED: [[/^Response started on ([\s\S]*)$/, 'nt.ev.RESPONSE_STARTED', (m) => ({ subject: m[1] })]],
  RESPONSE_COMPLETED: [[/^Response completed — re-hunt required: ([\s\S]*)$/, 'nt.ev.RESPONSE_COMPLETED', (m) => ({ subject: m[1] })]],
  VERIFICATION_NOT_RESOLVED: [[/^Re-hunt: threat still present \(NOT RESOLVED\) — ([\s\S]*)$/, 'nt.ev.VERIFICATION_NOT_RESOLVED', (m) => ({ subject: m[1] })]],
  INVESTIGATION_REOPENED: [[/^Investigation #(\d+) opened after re-hunt — ([\s\S]*)$/, 'nt.ev.INVESTIGATION_REOPENED', (m) => ({ n: m[1], subject: m[2] })]],
  INCIDENT_RESOLVED: [[/^Incident RESOLVED — re-hunt found no recurrence \(round (\d+)\)$/, 'nt.ev.INCIDENT_RESOLVED', (m) => ({ n: m[1] })]],
  INCIDENT_ESCALATED: [[/^Incident ESCALATED — not resolved after (\d+) re-hunt rounds$/, 'nt.ev.INCIDENT_ESCALATED', (m) => ({ n: m[1] })]],
  ALERT_REVIEW_DUE: [[/^Monitored \w+ alert due for review: ([\s\S]*)$/, 'nt.ev.ALERT_REVIEW_DUE', (m) => ({ subject: m[1] })]],
}
/** Every workflow e-mail is recorded as "Email to ROLE: subject" whatever its event type. */
const EMAIL: Rule = [/^Email to (\S+): ([\s\S]*)$/, 'nt.ev.email', (m) => ({ role: role(m[1]), subject: m[2] })]

const BODY: Rule[] = [
  [/^Created by (\S+) from (\d+) alert\(s\)\. AI analysis queued\.$/, 'nt.body.created', (m) => ({ actor: m[1], n: m[2] })],
  [/^Sent by (\S+)\.$/, 'nt.body.sentBy', (m) => ({ actor: m[1] })],
  [/^Monitoring reason: ([\s\S]*)$/, 'nt.body.monitor', (m) => ({ reason: m[1] })],
]

function apply(text: string, rules: Rule[]): string | null {
  for (const [re, key, params] of rules) {
    const m = re.exec(text)
    if (m) return tr(key, params(m))
  }
  return null
}

/** A notification's title and body in the current language (English keeps the backend text as written). */
export function notificationText(n: { eventType: string; title: string; body: string | null }): { title: string; body: string | null } {
  if (currentLang() === 'en') return { title: n.title, body: n.body }
  const title = apply(n.title, [...(TITLE[n.eventType] ?? []), EMAIL]) ?? n.title
  let body = n.body
  if (body) {
    const codes = body.split(/,\s*/)
    body = codes.every((c) => hasMsg(`nt.body.${c}`)) ? codes.map((c) => tr(`nt.body.${c}` as MsgKey)).join(', ') : apply(body, BODY) ?? body
  }
  return { title, body }
}

/** Short event-type label under a notification ("new incident", "re-hunt …"). */
export function notificationType(eventType: string): string {
  const key = `nt.type.${eventType}`
  return hasMsg(key) ? tr(key) : eventType.replace(/_/g, ' ').toLowerCase()
}

/** An incident timeline description (written by the backend or the AI orchestrator) in the current language. */
export function timelineText(eventType: string, description: string | null): string | null {
  if (!description || currentLang() === 'en') return description
  let m: RegExpExecArray | null
  switch (eventType) {
    case 'created':
      if ((m = /^Incident opened automatically: (\w+) Wazuh alert \(rule (\S+), level (\S+)\)(?: — Policy ([^.]+))?/.exec(description))) {
        return tr('act.autoCreated', { sev: sev(m[1]), rule: m[2], level: m[3] }) + (m[4] ? ` — Policy ${m[4]}` : '')
      }
      if (/^Incident opened automatically/.test(description)) return tr('act.autoCreatedPlain')
      if ((m = /^Incident created manually from (\d+) alert\(s\): ([\s\S]*)$/.exec(description))) return tr('tl.socCreated', { n: m[1], reason: m[2] })
      if ((m = /^Incident created manually from (\d+) alert\(s\)\.?$/.exec(description))) return tr('tl.socCreatedPlain', { n: m[1] })
      return description
    case 'ai_analysis_complete':
      if ((m = /^AI analysis FAILED \((\w+)\): ([\s\S]*?) — no AI analysis was produced\.$/.exec(description))) return tr('tl.aiFailed', { code: m[1], message: m[2] })
      if ((m = /Severity stays the Wazuh severity \((\w+)\)/.exec(description))) return tr('tl.aiDone', { sev: sev(m[1]) })
      if (/^AI pipeline completed/.test(description)) return tr('tl.aiDonePlain')
      return description
    case 'alert_added':
      return (m = /^Alert (\S+) added to the incident/.exec(description)) ? tr('tl.alertAdded', { id: m[1] }) : description
    case 'merged':
      return (m = /^Merged into incident (\S+)/.exec(description)) ? tr('tl.merged', { id: m[1] }) : description
    case 'SEVERITY_VALIDATED':
      if ((m = /^Severity changed (\w+) -> (\w+) by (\S+?)(?: \(Wazuh severity (\w+)\))?(?:: ([\s\S]*))?$/.exec(description))) {
        return tr('tl.sevChanged', { by: role(m[3]), from: sev(m[1]), to: sev(m[2]) }) + (m[4] ? tr('tl.sevWazuh', { sev: sev(m[4]) }) : '') + (m[5] ? `: ${m[5]}` : '')
      }
      return description
    default:
      return description
  }
}
