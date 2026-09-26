// "ขั้นต่อไป" (Next step) for one incident (pure; runs under `node --test`). From stored facts only it answers three
// questions for whoever opens the incident: whose turn is it, what exactly is next, and which ONE button does it.
// It mirrors the two-role workflow; it never decides anything — every action still goes through its backend-gated route.

export type Turn = 'SOC' | 'IR' | 'NONE'
export type NextKey =
  | 'resolved' | 'dismissed' | 'escalated'
  | 'ir-decide' | 'ir-start' | 'ir-complete' | 'ir-rehunt'
  | 'soc-rejected' | 'soc-failed' | 'soc-severity' | 'soc-ai' | 'soc-recommend' | 'soc-regenerate' | 'soc-send' | 'soc-noaction'

/** What the card's one button does. */
export type NextAction =
  | { kind: 'tab'; tab: string; anchor?: string }
  | { kind: 'route'; to: string }
  | { kind: 'run-ai' }
  | { kind: 'generate' }

export interface NextStepFacts {
  role: string | null
  incidentId: string
  incidentStatus: string
  investigationNumber: number
  /** A SEVERITY_VALIDATED entry exists on the incident timeline (the SOC confirmed or changed the Wazuh severity). */
  severityConfirmed: boolean
  hasAiAnalysis: boolean
  /** The current recommendation, if any (VALIDATED = passed the backend validation and can be sent). */
  recommendation: { status: string } | null
  /** Action steps of the current recommendation that have no live ticket yet. */
  unsentSteps: number
  /** Response ticket statuses of this incident. */
  ticketStatuses: string[]
  /** A COMPLETED ticket has no verification (re-hunt) yet. */
  awaitingRehunt: boolean
}

export interface NextStep {
  key: NextKey
  turn: Turn
  /** True when the signed-in role is the one that acts now (only then is the button shown). */
  mine: boolean
  tone: 'action' | 'waiting' | 'done' | 'problem'
  action: NextAction
  params: Record<string, string | number>
  /** Position in the 8-step workflow (1–8), for "step n of 8"; null when the case has ended. */
  position: number | null
  /** Re-hunt already found the threat once: this is investigation round n (> 1). */
  newCycle: number | null
}

const ACTIVE = ['PENDING_IR_DECISION', 'PENDING_APPROVAL', 'READY_FOR_EXECUTION', 'APPROVED', 'IN_PROGRESS']
/** Workflow positions: SOC 1–4 (severity, AI, recommendation, send), IR 5–8 (decide, start, complete, re-hunt). */
const POSITION: Partial<Record<NextKey, number>> = {
  'soc-severity': 1, 'soc-ai': 2, 'soc-recommend': 3, 'soc-regenerate': 3, 'soc-send': 4, 'soc-noaction': 4,
  'soc-rejected': 4, 'soc-failed': 4, 'ir-decide': 5, 'ir-start': 6, 'ir-complete': 7, 'ir-rehunt': 8,
}
export const WORKFLOW_STEPS = 8

export function nextStep(f: NextStepFacts): NextStep {
  const tickets = (id: string, queue: string): NextAction => ({ kind: 'route', to: `/tickets?queue=${queue}&incident=${id}` })
  const rec: NextAction = { kind: 'tab', tab: 'recommendation' }
  const has = (...s: string[]) => f.ticketStatuses.some((x) => s.includes(x))
  const make = (key: NextKey, turn: Turn, action: NextAction, params: Record<string, string | number> = {}): NextStep => {
    const mine = (turn === 'SOC' && f.role === 'SOC') || (turn === 'IR' && f.role === 'IR_TEAM')
    const tone = turn === 'NONE' ? 'done' : key === 'escalated' || key === 'soc-rejected' || key === 'soc-failed' ? 'problem' : mine ? 'action' : 'waiting'
    const newCycle = f.investigationNumber > 1 && turn === 'SOC' ? f.investigationNumber : null
    return { key, turn, mine, tone, action, params, position: POSITION[key] ?? null, newCycle }
  }

  // The case has ended.
  if (f.incidentStatus === 'resolved') return make('resolved', 'NONE', { kind: 'tab', tab: 'audit' })
  if (f.incidentStatus === 'dismissed') return make('dismissed', 'NONE', { kind: 'tab', tab: 'audit' })
  if (f.incidentStatus === 'escalated') return make('escalated', 'IR', { kind: 'route', to: `/tickets?queue=all&incident=${f.incidentId}` })

  // IR's turn: a ticket is in the IR part of the loop (most advanced first is not needed — any waiting ticket is work).
  if (has('PENDING_IR_DECISION', 'PENDING_APPROVAL')) return make('ir-decide', 'IR', tickets(f.incidentId, 'awaiting-decision'))
  if (has('READY_FOR_EXECUTION', 'APPROVED')) return make('ir-start', 'IR', tickets(f.incidentId, 'ready'))
  if (has('IN_PROGRESS')) return make('ir-complete', 'IR', tickets(f.incidentId, 'in-progress'))
  if (f.awaitingRehunt) return make('ir-rehunt', 'IR', tickets(f.incidentId, 'awaiting-rehunt'))

  // SOC's turn. A ticket that came back (rejected / failed) with nothing else live: the SOC reviews first.
  const live = has(...ACTIVE)
  if (!live && f.unsentSteps > 0 && has('REJECTED')) return make('soc-rejected', 'SOC', rec)
  if (!live && f.unsentSteps > 0 && has('FAILED')) return make('soc-failed', 'SOC', rec)
  if (!f.severityConfirmed) return make('soc-severity', 'SOC', { kind: 'tab', tab: 'overview', anchor: 'severity' })
  if (!f.hasAiAnalysis) return make('soc-ai', 'SOC', { kind: 'run-ai' })
  if (!f.recommendation) return make('soc-recommend', 'SOC', { kind: 'generate' })
  if (f.recommendation.status !== 'VALIDATED') return make('soc-regenerate', 'SOC', { kind: 'generate' })
  if (f.unsentSteps > 0) return make('soc-send', 'SOC', rec, { n: f.unsentSteps })
  return make('soc-noaction', 'SOC', rec)
}
