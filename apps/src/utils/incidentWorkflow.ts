// Read-only workflow summary for the Incident Overview: response / approval / re-hunt / escalation status derived
// from the tickets and verifications the incident page already loads. Display only — the backend owns every state.
import { tr } from '../i18n/locale.ts'

export interface SummaryTicket {
  id: string
  stage: string
  status: string
  approvalStatus: string
  actionName: string | null
  target: string | null
  assignedRole: string
  updatedAt: string
  approvals: { role: string | null; status: string; stepOrder: number; decidedBy: string | null; decidedAt: string | null }[]
}

export interface SummaryVerification {
  id: string
  responseId: string
  result: string
  matchingEvents: number | null
  spreadDetected: boolean
  verifiedAt?: string
  createdAt?: string
  verifiedBy?: string
  afterState?: { evidenceSource?: string } | null
}

export interface RehuntRound {
  round: number
  id: string
  responseId: string
  result: string
  at: string | null
  by: string | null
  matchingEvents: number | null
  spreadDetected: boolean
  source: string | null
}

const when = (v: { verifiedAt?: string; createdAt?: string }) => v.verifiedAt ?? v.createdAt ?? null

/** Every re-hunt / verification of the incident, oldest first, numbered 1..n (history is never overwritten). */
export function rehuntRounds(verifications: SummaryVerification[]): RehuntRound[] {
  return [...verifications]
    .sort((a, b) => (when(a) ?? '').localeCompare(when(b) ?? ''))
    .map((v, i) => ({
      round: i + 1,
      id: v.id,
      responseId: v.responseId,
      result: v.result,
      at: when(v),
      by: v.verifiedBy ?? null,
      matchingEvents: v.matchingEvents,
      spreadDetected: v.spreadDetected,
      source: v.afterState?.evidenceSource ?? null,
    }))
}

/** The most recently updated response ticket (the one the incident is currently waiting on), or null. */
export function latestTicket<T extends SummaryTicket>(tickets: T[]): T | null {
  return [...tickets].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0] ?? null
}

/** The IR decision of a ticket in words: waiting / approved / rejected (IR_TEAM is the only approver). */
export function approvalSummary(t: SummaryTicket | null): string {
  if (!t) return tr('ap.none')
  if (t.approvals.some((a) => a.status === 'pending')) return tr('ap.waiting')
  const decided = [...t.approvals].reverse().find((a) => a.status === 'approved' || a.status === 'rejected')
  if (decided) return tr(decided.status === 'rejected' ? 'ap.rejected' : 'ap.approved')
  if (t.approvalStatus === 'NOT_REQUIRED') return tr('ap.legacy')
  return t.approvalStatus.replace(/_/g, ' ').toLowerCase()
}
