// IR ticket lifecycle, derived only from backend state: the response plan's status, its re-hunt verification (if
// any) and the incident's status. The UI never sets or advances any of these itself.
import { workflowError } from './workflow.ts'
import { labelMap, tr } from '../i18n/locale.ts'
import { hasMsg } from '../i18n/messages.ts'
import type { Verification } from '@/api/vigix'

export type TicketStage =
  | 'AWAITING_IR_DECISION'
  | 'AWAITING_MANUAL_DECISION'
  | 'REJECTED'
  | 'READY_FOR_EXECUTION'
  | 'IN_PROGRESS'
  | 'AWAITING_REHUNT'
  | 'COMPLETED'
  | 'NOT_RESOLVED'
  | 'ESCALATED'
  | 'CLOSED'
  | 'FAILED'

export function ticketStage(planStatus: string, verification: Verification | null, incidentStatus: string | null): TicketStage {
  switch (planStatus) {
    case 'FAILED':
      return 'FAILED'
    case 'PENDING_IR_DECISION':
    case 'PENDING_APPROVAL':
      return 'AWAITING_IR_DECISION'
    case 'PENDING_MANUAL_DECISION':
      // IR rejected the recommended response: IR's own manual response decision is next.
      return 'AWAITING_MANUAL_DECISION'
    case 'REJECTED':
      return 'REJECTED'
    case 'APPROVED':
    case 'READY_FOR_EXECUTION':
      return 'READY_FOR_EXECUTION'
    case 'IN_PROGRESS':
      return 'IN_PROGRESS'
    case 'COMPLETED':
      if (!verification) return 'AWAITING_REHUNT'
      if (verification.result === 'RESOLVED') return 'COMPLETED'
      return incidentStatus === 'escalated' ? 'ESCALATED' : 'NOT_RESOLVED'
    default:
      // REJECTED / FAILED / CANCELLED / DRAFT: terminal for this ticket; the backend status is shown as-is.
      return 'CLOSED'
  }
}

export const STAGE_LABEL: Record<TicketStage, string> = labelMap({
  FAILED: 'stage.FAILED',
  AWAITING_IR_DECISION: 'stage.AWAITING_IR_DECISION',
  AWAITING_MANUAL_DECISION: 'stage.AWAITING_MANUAL_DECISION',
  REJECTED: 'stage.REJECTED',
  READY_FOR_EXECUTION: 'stage.READY_FOR_EXECUTION',
  IN_PROGRESS: 'stage.IN_PROGRESS',
  AWAITING_REHUNT: 'stage.AWAITING_REHUNT',
  COMPLETED: 'stage.COMPLETED',
  NOT_RESOLVED: 'stage.NOT_RESOLVED',
  ESCALATED: 'stage.ESCALATED',
  CLOSED: 'stage.CLOSED',
})

/** The IR decision (APPROVE and REJECT) always needs a written note. */
export const reasonNeededForDecision = (note: string) => !note.trim()

/** Readable label of a stored Response Ticket status. */
export const ticketStatusLabel = (status: string) => {
  const key = `tst.${status}`
  return hasMsg(key) ? tr(key) : status
}

export const STAGE_CLASS: Record<TicketStage, string> = {
  FAILED: 'bg-rose-50 text-rose-700 ring-rose-200',
  AWAITING_IR_DECISION: 'bg-amber-50 text-amber-800 ring-amber-200',
  AWAITING_MANUAL_DECISION: 'bg-orange-50 text-orange-800 ring-orange-200',
  REJECTED: 'bg-slate-100 text-slate-700 ring-slate-300',
  READY_FOR_EXECUTION: 'bg-sky-50 text-sky-700 ring-sky-200',
  IN_PROGRESS: 'bg-violet-50 text-violet-700 ring-violet-200',
  AWAITING_REHUNT: 'bg-accent-50 text-accent-700 ring-accent-200',
  COMPLETED: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  NOT_RESOLVED: 'bg-rose-50 text-rose-700 ring-rose-200',
  ESCALATED: 'bg-rose-100 text-rose-800 ring-rose-300',
  CLOSED: 'bg-slate-100 text-slate-600 ring-slate-200',
}

/** Maps a backend error code to analyst-readable text (the code itself is kept as the fallback). */
export function describeWorkflowError(e: unknown): string {
  const code = (e as { code?: string })?.code ?? 'UNKNOWN'
  if (code === 'FORBIDDEN' || code === 'HTTP_403') return tr('err.execForbidden')
  return workflowError(e)
}
