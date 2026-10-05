// The Response Ticket page groups the backend's ticket queues into four tabs plus an "other status" filter
// (pure; runs under `node --test`). The backend still serves one queue at a time and returns every queue's count,
// so a tab only decides WHICH queue to load: "in progress" opens the first of its three queues that has work.
import type { TicketQueue } from '@/api/work'

export type TicketGroup = 'my-work' | 'awaiting-decision' | 'active' | 'completed'
export const TICKET_GROUPS: TicketGroup[] = ['my-work', 'awaiting-decision', 'active', 'completed']
/** The three queues of the "in progress" tab, in workflow order. */
export const ACTIVE_QUEUES: TicketQueue[] = ['ready', 'in-progress', 'awaiting-rehunt']
/** Queues reached from the "other status" filter. Failed and escalated come first: they need someone to look. */
export const OTHER_QUEUES: TicketQueue[] = ['failed', 'escalated', 'rejected', 'all']
const ALL: TicketQueue[] = ['my-work', 'awaiting-decision', ...ACTIVE_QUEUES, 'completed', ...OTHER_QUEUES]

type Counts = Partial<Record<TicketQueue, number>>

export function groupOf(queue: TicketQueue): TicketGroup | 'other' {
  if (ACTIVE_QUEUES.includes(queue)) return 'active'
  return (TICKET_GROUPS as string[]).includes(queue) ? (queue as TicketGroup) : 'other'
}

export function groupCount(group: TicketGroup, counts: Counts): number | null {
  const qs = group === 'active' ? ACTIVE_QUEUES : [group as TicketQueue]
  if (qs.every((q) => counts[q] == null)) return null
  return qs.reduce((n, q) => n + (counts[q] ?? 0), 0)
}

/** The queue a tab opens: the first "in progress" queue with tickets (ready when all are empty). */
export function queueForGroup(group: TicketGroup, counts: Counts): TicketQueue {
  if (group !== 'active') return group
  return ACTIVE_QUEUES.find((q) => (counts[q] ?? 0) > 0) ?? 'ready'
}

/** Tickets that need someone to look at them now (shown as a red dot on the "other status" filter). */
export function attentionCount(counts: Counts): number {
  return (counts.failed ?? 0) + (counts.escalated ?? 0)
}

/** ?queue= from a link (dashboard cards, old bookmarks) or the role's default. */
export function initialQueue(requested: unknown, canExecuteResponse: boolean): TicketQueue {
  return typeof requested === 'string' && (ALL as string[]).includes(requested) ? (requested as TicketQueue) : canExecuteResponse ? 'my-work' : 'all'
}
