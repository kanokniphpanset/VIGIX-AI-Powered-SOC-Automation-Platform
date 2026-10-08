// Role workspaces (read-only, /api/v1/work) + incident audit / AI jobs + role-context incident email.
// Shapes mirror the backend responses; nothing is derived or invented here.
import { api } from './http.ts'
import type { EmailPreview } from './vigix'

export interface ApprovalStep {
  id: string
  role: string | null
  /** pending (active) | waiting (later chain step) | approved | rejected | more_evidence_requested | cancelled */
  status: string
  stepOrder: number
  decidedBy: string | null
  decidedAt: string | null
  createdAt: string
}

export type TicketQueue =
  | 'my-work'
  | 'awaiting-decision'
  | 'ready'
  | 'in-progress'
  | 'awaiting-rehunt'
  | 'completed'
  | 'rejected'
  | 'failed'
  | 'escalated'
  | 'all'

export type WorkTicketStage =
  | 'AWAITING_IR_DECISION'
  | 'AWAITING_MANUAL_DECISION'
  | 'READY_FOR_EXECUTION'
  | 'IN_PROGRESS'
  | 'AWAITING_REHUNT'
  | 'COMPLETED'
  | 'NOT_RESOLVED'
  | 'ESCALATED'
  | 'FAILED'
  | 'REJECTED'
  | 'CLOSED'

export interface WorkTicket {
  id: string
  incidentId: string
  incidentTitle: string
  incidentStatus: string
  incidentPriority: string
  investigationNumber: number
  recommendationId: string
  recommendationStepId: string | null
  stepTitle: string | null
  stepOrder: number | null
  actionCode: string | null
  actionName: string | null
  target: string | null
  status: string
  approvalStatus: string
  /** Executor role Policy assigned. */
  assignedRole: string
  /** Backend assignment: the user who started the response. */
  assignedTo: string | null
  assignedToEmail: string | null
  executedAt: string | null
  completedAt: string | null
  createdAt: string
  updatedAt: string
  approvals: ApprovalStep[]
  verification: { id: string; result: string; spreadDetected: boolean; verifiedAt: string } | null
  stage: WorkTicketStage
  currentApproval: ApprovalStep | null
  assignedToMe: boolean
}

export interface WorkApproval {
  id: string
  role: string | null
  status: string
  stepOrder: number
  reason: string | null
  comment: string | null
  decidedBy: string | null
  decidedByEmail: string | null
  decidedAt: string | null
  createdAt: string
  responseId: string | null
  recommendationId: string | null
  incidentId: string
  incidentTitle: string
  incidentPriority: string
  incidentStatus: string
  target: string | null
  planStatus: string | null
  stepTitle: string | null
  actionName: string | null
  chain: ApprovalStep[]
  /** Backend verdict: this is the viewer's own ACTIVE step (never true for admin). */
  canDecide: boolean
}

export interface WorkIncident {
  id: string
  title: string
  status: string
  priority: string
  openedAt: string
  closedAt: string | null
  investigationNumber: number
  alertId: string
  scenario: { id: string } | null
  responsibleRole: string | null
  executorRole: string | null
  currentApproval: { role: string | null; stepOrder: number } | null
  responseStatus: string | null
  aiJob: { status: string; trigger: string | null; attempt: number; at: string } | null
  lastVerification: string | null
  updatedAt: string
}

export interface AuditEntry {
  id: string
  source: 'audit' | 'timeline'
  occurredAt: string
  action: string
  actor: string
  actorEmail: string | null
  actorRole: string | null
  entity: string | null
  entityId: string | null
  description: string | null
  metadata: Record<string, unknown> | null
}

/** A closed incident similar to the current one (GET /incidents/:id/similar) — deterministic match, no AI. */
export interface SimilarCase {
  id: string
  title: string
  status: string
  priority: string
  openedAt: string
  closedAt: string | null
  investigationNumber: number
  lastVerification: string | null
  actions: { code: string | null; name: string | null; target: string | null; status: string }[]
  closeNote: string | null
  score: number
  reasons: { kind: 'SAME_IOC' | 'SAME_RULE' | 'SAME_TECHNIQUE' | 'SAME_HOST'; values: string[] }[]
}

export interface AiJob {
  id: string
  status: string
  trigger: string | null
  attempt: number
  queuedAt: string | null
  startedAt: string
  completedAt: string | null
  errorCode: string | null
  errorMessage: string | null
}

/** GET /api/v1/work/iocs — one indicator across every incident of the tenant. */
export interface IocLibraryItem {
  iocType: string
  iocValue: string
  sources: string[]
  reputationScore: number | null
  confidence: number | null
  firstSeen: string | null
  lastSeen: string | null
  caseCount: number
  cases: { id: string; title: string; status: string; openedAt: string | null }[]
}

export const workApi = {
  tickets: (queue: TicketQueue, limit = 25, offset = 0, incidentId?: string) =>
    api<{ queue: TicketQueue; counts: Record<TicketQueue, number>; total: number; items: WorkTicket[] }>('/api/v1/work/tickets', {
      query: { queue, limit, offset, incidentId },
    }),
  approvals: (scope: 'mine' | 'all', status: 'pending' | 'waiting' | 'decided' | 'all', limit = 50, offset = 0) =>
    api<{ total: number; counts: { minePending: number; mineWaiting: number; mineDecided: number }; items: WorkApproval[] }>('/api/v1/work/approvals', {
      query: { scope, status, limit, offset },
    }),
  incidents: (f: { status?: string; priority?: string; search?: string; limit?: number; offset?: number }) =>
    api<{ total: number; items: WorkIncident[] }>('/api/v1/work/incidents', { query: { ...f } }),
  iocs: (limit = 500) => api<{ total: number; items: IocLibraryItem[] }>('/api/v1/work/iocs', { query: { limit } }),
  audit: (incidentId: string) => api<{ items: AuditEntry[] }>(`/api/v1/incidents/${incidentId}/audit`),
  aiJobs: (incidentId: string) => api<{ items: AiJob[] }>(`/api/v1/incidents/${incidentId}/ai-jobs`),
  similarCases: (incidentId: string, limit = 5) => api<{ items: SimilarCase[] }>(`/api/v1/incidents/${incidentId}/similar`, { query: { limit } }),
}

export type EmailRecipientRole = 'SOC' | 'IR_TEAM' | 'ADMIN'

export interface ContextEmailOutcome {
  status: 'SENT' | 'FAILED' | 'NOT_SENT'
  recipientRole: EmailRecipientRole
  recipient: string | null
  sentAt: string | null
  deliveryId: string | null
  error: string | null
  duplicate: boolean
  context: string
}

export interface ContextEmailPreview {
  email: EmailPreview
  recipient: { recipientRole: EmailRecipientRole; recipient: string | null; source: 'settings' | 'server' | 'none'; emailChannelConfigured: boolean }
  /** INVESTIGATION (SOC) | RESPONSE (IR) | ADMINISTRATIVE (admin) — follows the sender's role. */
  context: string
}

export const incidentEmailApi = {
  preview: (incidentId: string, recipientRole: EmailRecipientRole, note?: string) =>
    api<ContextEmailPreview>(`/api/v1/incidents/${incidentId}/context-email`, { query: { recipientRole, note } }),
  send: (incidentId: string, body: { recipientRole: EmailRecipientRole; note: string | null; idempotencyKey: string }) =>
    api<ContextEmailOutcome>(`/api/v1/incidents/${incidentId}/context-email`, { method: 'POST', body }),
}
