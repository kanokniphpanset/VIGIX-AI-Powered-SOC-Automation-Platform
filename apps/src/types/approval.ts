import type { ApprovalDecision } from './common'

export interface ApprovalHistoryEntry {
  id: string
  requestedBy: string
  requestedAt: string
  reviewedBy?: string
  reviewedAt?: string
  decision?: ApprovalDecision
  comment?: string
}

export interface ApprovalRequest {
  incidentId: string
  required: boolean
  reason: string
  recommendedResponseSummary: string
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'MODIFICATION_REQUESTED'
  history: ApprovalHistoryEntry[]
}
