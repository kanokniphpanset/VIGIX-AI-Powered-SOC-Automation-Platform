export interface ResponseTicket {
  incidentId: string
  owner: string
  recipient: string
  subject: string
  body: string
  delivery: 'DRAFT' | 'DEMO' | 'SENT' | 'FAILED'
  sentAt?: string
  approvedBy?: string
  approvedAt?: string
  executionResult?: string
  executionEvidence?: string
  completedAt?: string
  analysisRevision: number
  lastAnalysisAt?: string
  managerApproval?: {
    status: 'NOT_REQUIRED' | 'REQUIRED' | 'PENDING' | 'APPROVED' | 'REJECTED'
    manager: string
    email: string
    action: string
    subject: string
    body: string
    requestedAt?: string
    decidedAt?: string
    decidedBy?: string
    comment?: string
  }
  history?: { at: string; cycle: number; label: string; snapshot: string }[]
}
