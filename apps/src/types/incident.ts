import type { AssetCriticality, AuditEntry, IncidentStatus, IncidentType, RoleName, Severity, TimelineEvent } from './common'
import type { Investigation } from './investigation'
import type { ResponseProcess } from './response'
import type { ApprovalRequest } from './approval'
import type { Verification } from './verification'

export interface IncidentAssignment {
  assignedRole: RoleName
  assignedTo: string
  assignedAt: string
}

export interface Incident {
  id: string
  incidentType: IncidentType
  wazuhSeverity: Severity
  riskScore: number
  vigixSeverity: Severity
  status: IncidentStatus
  asset: string
  assetCriticality: AssetCriticality
  description: string
  createdAt: string
  updatedAt: string
  assignedTo: string
  assignedRole: RoleName
  investigationCycle: number
  investigation: Investigation
  response: ResponseProcess
  approval: ApprovalRequest
  verification: Verification
  timeline: TimelineEvent[]
  auditTrail: AuditEntry[]
}
