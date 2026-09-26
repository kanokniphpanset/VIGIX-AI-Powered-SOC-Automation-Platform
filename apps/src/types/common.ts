// Shared primitive types used across the VIGIX domain model.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type IncidentStatus =
  | 'NEW'
  | 'INVESTIGATING'
  | 'VALIDATION'
  | 'ASSIGNED'
  | 'WAITING_APPROVAL'
  | 'APPROVED'
  | 'RESPONDING'
  | 'VERIFYING'
  | 'RE_INVESTIGATING'
  | 'RESOLVED'
  | 'CLOSED'
  | 'ESCALATED'

export type IncidentType =
  | 'Ransomware'
  | 'Malware'
  | 'Brute Force'
  | 'SQL Injection'
  | 'Suspicious Login'
  | 'Phishing'
  | 'Data Exfiltration'
  | 'Others'

export type AssetCriticality = 'Critical' | 'High' | 'Medium' | 'Low'

export type RoleName = 'SOC Analyst' | 'IR Team' | 'Administrator'

export type MatchVerdict = 'MALICIOUS' | 'SUSPICIOUS' | 'UNKNOWN' | 'NO_MATCH' | 'ERROR_TIMEOUT'

export type StepStatus = 'PENDING' | 'IN_PROGRESS' | 'COMPLETED' | 'SKIPPED'

export type ApprovalDecision = 'APPROVE' | 'REJECT' | 'REQUEST_MODIFICATION'

export type AnalystDecision = 'APPROVE' | 'MODIFY' | 'REJECT' | 'REQUEST_MORE_EVIDENCE'

export type VerificationResultType =
  | 'RESOLVED'
  | 'ACTIVITY_REDUCED'
  | 'STILL_ACTIVE'
  | 'RE_INVESTIGATION_REQUIRED'
  | 'PENDING'

export interface AuditEntry {
  id: string
  actor: string
  role: RoleName
  action: string
  detail?: string
  timestamp: string
}

export interface TimelineEvent {
  id: string
  label: string
  description: string
  actor?: string
  timestamp: string
  kind: 'system' | 'analyst' | 'ir' | 'manager' | 'ai'
}
