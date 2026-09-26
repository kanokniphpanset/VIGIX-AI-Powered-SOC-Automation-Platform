import type { AnalystDecision, MatchVerdict } from './common'

export interface WazuhAlert {
  ruleId: string
  ruleDescription: string
  wazuhLevel: number
  agent: string
  hostname: string
  sourceIp: string
  destinationIp?: string
  process?: string
  command?: string
  timestamp: string
  rawLog: string
}

export interface Qualification {
  result: 'QUALIFIED_INCIDENT' | 'NOT_QUALIFIED'
  reason: string
  thresholdLevel: number
  actualLevel: number
  evaluatedAt: string
}

export interface MitreMapping {
  techniqueId: string
  techniqueName: string
  tactic: string
}

export interface Classification {
  incidentType: string
  confidence: number
  mitre: MitreMapping[]
  evidenceSummary: string[]
  analystOverride?: {
    incidentType: string
    reason: string
    modifiedBy: string
    modifiedAt: string
  }
}

export interface IocRecord {
  type: 'IP' | 'Domain' | 'URL' | 'Hash' | 'Username' | 'Hostname'
  value: string
  firstSeen: string
  relatedEvents: number
}

export interface ThreatIntelSource {
  source: 'VirusTotal' | 'OTX' | 'MISP' | 'AbuseIPDB'
  verdict: MatchVerdict
  score?: string
  detail: string
  checkedAt: string
}

export interface AssetEvidence {
  hostname: string
  ipAddress: string
  os: string
  owner: string
  department: string
  criticality: string
  lastSeen: string
  agentStatus: 'Active' | 'Disconnected' | 'Never Connected'
}

export interface EvidenceBundle {
  wazuhAlerts: WazuhAlert[]
  iocs: IocRecord[]
  threatIntel: ThreatIntelSource[]
  asset: AssetEvidence
}

export interface RiskFactorItem {
  factor: string
  present: boolean
  weight: number
  detail: string
}

export interface RiskAssessment {
  wazuhSeverity: string
  vigixRiskScore: number
  vigixSeverity: string
  factors: RiskFactorItem[]
  analystValidated: boolean
  validatedBy?: string
  validatedAt?: string
}

export interface RecommendationProcessStep {
  order: number
  key: 'CONTAINMENT' | 'INVESTIGATION' | 'THREAT_HUNTING' | 'ERADICATION' | 'VERIFICATION'
  title: string
  objective: string
  recommendedAction: string
  evidenceRequired: string
  expectedResult: string
}

export interface PolicyBasis {
  organizationPolicy: string
  playbook: string
  ragSources: string[]
  historicalCases: { id: string; similarity: number; summary: string }[]
}

export interface Recommendation {
  steps: RecommendationProcessStep[]
  policyBasis: PolicyBasis
  generatedAt: string
  cycle: number
}

export interface HumanValidationRecord {
  decision: AnalystDecision | null
  comment: string
  decidedBy?: string
  decidedAt?: string
  modification?: string
}

export interface Investigation {
  incidentId: string
  wazuhAlert: WazuhAlert
  qualification: Qualification
  classification: Classification
  evidence: EvidenceBundle
  riskAssessment: RiskAssessment
  recommendation: Recommendation
  humanValidation: HumanValidationRecord
}
