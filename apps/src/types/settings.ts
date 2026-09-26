export interface SeverityPolicyRule {
  id: string
  name: string
  code: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  description: string
  riskScoreMin: number
  riskScoreMax: number
  priority: number
  status: 'Active' | 'Inactive'
  approvalRequired: boolean
  irAssignment: boolean
  threatHunting: boolean
  verification: boolean
  postIncidentReview: boolean
}

export interface ResponseRecommendationRule {
  id: string
  incidentType: string
  severity: string
  assetCriticality: string
  steps: string[]
  status: 'Active' | 'Inactive'
}

export interface RoleAssignmentRule {
  id: string
  role: string
  responsibilities: string[]
  memberCount: number
}

export interface AssetCriticalityEntry {
  id: string
  assetPattern: string
  criticality: string
  department: string
  notes: string
}

export interface OrganizationPolicyDoc {
  id: string
  title: string
  version: string
  updatedAt: string
  summary: string
}
