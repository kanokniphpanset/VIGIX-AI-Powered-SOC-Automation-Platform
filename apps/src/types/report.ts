export interface MonthlyReport {
  period: string
  generatedAt: string
  kpi: {
    totalAlerts: number
    totalIncidents: number
    critical: number
    high: number
    closed: number
    stillActive: number
    resolved: number
    reInvestigated: number
    escalated: number
  }
  executiveSummary: string
  incidentTypeDistribution: { label: string; value: number }[]
  severityDistribution: { label: string; value: number }[]
  mitreTop: { technique: string; name: string; count: number }[]
  verificationResults: { label: string; value: number }[]
  topAffectedAssets: { asset: string; incidents: number; criticality: string }[]
  approvalStatistics: { label: string; value: number }[]
  monthlyTrend: { week: string; critical: number; high: number; medium: number }[]
  investigationPerformance: { metric: string; value: string }[]
  responseSummary: { metric: string; value: string }[]
  findings: string[]
  recommendations: string[]
  criticalIncidents: { id: string; type: string; asset: string; outcome: string }[]
}
