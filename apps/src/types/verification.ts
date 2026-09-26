import type { VerificationResultType } from './common'

export interface RehuntQuery {
  iocs: string[]
  hostname: string
  processes: string[]
  sourceIps: string[]
  relatedEventFields: string[]
}

export interface RehuntResult {
  ranAt: string
  beforeResponseEvents: number
  afterResponseEvents: number
  result: VerificationResultType
}

export interface VerificationCycle {
  cycle: number
  startedAt: string
  rehunt?: RehuntResult
  stillActiveReason?: string
  additionalEvidenceNeeded?: string
  nextStep?: string
}

export interface Verification {
  incidentId: string
  responseCompletedAt: string
  query: RehuntQuery
  cycles: VerificationCycle[]
  maxCycles: number
  finalResult: VerificationResultType | 'ESCALATED'
}
