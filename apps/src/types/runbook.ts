import type { RoleName } from './common'
export interface RunbookInstruction {
  instruction: string
  owner: 'SOC Analyst' | 'IR Team'
  approvalRequired: boolean
  approvalCondition: string
  verification: string
}
export interface KnowledgeRunbook {
  id: string
  name: string
  description: string
  threatType: string
  playbookId: string
  policyIds: string[]
  caseIds: string[]
  steps: RunbookInstruction[]
  status: 'Draft' | 'Published'
  version: number
  updatedAt: string
  history: { version: number; at: string; actor: string; role: RoleName; status: string; snapshot: string }[]
}
