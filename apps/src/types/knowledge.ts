export type KnowledgeType =
  | 'Organization Playbook'
  | 'Response Playbook'
  | 'Historical Case'
  | 'MITRE ATT&CK'
  | 'External Playbook'

export interface KnowledgeItem {
  id: string
  title: string
  type: KnowledgeType
  version: string
  updatedAt: string
  usedCount: number
  status: 'Active' | 'Draft' | 'Deprecated'
  summary: string
  tags: string[]
}
