import type { AlertWorkflowState, AlertDisplayState } from '../../backend/src/domain/alert/triageWorkflow'
// Typed calls to the real VIGIX backend (Alert Inbox, Alert Detail, Incident Detail, Response Tickets).
// Shapes mirror the backend responses; nothing is derived or invented here.
import { api } from './http.ts'
import type { IrEmailOutcome } from '@/utils/irEmail'
import type { RunAiAnalysisResult } from '@/utils/aiAnalysis'
import type { PlaybookRevisionItem } from '@/utils/playbookLifecycle'

export interface AlertSummary {
  ruleId: string | null
  ruleDescription: string | null
  ruleLevel: number | null
  mitreTechniques: string[]
  sourceIp: string | null
  destinationIp: string | null
  host: string | null
  agentIp: string | null
  user: string | null
}

export interface IncidentRef {
  id: string
  title: string
  status: string
  priority: string
}

/** Lab attack-test scenario an analyst labelled a real alert with (VIGIX metadata; the Wazuh alert is unchanged). */
export interface AttackScenario {
  id: string
  attackType: string
  caseName: string
  description: string
}

export interface InboxAlert {
  id: string
  externalAlertId: string
  siemSource: string
  severity: string
  status: string
  receivedAt: string
  summary: AlertSummary
  incident: IncidentRef | null
  scenario: AttackScenario | null
  /** SOC review of an alert that did not become an incident (null = not reviewed). MONITOR = legacy. */
  triage?: { disposition: 'FALSE_POSITIVE' | 'INFORMATIONAL' | 'MONITOR'; note: string | null; triagedBy: string; triagedAt: string } | null
  workflowState: AlertWorkflowState
  displayState: AlertDisplayState
  /** The SOC can still decide it (open, no incident, MEDIUM / HIGH / CRITICAL). */
  actionable: boolean
  disposition: string | null
  reviewAt: string | null
  monitorReason: string | null
  closedAt: string | null
  slaDueAt: string | null
  slaStatus: string | null
  ageMinutes: number
  firedTimes: number | null
  /** The mock fixture (lab test data) this alert was sent from; null for a real SIEM alert. */
  mock?: { key: string; title: string; set: 'TC' | 'MOCK_ATK' } | null
}

/** A mock alert fixture from resources/ (GET /alerts/mock) — lab test data, sent through normal Wazuh ingestion. */
export interface MockAlertCase {
  key: string
  set: 'TC' | 'MOCK_ATK'
  title: string
  attackType: string
  file: string
  fixtureAlertId: string | null
  ruleId: string | null
  ruleLevel: number | null
  ruleDescription: string | null
  host: string | null
}

export interface AlertView {
  alert: InboxAlert
  rawPayload: Record<string, unknown>
  iocs: { iocType: string; value: string; path: string }[]
}

export interface InboxFilters {
  search?: string
  severity?: string
  /** needs-review | in-incident | closed | all */
  status?: string
  source?: string
  sort?: string
  incident?: string
  mitre?: string
  attackType?: string
  /** Scenario id (ATK-01…) or case name. */
  scenario?: string
  agent?: string
  /** Mock fixture key (TC-01, MOCK-ATK-01, …) or 'all' = only alerts sent from mock fixtures. */
  mock?: string
  from?: string
  limit?: number
  offset?: number
}

export const alertsApi = {
  inbox: (f: InboxFilters) => api<{ items: InboxAlert[]; total: number }>('/api/v1/alerts/inbox', { query: { ...f } }),
  view: (id: string) => api<AlertView>(`/api/v1/alerts/${id}/view`),
  scenarios: () => api<{ items: AttackScenario[] }>('/api/v1/alerts/scenarios'),
  /** Mock alert fixtures (lab test data) and whether this deployment lets the SOC send them. */
  mockCatalog: () => api<{ sendEnabled: boolean; items: MockAlertCase[] }>('/api/v1/alerts/mock'),
  /** Send one fixture through the normal Wazuh ingestion path (SOC; dev/lab only). */
  sendMock: (key: string) =>
    api<{ key: string; alertId: string; externalAlertId: string; severity: string; incidentId: string | null; triageRequired: boolean }>(`/api/v1/alerts/mock/${encodeURIComponent(key)}/send`, { method: 'POST' }),
  /** SOC review of an open alert (no claim): close it (MEDIUM, reason required) or create its incident. */
  triage: (id: string, body: { decision: 'FALSE_POSITIVE' | 'INFORMATIONAL' | 'CREATE_INCIDENT'; reason: string | null }) =>
    api<{ incidentId: string | null }>(`/api/v1/alerts/${id}/triage`, { method: 'POST', body }),
  /** SOC: label a real alert with a test scenario (null removes the label). */
  setScenario: (id: string, scenarioId: string | null) => api<{ alertId: string; scenario: AttackScenario | null }>(`/api/v1/alerts/${id}/scenario`, { method: 'PUT', body: { scenarioId } }),
}

export interface Incident {
  id: string
  alertId: string
  title: string
  status: string
  priority: string
  openedAt: string
  closedAt: string | null
  investigationNumber: number
}

/** GET /api/v1/incidents/:id/severity — the only severity source is the Wazuh rule level; AI never provides one. */
export interface IncidentSeverity {
  source: 'WAZUH_RULE_LEVEL'
  wazuhSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null
  wazuhRuleLevel: number | null
  wazuhRuleId: string | null
  /** SOC-validated incident severity (starts as the Wazuh severity). */
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  overridden: boolean
  override: { reason: string | null; actor: string; at: string } | null
}

export interface TimelineEntry {
  id: string
  eventType: string
  description: string
  actor: string
  occurredAt: string
}

export type AlertFactKey = 'user' | 'sourcePort' | 'attempts' | 'program' | 'logonType' | 'workstation' | 'filePath' | 'sha256' | 'process' | 'parentProcess' | 'commandLine' | 'scriptBlock' | 'url' | 'httpStatus' | 'log'
export interface IncidentAlertFactRow {
  alertId: string
  externalAlertId: string
  severity: string
  ruleLevel: number | null
  ruleDescription: string | null
  sourceIp: string | null
  destinationIp: string | null
  mitreTechniques: string[]
  incidentType: string | null
  facts: { key: AlertFactKey; value: string }[]
}
export interface IncidentAlertFacts {
  incidentType: string | null
  playbook: { code: string; name: string } | null
  matchedTechniques: string[]
  rows: IncidentAlertFactRow[]
}

export type GuidanceSource = 'CASE' | 'GROUP' | 'PLAYBOOK'
export interface ResponseSetup {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  detectedType: string | null
  incidentType: string | null
  typeSource: 'SOC' | 'MITRE' | null
  types: { incidentType: string; playbookCode: string; playbookName: string }[]
  playbook: { code: string; name: string; version: string; matchedTechniques: string[]; actions: { code: string; name: string; impactLevel: string }[] } | null
  group: { incidentType: string; severity: string; policies: string[]; allowedActions: string[] | null; notes: string[] } | null
  caseGuidance: { allowedActions: string[]; instructions: string | null; setBy: string; setAt: string } | null
  effective: { allowedActions: string[]; instructions: string | null; source: GuidanceSource }
}

/** GET /api/v1/incidents/:id/response-group - the incident's group (type + severity), its response policy, its incidents. */
export interface ResponseGroup {
  group: { incidentType: string; severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; policyCode: string } | null
  policy: { code: string; enabled: boolean; version: number; updatedAt: string; allowedActions: string[] | null; note: string | null } | null
  members: { id: string; title: string; status: string; severity: string; openedAt: string; typeSource: 'SOC' | 'MITRE' }[]
}

export interface RawAlert {
  id: string
  externalAlertId: string
  severity: string
  status: string
  receivedAt: string
  rawPayload: Record<string, unknown>
}

export interface Investigation {
  id: string
  investigationNumber: number
  status: string
  startedAt: string
  completedAt: string | null
  evidenceCount: number
  iocCount: number
  isCurrent: boolean
}

export interface Evidence {
  id: string
  type: string
  source: string
  origin: string
  title: string
  description: string | null
  timestamp: string
}

export interface Ioc {
  id: string
  iocType: string
  iocValue: string
  source: string
  reputationScore: number | null
  manual?: boolean
  createdBy?: string | null
  createdAt?: string
  /** Related-alert evidence: the OTHER Wazuh alert the SOC observed this indicator in (1 Alert = 1 Incident stays). */
  sourceAlertId?: string | null
  sourceExternalAlertId?: string | null
  addedReason?: string | null
  /** Threat Intelligence result the AI pipeline recorded for this indicator (latest AI job); null when none. */
  threatIntel?: IocThreatIntel | null
}

export interface IocThreatIntel {
  /** MALICIOUS / SUSPICIOUS / BENIGN / UNKNOWN, as recorded. */
  verdict: string | null
  confidence: number | null
  providers: { provider: string; status: string; source: string | null }[]
  evidence: { provider: string; summary: string | null; reference: string | null }[]
  queriedAt: string | null
  executionId: string | null
}

/** GET /api/v1/incidents/:id/related-alert-evidence — read only; the alerts keep their own incidents. */
export interface RelatedAlertEvidence {
  alertId: string
  externalAlertId: string
  severity: string
  ruleId: string | null
  ruleDescription: string | null
  ruleLevel: number | null
  host: string | null
  receivedAt: string
  incidentId: string | null
  relation: ('SAME_HOST' | 'SHARED_IOC')[]
  sharedIocs: string[]
  iocs: { iocType: string; value: string; path: string; onIncident: boolean }[]
}

export interface MitreMapping {
  techniqueId: string
  tactic: string
  confidence: number | null
}

/** AI analysis of the evidence. It never carries a severity: VIGIX severity comes only from the Wazuh rule level. */
/** LLM = real model output; the others are never shown as an AI analysis (backend domain/ai/analysisSource.ts). */
export type AnalysisSource = 'LLM' | 'FAILED' | 'HEURISTIC_FALLBACK' | 'UNVERIFIED_LEGACY'

export interface AiAnalysis {
  grounding?: { status: 'GROUNDED' | 'UNGROUNDED'; ungrounded: { kind: string; value: string }[] } | null
  summary: string | null
  keyFindings: string[]
  /** 'LLM' when summary is a real LLM analysis. */
  source?: AnalysisSource | null
  model?: string | null
  generatedAt?: string | null
  /** The most recent run when it is not the analysis shown (a failed run / a legacy heuristic fallback kept as history). */
  latestRun?: { source: AnalysisSource; generatedAt: string } | null
}

export interface RecommendationInstruction {
  order: number
  instruction: string
  target: string | null
  expectedResult: string | null
  /** Subtype-knowledge recommendations (optional, additive): contract-format pieces of one instruction. */
  title?: string
  impact?: string | null
  verify?: string | null
  kind?: 'action' | 'verify'
  /** named non-IR owner (DBA, business authority ...) who performs this instruction. */
  manualOwner?: string | null
  /** how to perform it / checks before acting / how to undo / why it is proposed again (optional, additive). */
  method?: string | null
  methodKind?: 'method' | 'detail'
  preconditions?: string[]
  rollback?: string | null
  note?: string | null
}

export interface RecommendationStep {
  id: string
  stepOrder: number
  /** CHECK: investigation / decision step. ACTION: catalog Action (ticketable). MANUAL: control VIGIX cannot execute. */
  stepType?: 'ACTION' | 'CHECK' | 'MANUAL'
  /** Procedure condition that must be confirmed before the step is carried out. */
  precondition?: string | null
  title: string
  objective: string | null
  actionId: string | null
  target: string | null
  reason: string
  evidence: string[]
  requiresApproval: boolean
  instructions: RecommendationInstruction[]
  verificationCriteria: string | null
}

export interface Recommendation {
  id: string
  investigationNumber: number
  recommendationNumber: number
  status: string
  summary: string
  createdBy: string
  steps: RecommendationStep[]
  /** The numbered "คำแนะนำเพื่อยับยั้ง Incident" text (subtype-knowledge recommendations), rendered by the backend from the stored steps. */
  recommendationText?: string
}

/** Recommendation Preview (subtype knowledge): read-only, never persisted; no internal ids. */
export interface RecommendationPreview {
  available: boolean
  /** FIXTURE_PREVIEW = simulated data, never the result of a real incident. */
  source: 'STORED_SHADOW' | 'COMPUTED_PREVIEW' | 'FIXTURE_PREVIEW' | null
  fixture?: { id: string; title: string; note: string }
  label: string
  reviewed: boolean
  unavailableReason: string | null
  generatedAt: string
  investigationNumber: number | null
  basis: { ticketCount: number; rehunt: { round: number; result: string; verifiedAt: string | null } | null; organizationContextComplete: boolean } | null
  summary: string | null
  explain: string[]
  measures: {
    label: string
    target: string | null
    objective: string
    instructions: { title: string; method: string | null; methodKind: 'method' | 'detail'; preconditions: string[]; impact: string | null; verify: string | null; rollback: string | null; note: string | null; owner: string | null }[]
  }[]
  overallVerify: string[]
  approvals: { label: string; target: string | null; text: string }[]
  missingInfo: string[]
  priorStatus: { category: 'effective' | 'pending' | 'unverified' | 'failed'; label: string; text: string }[]
  toolNote: string | null
  text: string | null
  /** Computed preview: what it was computed from (the incident's real alerts) and what is still missing. */
  evidenceBasis?: {
    alerts: {
      ref: string
      externalAlertId: string | null
      eventTime: string | null
      ingestedAt: string | null
      provenanceClass: 'REAL_TELEMETRY' | 'HARNESS_GENERATED' | 'MOCK_FIXTURE' | 'UNKNOWN_ORIGIN' | null
      mapping: 'STORED_V2' | 'ADAPTED_IN_MEMORY' | 'EXTRACT_FAILED' | 'NOT_WAZUH' | 'NO_RAW_ALERT'
      error: string | null
      observed: { label: string; value: string }[]
      unmapped: { label: string; path: string; value: string }[]
    }[]
    adaptedInMemory: boolean
    analystAssertions: number
    gap: {
      family: { label: string; source: 'SOC' | 'MITRE' } | null
      targets: { label: string; value: string; ok: boolean; problems: string[] }[]
      needed: { subtype: string; items: string[]; notEnough: string[] }[]
    }
    familyNote: string | null
  }
}

export interface ResponsePlan {
  id: string
  recommendationId: string
  recommendationStepId: string | null
  target: string | null
  reason: string
  approvalStatus: string
  assignedRole: string
  assignedTo: string | null
  status: string
  /** Set by the backend when the response is started. */
  executedAt: string | null
  completedAt: string | null
  incidentId?: string
  actionId?: string
  expectedResult?: string | null
  /** Whatever the analyst submitted on completion/failure (outcome, note, checklist...). */
  executionResult?: Record<string, unknown> | null
  createdAt?: string
  updatedAt?: string
}

/** One IOC-matching SIEM event found by a re-hunt (stored on the verification's afterState). */
export interface RehuntEvent {
  id: string
  host: string | null
  agentId?: string | null
  ruleId?: string | null
  ruleLevel?: number | null
  ruleDescription?: string | null
  timestamp: string
  matchedIoc?: boolean
  matchedIocValues?: string[]
}

export interface Verification {
  id: string
  responseId: string
  result: string
  matchingEvents: number | null
  spreadDetected: boolean
  threatContained: boolean
  iocRecurrence: boolean
  verifiedAt?: string
  createdAt?: string
  wazuhIndex?: string | null
  timeRangeStart?: string | null
  timeRangeEnd?: string | null
  affectedHosts?: string[]
  afterState?: {
    events?: RehuntEvent[]
    truncated?: boolean
    evidenceSource?: string
    /** IOCs the re-hunt query actually searched. */
    searchedIocs?: { type: string; value: string }[]
    /** IOC categories with no field in the index — not searched (never a NO MATCH for them). */
    skippedIocTypes?: string[]
    skippedIocs?: { type: string; value: string; reason: string }[]
    /** The alert's own endpoint identity (agent.name / agent.ip), never hunted. */
    excludedIocs?: { type: string; value: string; reason: string }[]
  } | null
  notes?: string | null
  verifiedBy?: string
}

export const incidentsApi = {
  updateStatus: (id: string, status: string) => api<Incident>(`/api/v1/incidents/${id}/status`, { method: 'PATCH', body: { status } }),
  /** Human severity validation (SOC / IR_TEAM): confirm or correct the incident severity that Policy uses. */
  validateSeverity: (id: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', note: string | null) =>
    api<{ severity: string; previous: string; changed: boolean; wazuhSeverity: string | null; overridesWazuh: boolean }>(`/api/v1/incidents/${id}/severity-validation`, { method: 'POST', body: { severity, note } }),
  /** SOC's explicit Send / Don't send email choice (never automatic; duplicate-protected). */
  notificationDecision: (id: string, notification: 'SEND' | 'SKIP', note: string | null) => api<{ choice: string; email: { status: string; error: string | null; duplicate: boolean } | null }>(`/api/v1/incidents/${id}/notification-decision`, { method: 'POST', body: { notification, note } }),
  addEvidence: (id: string, body: Record<string, unknown>) => api<Evidence>(`/api/v1/investigations/${id}/evidence`, { method: 'POST', body }),
  addIoc: (id: string, body: Record<string, unknown>) => api<Ioc>(`/api/v1/investigations/${id}/iocs`, { method: 'POST', body }),
  list: (limit = 50, offset = 0) => api<{ items: Incident[]; total: number }>('/api/v1/incidents', { query: { limit, offset } }),
  get: (id: string) => api<Incident>(`/api/v1/incidents/${id}`),
  timeline: (id: string) => api<TimelineEntry[]>(`/api/v1/incidents/${id}/timeline`),
  alerts: (id: string) => api<{ items: RawAlert[] }>(`/api/v1/incidents/${id}/alerts`),
  /** Investigation table: each alert's key facts for the incident type (type from the matched playbook). */
  alertFacts: (id: string) => api<IncidentAlertFacts>(`/api/v1/incidents/${id}/alert-facts`),
  /** SOC response setup before a Recommendation: incident type, group / case guidance, what applies now. */
  responseSetup: (id: string) => api<ResponseSetup>(`/api/v1/incidents/${id}/response-setup`),
  /** Read-only: the incident's group, its response policy and the incidents in the group. */
  responseGroup: (id: string) => api<ResponseGroup>(`/api/v1/incidents/${id}/response-group`),
  setIncidentType: (id: string, incidentType: string | null) => api<ResponseSetup>(`/api/v1/incidents/${id}/incident-type`, { method: 'PUT', body: { incidentType } }),
  setCaseGuidance: (id: string, allowedActions: string[], instructions: string | null) => api<ResponseSetup>(`/api/v1/incidents/${id}/response-guidance`, { method: 'PUT', body: { allowedActions, instructions } }),
  clearCaseGuidance: (id: string) => api<ResponseSetup>(`/api/v1/incidents/${id}/response-guidance`, { method: 'DELETE' }),
  saveGroupGuidance: (id: string, allowedActions: string[], note: string | null) => api<ResponseSetup>(`/api/v1/incidents/${id}/response-guidance/group`, { method: 'PUT', body: { allowedActions, note } }),
  iocs: (id: string) => api<{ items: Ioc[] } | Ioc[]>(`/api/v1/incidents/${id}/iocs`),
  relatedAlertEvidence: (id: string) => api<{ items: RelatedAlertEvidence[]; criteria: Record<string, unknown> }>(`/api/v1/incidents/${id}/related-alert-evidence`),
  mitre: (id: string) => api<{ items: MitreMapping[] } | MitreMapping[]>(`/api/v1/incidents/${id}/mitre-mappings`),
  aiAnalysis: (id: string) => api<AiAnalysis>(`/api/v1/incidents/${id}/ai-analysis`),
  /** Run / Re-run the existing AI pipeline for this incident's alert (analysis only; SOC / IR_TEAM). */
  runAiAnalysis: (id: string) => api<RunAiAnalysisResult>(`/api/v1/incidents/${id}/ai-analysis/run`, { method: 'POST' }),
  investigations: (id: string) => api<{ items: Investigation[] }>(`/api/v1/incidents/${id}/investigations`),
  evidence: (investigationId: string) => api<{ items: Evidence[] } | Evidence[]>(`/api/v1/investigations/${investigationId}/evidence`),
  recommendations: (id: string) => api<{ items: Recommendation[] }>(`/api/incidents/${id}/recommendations`),
  /** Read-only Recommendation Preview (GET): creates no recommendation, ticket or action. SOC / IR_TEAM. */
  recommendationPreview: (id: string) => api<RecommendationPreview>(`/api/incidents/${id}/recommendations/preview`),
  responses: (id: string) => api<{ items: ResponsePlan[] }>('/api/responses', { query: { incidentId: id, limit: 100 } }),
  verifications: (id: string) => api<{ items: Verification[] }>(`/api/incidents/${id}/verifications`),
  /** Create Incident from alerts that belong to no incident yet (SOC). */
  create: (body: { title: string; priority: string; alertIds: string[]; note?: string }) => api<Incident>('/api/v1/incidents', { method: 'POST', body }),
  /** Wazuh severity (rule level), SOC-validated severity and override reason — kept separate; no AI value exists. */
  severity: (id: string) => api<IncidentSeverity>(`/api/v1/incidents/${id}/severity`),
}

/** Some list endpoints return a bare array, others { items }. */
export function items<T>(r: { items: T[] } | T[]): T[] {
  return Array.isArray(r) ? r : r.items
}

export const authApi = {
  login: (email: string, password: string) => api<{ token: string; role: string; tenantId?: string }>('/api/auth/login', { method: 'POST', body: { email, password } }),
  /** The signed-in user's own password (identity from the JWT). Errors: 400 CURRENT_PASSWORD_INCORRECT /
   *  PASSWORD_POLICY_VIOLATION {rules} / PASSWORD_UNCHANGED / PASSWORD_CONFIRMATION_MISMATCH. */
  changePassword: (body: { currentPassword: string; newPassword: string; confirmPassword: string }) =>
    api<{ changed: true; reauthRequired: true }>('/api/auth/change-password', { method: 'POST', body }),
  /** The signed-in user's own sign-in email; the current password is required. Errors: 400 CURRENT_PASSWORD_INCORRECT /
   *  EMAIL_UNCHANGED / VALIDATION_ERROR, 409 EMAIL_TAKEN. The session stays valid (the token carries no email). */
  changeEmail: (body: { newEmail: string; currentPassword: string }) =>
    api<{ changed: true; email: string }>('/api/auth/change-email', { method: 'POST', body }),
}

// ---------------------------------------------------------------- IR handoff + Ticket (workflow actions)
export interface Approval {
  createdAt?: string
  requestedTo?: string | null
  id: string
  recommendationId: string | null
  responseId: string | null
  approvalRole: string
  /** pending (awaiting the IR decision) | approved | rejected — waiting / cancelled / more_evidence_requested: history only */
  status: string
  stepOrder?: number
  reason: string | null
  decidedBy: string | null
  decidedAt: string | null
  comment: string | null
}

export interface HandoffPayload {
  incidentId: string
  title: string
  severity: string
  asset?: string
  description?: string
  recommendation?: string
  mitre?: string[]
  iocs?: string[]
  note?: string
  incidentUrl?: string
}

export const workflowApi = {
  /** Re-opens a missing IR decision for a ticket still awaiting it (fallback; the ticket normally opens it itself). */
  requestApproval: (recommendationId: string, responseId: string) => api<Approval>('/api/approvals/request', { method: 'POST', body: { recommendationId, responseId } }),
  validateRecommendation: (id: string) => api<{ recommendation: Recommendation; violations: unknown[] }>(`/api/recommendations/${id}/validate`, { method: 'POST' }),
  submitVerification: (incidentId: string, body: Record<string, unknown>) => api<Verification>(`/api/incidents/${incidentId}/verifications`, { method: 'POST', body }),
  allResponses: (limit = 25, offset = 0, incidentId?: string) => api<{ items: (ResponsePlan & { incidentId: string; actionId: string; expectedResult: string | null; createdAt: string })[]; total: number }>('/api/responses', { query: { limit, offset, incidentId } }),
  response: (id: string) => api<ResponsePlan & { incidentId: string; createdAt: string }>(`/api/responses/${id}`),
  recommendation: (id: string) => api<Recommendation>(`/api/recommendations/${id}`),
  approvalsFor: (recommendationId: string) => api<{ items: Approval[] }>(`/api/recommendations/${recommendationId}/approvals`),
  /** SOC Send to IR: creates the Response Tickets (PENDING_IR_DECISION) first, then notifies IR with the ticket links. */
  sendToIr: (recommendationId: string, note?: string) =>
    api<{ tickets: ResponsePlan[] }>(`/api/recommendations/${recommendationId}/send-to-ir`, { method: 'POST', body: { note: note?.trim() || null } }),
  /** SOC: send ONE recommendation step to IR (creates its ticket). */
  createPlan: (recommendationId: string, stepId: string) => api<ResponsePlan>('/api/responses', { method: 'POST', body: { recommendationId, stepId } }),
  /** IR decision — the note is mandatory for both APPROVE and REJECT. */
  approve: (approvalId: string, note: string) => api<Approval>(`/api/approvals/${approvalId}/approve`, { method: 'POST', body: { comment: note } }),
  reject: (approvalId: string, note: string) => api<Approval>(`/api/approvals/${approvalId}/reject`, { method: 'POST', body: { comment: note } }),
  /** IR Manual Decision after a REJECT: IR approves its own manual response (note = the manual plan). */
  manualDecision: (responseId: string, note: string) => api<ResponsePlan>(`/api/responses/${responseId}/manual-decision`, { method: 'POST', body: { note } }),
  /** SOC Validation REJECT: rejects the recommendation and closes the incident (note mandatory). */
  rejectRecommendation: (recommendationId: string, note: string) => api<Recommendation>(`/api/recommendations/${recommendationId}/reject`, { method: 'POST', body: { note } }),
  /** Recommendation Preview with SIMULATED data (backend RECOMMENDATION_PREVIEW_FIXTURES=true); read-only. */
  previewFixtures: () => api<{ enabled: boolean; items: { id: string; title: string; note: string }[] }>('/api/recommendations/preview-fixtures'),
  previewFixture: (fixtureId: string) => api<RecommendationPreview>(`/api/recommendations/preview-fixtures/${encodeURIComponent(fixtureId)}`),
  /** IR starts executing an APPROVED ticket. */
  start: (responseId: string) => api<ResponsePlan>(`/api/responses/${responseId}/start`, { method: 'POST', body: {} }),
  complete: (responseId: string, executionResult: Record<string, unknown>) => api<ResponsePlan>(`/api/responses/${responseId}/complete`, { method: 'POST', body: { executionResult } }),
  fail: (responseId: string, executionResult: Record<string, unknown>) => api<ResponsePlan>(`/api/responses/${responseId}/fail`, { method: 'POST', body: { executionResult } }),
  rehunt: (incidentId: string, responseId: string, notes?: string) =>
    api<{ verification: Verification; evidence: unknown }>(`/api/incidents/${incidentId}/verifications/rehunt`, { method: 'POST', body: { responseId, notes: notes ?? null } }),
  /** Email to the server-configured IR_TEAM_EMAIL (recipient is never chosen by the client). */
  /** Re-runs recommendation generation for the incident's current cycle (validated; nothing persisted on failure). */
  regenerate: (incidentId: string) => api<Recommendation>('/api/recommendations/generate', { method: 'POST', body: { incidentId } }),
  handoff: (payload: HandoffPayload) => api<{ status: string; recipient: string }>('/api/notifications/ir-handoff', { method: 'POST', body: payload }),
}

// ---------------------------------------------------------------- Dashboard + SLA
export type SlaStatus = 'NOT_STARTED' | 'ON_TRACK' | 'AT_RISK' | 'BREACHED' | 'MET' | 'PAUSED' | 'CANCELLED'
export interface SlaClock {
  targetMinutes: number
  /** The target as the Policy states it (e.g. 3 business days); null when a policy override sets other minutes. */
  target: { value: number; unit: 'minute' | 'hour' | 'business_day' } | null
  dueAt: string
  at: string | null
  status: SlaStatus
}
export interface IncidentSla {
  incidentId: string
  priority: string | null
  firstResponse: SlaClock | null
  resolution: SlaClock | null
  matchedPolicies: string[]
}
export interface RehuntHealth {
  configured: boolean
  reachable: boolean
  clusterStatus?: string
  indexPattern: string
  alertIndices?: number
  error?: string
  provider?: 'wazuh-indexer' | 'mock'
}
export type ReportWindowKey = 'daily' | 'weekly' | '1m' | '3m'
export interface DashboardSummary {
  generatedAt: string
  /** The report window the backend resolved and filtered event counts by (null = all time). */
  window?: { period: ReportWindowKey | null; since: string | null }
  alerts: { total: number; last24h: number; unlinked: number; bySeverity: Record<string, number>; daily: { date: string; critical: number; high: number; medium: number; low: number }[] }
  incidents: { total: number; byStatus: Record<string, number>; openByPriority: Record<string, number>; mttrMinutes: number | null; resolvedLast7d: number; openedLast7d: number }
  responses: { byStatus: Record<string, number>; pendingApprovalsByRole: Record<string, number> }
  verifications: { byResult: Record<string, number> }
  topTechniques: { techniqueId: string; tactic: string; incidents: number }[]
  topSources: { value: string; incidents: number }[]
  activity: { occurredAt: string; incidentId: string; incidentTitle: string; eventType: string; description: string; actor: string }[]
  sla: { breached: number; atRisk: number; onTrack: number; notStarted: number; watchlist: { incidentId: string; title: string; status: string; priority: string | null; clock: 'firstResponse' | 'resolution'; dueAt: string; slaStatus: SlaStatus }[] }
  integrations: { rehunt: RehuntHealth; aiOrchestrator: { reachable: boolean; latencyMs: number | null } }
  aiJobs: { byStatus: Record<string, number>; total: number }
  triage: { pending: number; pendingLow: number; monitoring: number; byDisposition: Record<string, number> }
  approvals: { byRoleStatus: Record<string, Record<string, number>> }
  verificationDetail: { spread: number; awaitingRehunt: number; escalationEvents: number; escalatedIncidents: number }
  recommendationReady: number
  /** Incident severity of every non-dismissed incident (analyst-validated when corrected). */
  severityDistribution: { LOW: number; MEDIUM: number; HIGH: number; CRITICAL: number; unknown: number }
  kpi: {
    investigationTimeMinutes: number | null
    investigationSamples: number
    timeToDecisionMinutes: number | null
    decisionSamples: number
    workload: { assignee: string; role: string | null; open: number }[]
    automationSuccessRate: number | null
    automationFinished: number
  }
  systemHealth: HealthItem[]
}
export interface HealthItem {
  key: string
  label: string
  /** UNKNOWN = VIGIX cannot check it (shown as "No data available", never as healthy). */
  status: 'UP' | 'DEGRADED' | 'DOWN' | 'NOT_CONFIGURED' | 'UNKNOWN'
  detail: string | null
  latencyMs: number | null
}

// ---------------------------------------------------------------- Knowledge (read-only libraries) + system status
export interface Playbook {
  id: string
  code: string
  name: string
  description: string | null
  version: string
  status: string
  steps: { id: string; stepOrder: number; title: string; description?: string | null }[]
  /** Incident-level selection keys (scope, incidentType, mitreTechniques, allowedActions). */
  triggerConditions?: Record<string, unknown>
}
export interface Runbook {
  id: string
  code: string
  name: string
  version: string
  status: string
  description: string | null
  objective: string | null
}
export interface Policy {
  id: string
  code: string
  name: string
  description: string | null
  type: string
  enabled: boolean
  version: number
  precedence: number
  rules: { id: string }[]
}
export interface MitreTechnique {
  techniqueId: string
  name: string
  tactics: string[]
}
export const knowledgeApi = {
  record: (library: 'playbooks' | 'runbooks' | 'policies' | 'actions', id: string) => api<Record<string, unknown>>(`/api/${library}/${id}`),
  create: (library: 'playbooks' | 'runbooks' | 'policies' | 'actions', body: Record<string, unknown>) => api<Record<string, unknown>>(`/api/${library}`, { method: 'POST', body }),
  update: (library: 'playbooks' | 'runbooks' | 'policies' | 'actions', id: string, body: Record<string, unknown>) => api<Record<string, unknown>>(`/api/${library}/${id}`, { method: 'PUT', body }),
  /** DELETE /api/policies/:id or /api/playbooks/:id — audited with a copy (the reason is optional). */
  remove: (library: 'policies' | 'playbooks', id: string, reason?: string) => api<{ deleted: boolean; id: string; code: string }>(`/api/${library}/${id}`, { method: 'DELETE', body: reason ? { reason } : {} }),
  toggle: (library: 'policies' | 'actions', id: string, enabled: boolean) => api(`/api/${library}/${id}/${enabled ? 'enable' : 'disable'}`, { method: 'PATCH' }),
  actions: () => api<{ items: { id: string; code: string; name: string; description: string | null; enabled: boolean; category: string }[] }>('/api/actions'),
  evaluate: (body: Record<string, unknown>) => api<Record<string, unknown>>('/api/policies/evaluate', { method: 'POST', body }),
  playbooks: () => api<{ items: Playbook[] }>('/api/playbooks'),
  runbooks: () => api<{ items: Runbook[] }>('/api/runbooks'),
  policies: () => api<{ items: Policy[] }>('/api/policies'),
  techniques: () => api<{ techniques: MitreTechnique[] }>('/api/v1/mitre/techniques'),
}
/**
 * Playbook versions (Phase 1D): SOC / IR_TEAM (and admin) create and edit drafts; SOC / IR_TEAM publish and roll back
 * directly — there is no review or approval step.
 */
export const playbookVersionsApi = {
  list: (id: string) => api<{ publishedRevisionId: string | null; items: PlaybookRevisionItem[] }>(`/api/playbooks/${id}/revisions`),
  /** "Create New Version": a draft copy of the published version. */
  createVersion: (id: string) => api<PlaybookRevisionItem>(`/api/playbooks/${id}/revisions`, { method: 'POST', body: {} }),
  updateDraft: (id: string, revisionId: string, body: Record<string, unknown>) =>
    api<{ revisionId: string; version: string }>(`/api/playbooks/${id}/revisions/${revisionId}`, { method: 'PUT', body }),
  publish: (id: string, revisionId: string) =>
    api<{ revisionId: string; version: string }>(`/api/playbooks/${id}/revisions/${revisionId}/publish`, { method: 'POST', body: {} }),
  rollback: (id: string, revisionId: string) =>
    api<{ revisionId: string; version: string }>(`/api/playbooks/${id}/revisions/${revisionId}/rollback`, { method: 'POST', body: {} }),
}
export interface NotificationRecipient {
  role: 'SOC' | 'IR_TEAM' | 'ADMIN'
  /** Full for admin, masked for everyone else. */
  email: string | null
  masked: boolean
  source: 'settings' | 'server' | 'none'
  hasServerDefault: boolean
  updatedBy: string | null
  updatedAt: string | null
}
export const settingsApi = {
  emailProvider: () => api<{ configured: boolean; user: string; source: string }>('/api/v1/settings/email-provider'),
  saveEmailProvider: (user: string, password?: string) => api<{ configured: boolean; user: string; source: string }>('/api/v1/settings/email-provider', { method: 'PUT', body: { user, ...(password ? { password } : {}) } }),
  notificationRecipients: () => api<{ items: NotificationRecipient[] }>('/api/v1/settings/notification-recipients'),
  /** Admin only. email = null clears the Settings value (the server default applies again). */
  setNotificationRecipient: (role: string, email: string | null) =>
    api<{ items: NotificationRecipient[] }>(`/api/v1/settings/notification-recipients/${role}`, { method: 'PUT', body: { email } }),
}
// ---------------------------------------------------------------- Send to IR (article / response guide)
export interface EmailPreview {
  subject: string
  body: string
}
export interface KnowledgeArticle {
  id: string
  type: 'PLAYBOOK' | 'RUNBOOK'
  code: string | null
  title: string
  version: string | null
  status: string | null
  sections: { heading: string; lines: string[] }[]
}
export interface ResponseGuide {
  incidentId: string
  title: string
  severity: string
  priority: string
  status: string
  investigationNumber: number
  mitre: { techniqueId: string; tactic: string }[]
  iocs: { type: string; value: string; source: string }[]
  recommendation: { id: string; number: number; summary: string; status: string } | null
  playbook: { code: string; version: string } | null
  ticket: { id: string; status: string; target: string | null } | null
  steps: {
    stepOrder: number
    action: string
    target: string | null
    reason: string
    instructions: { order: number; instruction: string; expectedResult: string | null; impact?: string | null; verify?: string | null; method?: string | null; methodKind?: 'method' | 'detail'; preconditions?: string[]; rollback?: string | null; note?: string | null }[]
    verificationCriteria: string | null
    runbook: { code: string; name: string } | null
  }[]
}
export type { IrEmailOutcome }
/** Who the email would go to — masked; the full address never leaves the server. */
export interface IrRecipientPreview {
  recipientRole: 'IR_TEAM'
  recipient: string | null
  source: 'settings' | 'server' | 'none'
  emailChannelConfigured: boolean
}
export interface SendToIrPreview {
  email: EmailPreview
  recipient: IrRecipientPreview
}
/** The recipient is always the server's IR Team address — the client only chooses the subject (and which ticket). */
export const irEmailApi = {
  article: (articleId: string) => api<SendToIrPreview & { article: KnowledgeArticle }>(`/api/v1/knowledge/articles/${articleId}`),
  sendArticle: (articleId: string, subject: string | null, idempotencyKey: string) =>
    api<IrEmailOutcome>(`/api/v1/knowledge/articles/${articleId}/send-to-ir`, { method: 'POST', body: { subject, idempotencyKey } }),
  responseGuide: (incidentId: string, responseId?: string | null) =>
    api<SendToIrPreview & { guide: ResponseGuide }>(`/api/v1/incidents/${incidentId}/response-guide`, { query: { responseId: responseId ?? undefined } }),
  sendResponseGuide: (incidentId: string, body: { subject: string | null; responseId?: string | null; idempotencyKey: string }) =>
    api<IrEmailOutcome>(`/api/v1/incidents/${incidentId}/send-response-guide`, { method: 'POST', body }),
}

export const systemApi = {
  health: () => api<{ status: string; service: string; timestamp: string }>('/api/v1/health'),
}

export const dashboardApi = {
  /** `period` (daily/weekly/1m/3m) — the BACKEND computes the window start and limits event counts to it; backlog
   *  figures stay "as of now". `since` (ISO instant) is still accepted as an override for callers that need one. */
  summary: (days = 14, period?: ReportWindowKey, since?: Date) =>
    api<DashboardSummary>('/api/v1/dashboard/summary', { query: { days, period, since: since?.toISOString() } }),
}
// ---------------------------------------------------------------- In-app notifications (header bell)
export interface InAppNotification {
  alertId: string | null
  id: string
  eventType: string
  recipientRole: string
  incidentId: string | null
  responseId: string | null
  title: string
  body: string | null
  /** App-relative path to the existing page (incident / response ticket / approval queue). */
  link: string | null
  createdAt: string
  read: boolean
}
export const notificationsApi = {
  list: (limit = 30) => api<{ items: InAppNotification[]; unread: number }>('/api/v1/notifications', { query: { limit } }),
  markRead: (ids?: string[]) => api<{ marked: number }>('/api/v1/notifications/read', { method: 'POST', body: ids ? { ids } : {} }),
}
export const slaApi = {
  incident: (id: string) => api<IncidentSla>(`/api/v1/incidents/${id}/sla`),
  rehuntHealth: () => api<RehuntHealth>('/api/verifications/rehunt-health'),
}
