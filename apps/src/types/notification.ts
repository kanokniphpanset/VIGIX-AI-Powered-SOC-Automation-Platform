import type { RoleName } from './common'

export type NotificationEventKey =
  | 'INCIDENT_CREATED'
  | 'INVESTIGATION_REQUIRED'
  | 'IR_ASSIGNMENT'
  | 'APPROVAL_REQUIRED'
  | 'RESPONSE_APPROVED'
  | 'VERIFICATION_REQUIRED'
  | 'RE_INVESTIGATION_REQUIRED'
  | 'INCIDENT_CLOSED'

export interface NotificationChannelConfig {
  channel: 'Email' | 'Slack' | 'Microsoft Teams'
  enabled: boolean
  /** Display identifier — a Slack channel name or Teams connection status. Not meaningful for Email, which is configured per-role via emailsByRole instead. */
  target: string
  /** Only meaningful when channel === 'Email'. Every email address that should receive notifications for a given role — e.g. emailsByRole['IR Team'] is who gets the Response Ticket emails. A role with no entry (or an empty array) has no Email recipients configured yet. */
  emailsByRole?: Partial<Record<RoleName, string[]>>
}

/** The editable message sent for an event. subject/body may contain {{variable}} placeholders — see TEMPLATE_VARIABLES in notificationService for the full list. */
export interface NotificationTemplateContent {
  subject: string
  body: string
}

export interface NotificationEventConfig {
  event: NotificationEventKey
  label: string
  description: string
  recipients: RoleName[]
  channels: ('Email' | 'Slack' | 'Microsoft Teams')[]
  deepLinkRoute: string
  template: NotificationTemplateContent
}

export interface NotificationTemplatePreview {
  incidentId: string
  incidentType: string
  severity: string
  riskScore: number
  affectedAsset: string
  detectionSummary: string
  actionRequired: string
  responsibleRole: string
  timestamp: string
  openInVigixUrl: string
}
