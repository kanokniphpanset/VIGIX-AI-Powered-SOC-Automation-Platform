/**
 * NotificationEvent — the wire shape defined in
 * docs/architecture/notification-event-contract.md (Phase N1). Backend is
 * the only thing that ever constructs one of these; n8n only reads it.
 *
 * Deliberately NOT persisted anywhere (no notification table exists, and
 * none is added here) — eventId exists so a future retry can be
 * deduplicated by the receiver, not so this event can be looked up later.
 */

export type NotificationEventType =
  | "APPROVAL_REQUIRED"
  | "APPROVAL_APPROVED"
  | "APPROVAL_REJECTED"
  | "RESPONSE_ASSIGNED"
  | "RESPONSE_COMPLETED"
  | "VERIFICATION_NOT_RESOLVED"
  | "INVESTIGATION_REOPENED";

/** ADMIN = system administration contact (Settings recipient); it never approves or executes. */
export type NotificationRole = "SOC" | "IR_TEAM" | "ADMIN";

/** Delivery mechanism only — never an authorization concept. Backend
 * always sends all three today (N3.5); n8n further intersects this with
 * whichever channels actually have a credential configured for the role,
 * so a channel with no webhook/token/chat-id configured is never attempted
 * regardless of what's listed here. */
export type NotificationChannel = "email" | "discord" | "telegram";

export interface ActionRef {
  code: string;
  name: string;
}

export interface RunbookRef {
  code: string;
}

export interface IncidentSummary {
  id: string;
  title: string;
  /** Incident severity (low | medium | high | critical) — the Policy classification input. No risk score. */
  priority: string;
  investigationNumber: number;
}

export interface TicketSummary {
  id: string;
  incidentId: string;
  status: string;
  approvalStatus: string;
  action: ActionRef | null;
  target: string | null;
  runbook: RunbookRef | null;
  assignedRole: string;
}

export interface RecommendationStepRef {
  title: string;
  action: ActionRef | null;
  target: string | null;
  runbook: RunbookRef | null;
}

export interface ResponseProcessStep {
  stepOrder: number;
  title: string;
  objective: string | null;
  target: string | null;
  reason: string;
  instructions: { order: number; instruction: string; target: string | null; expectedResult: string | null; impact?: string | null; verify?: string | null; manualOwner?: string | null; method?: string | null; methodKind?: "method" | "detail"; preconditions?: string[]; rollback?: string | null; note?: string | null }[];
  expectedResult: string | null;
  verificationCriteria: string | null;
}

/** The full approved response process IR executes (APPROVAL_APPROVED): what to do, where, and how to verify it. */
export interface ResponseProcess {
  severity: string;
  evidence: string[];
  steps: ResponseProcessStep[];
}

export interface RecommendationSummary {
  id: string;
  recommendationNumber: number;
  summary: string;
  /** Only populated when the caller actually derives it (APPROVAL_REQUIRED);
   * omitted rather than sent as a misleading empty array otherwise. */
  stepsRequiringApproval?: RecommendationStepRef[];
  /** Only on APPROVAL_APPROVED: the approved steps with their operational instructions. */
  responseProcess?: ResponseProcess;
}

export interface ApprovalSummary {
  id: string;
  role: string;
  status: string;
  reason: string;
  decidedBy: string | null;
  comment: string | null;
}

export interface VerificationSummary {
  id: string;
  result: "RESOLVED" | "NOT_RESOLVED";
  threatContained: boolean;
  spreadDetected: boolean;
  iocRecurrence: boolean;
  matchingEvents: number | null;
  notes: string | null;
}

export interface NotificationEvent {
  eventType: NotificationEventType;
  eventId: string;
  timestamp: string;
  tenantId: string;
  recipient: { roles: NotificationRole[]; channels: NotificationChannel[] };
  incident: IncidentSummary;
  ticket?: TicketSummary;
  recommendation?: RecommendationSummary;
  approval?: ApprovalSummary;
  verification?: VerificationSummary;
  links: { ticket?: string; approval?: string };
}
