import { randomUUID } from "crypto";
import type { Recommendation, RecommendationStepProps } from "../../../domain/recommendation/entities/Recommendation.entity";
import type { Approval } from "../../../domain/approval/entities/Approval.entity";
import type { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import type { Verification } from "../../../domain/verification/entities/Verification.entity";
import type { Action } from "../../../domain/action/entities/Action.entity";
import type { Runbook } from "../../../domain/runbook/entities/Runbook.entity";
import type {
  NotificationEvent,
  ResponseProcess,
  NotificationRole,
  NotificationChannel,
  IncidentSummary,
  TicketSummary,
  ApprovalSummary,
  VerificationSummary,
  ActionRef,
  RunbookRef,
} from "../events/NotificationEvent";

/** N3.5 — backend has no per-event-type channel preference logic yet, so
 * every event honestly requests all three; n8n intersects this with
 * whichever channels actually have a credential configured for the role. */
const DEFAULT_CHANNELS: NotificationChannel[] = ["email", "discord", "telegram"];

/**
 * NotificationEventBuilder — pure mapping functions, no I/O. Every field
 * mapped here is traceable to a real entity getter (see
 * docs/architecture/notification-event-contract.md §3/§5 for the field-by-
 * field source of truth). Callers (the 5 use-cases wired to notifications)
 * are responsible for fetching whatever extra entities the contract says
 * aren't already in scope at that call site — this file never queries
 * anything itself, which is also what keeps it trivially unit-testable.
 */

/** Structural, not the concrete Incident class — some call sites (e.g.
 * RequestApprovalUseCase) only have an IncidentContextRow DTO in scope, not
 * a fully-loaded Incident entity, and the contract says that's fine (no
 * extra fetch needed there). Both shapes satisfy this. */
export interface IncidentLike {
  id: string;
  title: string;
  priority: string;
  investigationNumber: number;
}

function toActionRef(action: Action | null): ActionRef | null {
  return action ? { code: action.code, name: action.name } : null;
}

function toRunbookRef(runbook: Runbook | null): RunbookRef | null {
  return runbook ? { code: runbook.code } : null;
}

function toIncidentSummary(incident: IncidentLike): IncidentSummary {
  return {
    id: incident.id,
    title: incident.title,
    priority: incident.priority,
    investigationNumber: incident.investigationNumber,
  };
}

function toApprovalSummary(approval: Approval): ApprovalSummary {
  return {
    id: approval.id,
    role: approval.approvalRole,
    status: approval.status,
    reason: approval.reason,
    decidedBy: approval.decidedBy,
    comment: approval.comment,
  };
}

function toTicketSummary(response: ResponsePlan, action: Action | null, runbook: Runbook | null): TicketSummary {
  return {
    id: response.id,
    incidentId: response.incidentId,
    status: response.status,
    approvalStatus: response.approvalStatus,
    action: toActionRef(action),
    target: response.target,
    runbook: toRunbookRef(runbook),
    assignedRole: response.assignedRole,
  };
}

function toVerificationSummary(verification: Verification): VerificationSummary {
  return {
    id: verification.id,
    result: verification.result,
    threatContained: verification.threatContained,
    spreadDetected: verification.spreadDetected,
    iocRecurrence: verification.iocRecurrence,
    matchingEvents: verification.matchingEvents,
    notes: verification.notes,
  };
}

function buildLinks(baseUrl: string, opts: { ticketId?: string; approvalIncidentId?: string }): NotificationEvent["links"] {
  const links: NotificationEvent["links"] = {};
  if (opts.ticketId) links.ticket = `${baseUrl}/tickets/${opts.ticketId}`;
  // Approvals are decided on the Approval Queue (the incident page has no approval tab).
  if (opts.approvalIncidentId) links.approval = `${baseUrl}/approvals`;
  return links;
}

export function buildApprovalRequiredEvent(args: {
  tenantId: string;
  baseUrl: string;
  incident: IncidentLike;
  recommendation: Recommendation;
  approval: Approval;
  stepsRequiringApproval: { step: RecommendationStepProps; action: Action | null; runbook: Runbook | null }[];
}): NotificationEvent {
  return {
    eventType: "APPROVAL_REQUIRED",
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    tenantId: args.tenantId,
    recipient: { roles: [args.approval.approvalRole as NotificationRole], channels: DEFAULT_CHANNELS },
    incident: toIncidentSummary(args.incident),
    recommendation: {
      id: args.recommendation.id,
      recommendationNumber: args.recommendation.recommendationNumber,
      summary: args.recommendation.summary,
      stepsRequiringApproval: args.stepsRequiringApproval.map(({ step, action, runbook }) => ({
        title: step.title,
        action: toActionRef(action),
        target: step.target,
        runbook: toRunbookRef(runbook),
      })),
    },
    approval: toApprovalSummary(args.approval),
    links: buildLinks(args.baseUrl, { approvalIncidentId: args.incident.id }),
  };
}

export function buildApprovalDecidedEvent(args: {
  eventType: "APPROVAL_APPROVED" | "APPROVAL_REJECTED";
  tenantId: string;
  baseUrl: string;
  incident: IncidentLike;
  recommendation: Recommendation;
  approval: Approval;
  /** APPROVAL_APPROVED: the approved response process for IR (steps + instructions + verification). */
  responseProcess?: ResponseProcess;
}): NotificationEvent {
  const recipientRole: NotificationRole = args.eventType === "APPROVAL_APPROVED" ? "IR_TEAM" : "SOC";
  return {
    eventType: args.eventType,
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    tenantId: args.tenantId,
    recipient: { roles: [recipientRole], channels: DEFAULT_CHANNELS },
    incident: toIncidentSummary(args.incident),
    recommendation: {
      id: args.recommendation.id,
      recommendationNumber: args.recommendation.recommendationNumber,
      summary: args.recommendation.summary,
      ...(args.responseProcess ? { responseProcess: args.responseProcess } : {}),
    },
    approval: toApprovalSummary(args.approval),
    links: buildLinks(args.baseUrl, { approvalIncidentId: args.incident.id, ticketId: args.approval.responseId ?? undefined }),
  };
}

export function buildResponseAssignedEvent(args: {
  tenantId: string;
  baseUrl: string;
  incident: IncidentLike;
  response: ResponsePlan;
  recommendation?: Recommendation;
  action: Action | null;
  runbook: Runbook | null;
}): NotificationEvent {
  return {
    eventType: "RESPONSE_ASSIGNED",
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    tenantId: args.tenantId,
    recipient: { roles: [args.response.assignedRole as NotificationRole], channels: DEFAULT_CHANNELS },
    incident: toIncidentSummary(args.incident),
    ticket: toTicketSummary(args.response, args.action, args.runbook),
    ...(args.recommendation ? { recommendation: {
      id: args.recommendation.id,
      recommendationNumber: args.recommendation.recommendationNumber,
      investigationNumber: args.recommendation.investigationNumber,
      recommendationStepId: args.response.recommendationStepId,
      summary: args.recommendation.summary,
      responseProcess: {
        severity: args.incident.priority,
        evidence: args.recommendation.steps.filter(s => s.id === args.response.recommendationStepId).flatMap(s => s.evidence),
        // Include only the versioned step assigned to this ticket, never unrelated work.
        steps: args.recommendation.steps.filter(s => s.id === args.response.recommendationStepId).map(s => ({
          stepOrder: s.stepOrder, title: s.title, objective: s.objective, target: s.target,
          reason: s.reason, instructions: s.instructions, expectedResult: s.expectedResult,
          verificationCriteria: s.verificationCriteria,
        })),
      },
    } } : {}),
    links: { ...buildLinks(args.baseUrl, { ticketId: args.response.id }), incident: `${args.baseUrl}/incidents/${args.incident.id}` },
  };
}

export function buildResponseCompletedEvent(args: {
  tenantId: string;
  baseUrl: string;
  incident: IncidentLike;
  response: ResponsePlan;
  action: Action | null;
  runbook: Runbook | null;
}): NotificationEvent {
  return {
    eventType: "RESPONSE_COMPLETED",
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    tenantId: args.tenantId,
    recipient: { roles: ["SOC"], channels: DEFAULT_CHANNELS },
    incident: toIncidentSummary(args.incident),
    ticket: toTicketSummary(args.response, args.action, args.runbook),
    links: buildLinks(args.baseUrl, { ticketId: args.response.id }),
  };
}

export function buildVerificationNotResolvedEvent(args: {
  tenantId: string;
  baseUrl: string;
  incident: IncidentLike;
  verification: Verification;
}): NotificationEvent {
  return {
    eventType: "VERIFICATION_NOT_RESOLVED",
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    tenantId: args.tenantId,
    recipient: { roles: ["SOC", "IR_TEAM"], channels: DEFAULT_CHANNELS },
    incident: toIncidentSummary(args.incident),
    verification: toVerificationSummary(args.verification),
    links: {},
  };
}

export function buildInvestigationReopenedEvent(args: {
  tenantId: string;
  baseUrl: string;
  incident: IncidentLike;
  verification: Verification;
}): NotificationEvent {
  return {
    eventType: "INVESTIGATION_REOPENED",
    eventId: randomUUID(),
    timestamp: new Date().toISOString(),
    tenantId: args.tenantId,
    recipient: { roles: ["SOC", "IR_TEAM"], channels: DEFAULT_CHANNELS },
    incident: toIncidentSummary(args.incident),
    verification: toVerificationSummary(args.verification),
    links: {},
  };
}
