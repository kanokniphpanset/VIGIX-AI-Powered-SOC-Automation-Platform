// Work queues for the role workspaces (SOC / IR_TEAM / admin). Pure derivation over stored backend state:
// response-ticket status, its IR decision, its re-hunt verification and the incident status. Nothing here writes,
// assigns, approves or executes — the queues only answer "whose turn is it" from what Policy + the workflow recorded.

export interface ApprovalStepRow {
  id: string;
  role: string | null;
  /** pending (awaiting the IR decision) | approved | rejected — waiting / cancelled / more_evidence_requested: history only */
  status: string;
  stepOrder: number;
  decidedBy: string | null;
  decidedAt: string | null;
  createdAt: string;
}

export interface TicketRow {
  id: string;
  incidentId: string;
  incidentTitle: string;
  incidentStatus: string;
  incidentPriority: string;
  investigationNumber: number;
  recommendationId: string;
  recommendationStepId: string | null;
  stepTitle: string | null;
  stepOrder: number | null;
  actionCode: string | null;
  actionName: string | null;
  target: string | null;
  status: string;
  approvalStatus: string;
  /** Executor role Policy assigned the ticket to. */
  assignedRole: string;
  /** Backend assignment: the user who started the response (null until someone starts it). */
  assignedTo: string | null;
  assignedToEmail: string | null;
  executedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  updatedAt: string;
  approvals: ApprovalStepRow[];
  verification: { id: string; result: string; spreadDetected: boolean; verifiedAt: string } | null;
}

export type TicketStage =
  | "AWAITING_IR_DECISION"
  | "READY_FOR_EXECUTION"
  | "IN_PROGRESS"
  | "AWAITING_REHUNT"
  | "COMPLETED"
  | "NOT_RESOLVED"
  | "ESCALATED"
  | "FAILED"
  | "REJECTED"
  | "CLOSED";

export function ticketStage(t: Pick<TicketRow, "status" | "verification" | "incidentStatus">): TicketStage {
  switch (t.status) {
    case "PENDING_IR_DECISION":
    case "PENDING_APPROVAL":
      return "AWAITING_IR_DECISION";
    case "APPROVED":
    case "READY_FOR_EXECUTION":
      return "READY_FOR_EXECUTION";
    case "IN_PROGRESS":
      return "IN_PROGRESS";
    case "FAILED":
      return "FAILED";
    case "REJECTED":
    case "MORE_EVIDENCE_REQUESTED":
      return "REJECTED";
    case "COMPLETED":
      if (!t.verification) return "AWAITING_REHUNT";
      if (t.verification.result === "RESOLVED") return "COMPLETED";
      return t.incidentStatus === "escalated" ? "ESCALATED" : "NOT_RESOLVED";
    default:
      return "CLOSED";
  }
}

/** The open IR decision (status "pending"), else null. */
export function activeApprovalStep(approvals: ApprovalStepRow[]): ApprovalStepRow | null {
  return [...approvals].sort((a, b) => a.stepOrder - b.stepOrder).find((a) => a.status === "pending") ?? null;
}

export const TICKET_QUEUES = [
  "my-work",
  "awaiting-decision",
  "ready",
  "in-progress",
  "awaiting-rehunt",
  "completed",
  "rejected",
  "failed",
  "escalated",
  "all",
] as const;
export type TicketQueue = (typeof TICKET_QUEUES)[number];

export interface Viewer {
  id: string;
  role: string;
}

const EXECUTION_STAGES: TicketStage[] = ["READY_FOR_EXECUTION", "IN_PROGRESS", "AWAITING_REHUNT"];

/**
 * Queue membership from backend state only (never from who received an email):
 *   my-work           IR work that is mine: tickets waiting for the IR decision (when I am IR_TEAM), tickets I started
 *                     (assignedTo = me) that are not finished, and READY tickets nobody started yet.
 *   awaiting-decision tickets waiting for IR APPROVE / REJECT.
 * admin is a system role: it never decides or executes (it must not stand in for IR).
 */
export function inQueue(queue: TicketQueue, t: TicketRow, viewer: Viewer): boolean {
  const stage = ticketStage(t);
  switch (queue) {
    case "my-work":
      return (
        (viewer.role === "IR_TEAM" && stage === "AWAITING_IR_DECISION") ||
        (t.assignedTo === viewer.id && EXECUTION_STAGES.includes(stage)) ||
        (t.assignedTo === null && stage === "READY_FOR_EXECUTION" && t.assignedRole === viewer.role)
      );
    case "awaiting-decision":
      return stage === "AWAITING_IR_DECISION";
    case "rejected":
      return stage === "REJECTED";
    case "ready":
      return stage === "READY_FOR_EXECUTION";
    case "in-progress":
      return stage === "IN_PROGRESS";
    case "awaiting-rehunt":
      return stage === "AWAITING_REHUNT";
    case "completed":
      return stage === "COMPLETED";
    case "failed":
      return stage === "FAILED";
    case "escalated":
      return stage === "ESCALATED" || (t.incidentStatus === "escalated" && stage !== "COMPLETED");
    case "all":
      return true;
  }
}

export function queueCounts(rows: TicketRow[], viewer: Viewer): Record<TicketQueue, number> {
  return Object.fromEntries(TICKET_QUEUES.map((q) => [q, rows.filter((t) => inQueue(q, t, viewer)).length])) as Record<TicketQueue, number>;
}

// ---------------------------------------------------------------- Approval queue

export interface ApprovalQueueRow {
  id: string;
  role: string | null;
  status: string;
  stepOrder: number;
  reason: string | null;
  comment: string | null;
  decidedBy: string | null;
  decidedByEmail: string | null;
  decidedAt: string | null;
  createdAt: string;
  responseId: string | null;
  recommendationId: string | null;
  incidentId: string;
  incidentTitle: string;
  incidentPriority: string;
  incidentStatus: string;
  target: string | null;
  planStatus: string | null;
  stepTitle: string | null;
  actionName: string | null;
  chain: ApprovalStepRow[];
}

export type ApprovalScope = "mine" | "all";
export type ApprovalStatusFilter = "pending" | "waiting" | "decided" | "all";

const DECIDED = new Set(["approved", "rejected", "more_evidence_requested", "cancelled"]);

/** scope "mine": only decisions assigned to the viewer's role (IR_TEAM). status "pending" = the open IR decisions. */
export function inApprovalQueue(row: ApprovalQueueRow, viewer: Viewer, scope: ApprovalScope, status: ApprovalStatusFilter): boolean {
  if (scope === "mine" && (viewer.role === "admin" || row.role !== viewer.role)) return false;
  if (status === "pending") return row.status === "pending";
  if (status === "waiting") return row.status === "waiting";
  if (status === "decided") return DECIDED.has(row.status);
  return true;
}

// ---------------------------------------------------------------- Audit sanitisation

const SECRET_KEY = /(password|secret|token|api[_-]?key|authorization|smtp)/i;

/** Audit metadata is shown to analysts; drop anything that looks like a credential (defence in depth). */
export function sanitizeMetadata(value: unknown, depth = 0): unknown {
  if (depth > 6 || value == null) return value;
  if (Array.isArray(value)) return value.map((v) => sanitizeMetadata(v, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([k]) => !SECRET_KEY.test(k))
        .map(([k, v]) => [k, sanitizeMetadata(v, depth + 1)])
    );
  }
  return value;
}
