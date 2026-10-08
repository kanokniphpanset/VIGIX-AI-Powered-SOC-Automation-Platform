import { IWorkReadRepository, IncidentWorkFilters } from "./ports/IWorkReadRepository";
import { rankSimilarCases } from "../../domain/incident/similarCases";
import {
  ApprovalScope,
  ApprovalStatusFilter,
  TicketQueue,
  Viewer,
  activeApprovalStep,
  inApprovalQueue,
  inQueue,
  queueCounts,
  sanitizeMetadata,
  ticketStage,
} from "./WorkQueues";

/** How many of the newest tickets / approvals the queues are derived from (same in-memory scope as the Alert Inbox). */
export const WORK_WINDOW = 500;
/** How many of the most recently closed incidents are compared for "similar past cases". */
export const SIMILAR_CANDIDATE_WINDOW = 1000;

/**
 * Read-only queries behind the role workspaces. Every value comes from the stored workflow; queue membership follows
 * backend assignment (Policy executor role, the user who started the response, the active approval step).
 */
export class WorkQueries {
  constructor(private readonly repo: IWorkReadRepository) {}

  async tickets(input: { tenantId: string; viewer: Viewer; queue: TicketQueue; incidentId?: string; limit: number; offset: number }) {
    let rows = await this.repo.tickets(input.tenantId, WORK_WINDOW);
    if (input.incidentId) rows = rows.filter((t) => t.incidentId === input.incidentId);
    const counts = queueCounts(rows, input.viewer);
    const matched = rows.filter((t) => inQueue(input.queue, t, input.viewer));
    return {
      queue: input.queue,
      counts,
      total: matched.length,
      items: matched.slice(input.offset, input.offset + input.limit).map((t) => ({
        ...t,
        stage: ticketStage(t),
        currentApproval: activeApprovalStep(t.approvals),
        assignedToMe: t.assignedTo === input.viewer.id,
      })),
    };
  }

  async approvals(input: { tenantId: string; viewer: Viewer; scope: ApprovalScope; status: ApprovalStatusFilter; limit: number; offset: number }) {
    const rows = await this.repo.approvals(input.tenantId, WORK_WINDOW);
    const matched = rows.filter((r) => inApprovalQueue(r, input.viewer, input.scope, input.status));
    const mineCount = (status: ApprovalStatusFilter) => rows.filter((r) => inApprovalQueue(r, input.viewer, "mine", status)).length;
    return {
      total: matched.length,
      counts: { minePending: mineCount("pending"), mineWaiting: mineCount("waiting"), mineDecided: mineCount("decided") },
      items: matched.slice(input.offset, input.offset + input.limit).map((r) => ({
        ...r,
        /** Only the viewer's own ACTIVE step is decidable; admin never decides business approvals from this queue. */
        canDecide: r.status === "pending" && input.viewer.role !== "admin" && r.role === input.viewer.role,
      })),
    };
  }

  async incidents(input: { tenantId: string; filters: IncidentWorkFilters }) {
    const page = await this.repo.incidents(input.tenantId, input.filters);
    return { total: page.total, items: page.items };
  }

  async incidentAudit(input: { tenantId: string; incidentId: string; limit: number }) {
    const entries = await this.repo.incidentAudit(input.tenantId, input.incidentId, input.limit);
    if (!entries) return null;
    return entries.map((e) => ({ ...e, metadata: sanitizeMetadata(e.metadata) }));
  }

  incidentAiJobs(input: { tenantId: string; incidentId: string }) {
    return this.repo.incidentAiJobs(input.tenantId, input.incidentId);
  }

  iocLibrary(input: { tenantId: string; limit: number }) {
    return this.repo.iocLibrary(input.tenantId, input.limit);
  }

  /**
   * Closed incidents most similar to this one (shared IOC / Wazuh rule / MITRE technique / host — see
   * domain/incident/similarCases), each with why it matched and how it was handled. null = incident not found.
   */
  async similarCases(input: { tenantId: string; incidentId: string; limit: number }) {
    const facts = await this.repo.similarCaseFacts(input.tenantId, input.incidentId, SIMILAR_CANDIDATE_WINDOW);
    if (!facts) return null;
    // The fingerprints are only for scoring; the response carries the matched values in `reasons`.
    return rankSimilarCases(facts.target, facts.candidates, input.limit).map(({ iocs: _i, ruleIds: _r, techniques: _t, hosts: _h, ...c }) => c);
  }
}
