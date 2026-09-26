import { incidentSeverity } from "../../domain/incident/severity";
import { IRecommendationContextRepository } from "../recommendation/ports/IRecommendationContextRepository";
import { IAssetCriticalityProvider } from "../approval/ports/IAssetCriticalityProvider";
import { IResponsePlanRepository } from "../../domain/response/repositories/IResponsePlanRepository";
import { PolicyEvaluator } from "../../infrastructure/policy-engine/PolicyEvaluator";
import { SLAEvaluator, SlaStatus } from "../../infrastructure/policy-engine/SLAEvaluator";

export interface SlaClock {
  targetMinutes: number;
  dueAt: string;
  /** When the clock was satisfied (first response started / incident resolved), or null. */
  at: string | null;
  status: SlaStatus;
}

export interface IncidentSla {
  incidentId: string;
  /** Policy priority (P0..P3) — the SLA tier. Null when Policy assigned no priority. */
  priority: string | null;
  firstResponse: SlaClock | null;
  resolution: SlaClock | null;
  matchedPolicies: string[];
}

/**
 * IncidentSlaService — the incident's SLA, from the Policy Engine (priority → SLA minutes, policy overrides first)
 * with the same incident inputs ApprovalService uses (alert severity, latest risk score, asset criticality of the
 * evidence hosts). Read-only: evaluates Policy but writes no audit row, changes nothing.
 *
 * Clocks start at the incident's openedAt. First response = the earliest human start of a response plan
 * (ResponsePlan.executedAt). Resolution = closedAt of a RESOLVED incident. A merged/dismissed incident's clocks
 * are CANCELLED; an ESCALATED incident keeps running (it is not resolved).
 */
export class IncidentSlaService {
  private readonly sla = new SLAEvaluator();

  constructor(
    private readonly context: IRecommendationContextRepository,
    private readonly policy: PolicyEvaluator,
    private readonly responsePlans: IResponsePlanRepository,
    private readonly assets?: IAssetCriticalityProvider
  ) {}

  async forIncident(
    tenantId: string,
    incident: { id: string; status: string; openedAt: Date; closedAt: Date | null },
    now: Date = new Date()
  ): Promise<IncidentSla> {
    const ctx = await this.context.getIncidentContext(incident.id, tenantId);
    let assetCriticality: string | undefined;
    if (this.assets && ctx) {
      const hosts = (await this.context.getEvidence(incident.id, ctx.investigationNumber)).map((e) => e.host).filter((h): h is string => !!h);
      assetCriticality = this.assets.resolve(hosts).criticality;
    }
    const result = await this.policy.evaluate(tenantId, {
      severity: incidentSeverity(ctx),
      assetCriticality: assetCriticality as never,
    });
    const base = { incidentId: incident.id, priority: result.priority ?? null, matchedPolicies: result.matchedPolicies };
    if (!result.sla) return { ...base, firstResponse: null, resolution: null };

    const plans = await this.responsePlans.findAll(tenantId, 500, 0, incident.id);
    const firstStart = plans.map((p) => p.executedAt).filter((d): d is Date => !!d).sort((a, b) => a.getTime() - b.getTime())[0] ?? null;
    const cancelled = incident.status === "dismissed";
    const resolvedAt = incident.status === "resolved" ? incident.closedAt : null;

    const clock = (minutes: number, doneAt: Date | null): SlaClock => {
      const dueAt = new Date(incident.openedAt.getTime() + minutes * 60_000);
      return {
        targetMinutes: minutes,
        dueAt: dueAt.toISOString(),
        at: doneAt ? doneAt.toISOString() : null,
        status: this.sla.getStatus({ dueAt, startedAt: incident.openedAt, completedAt: doneAt, cancelled }, now),
      };
    };
    return {
      ...base,
      firstResponse: clock(result.sla.firstResponseMinutes, firstStart),
      resolution: clock(result.sla.resolutionMinutes, resolvedAt),
    };
  }
}
