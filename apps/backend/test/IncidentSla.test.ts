import { IncidentSlaService } from "../src/application/sla/IncidentSlaService";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { IResponsePlanRepository } from "../src/domain/response/repositories/IResponsePlanRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";

/** SLA clocks come from Policy (priority -> minutes) and start at incident openedAt; read-only. */
const opened = new Date("2026-09-23T10:00:00Z");
const min = (m: number) => new Date(opened.getTime() + m * 60_000);

function service(opts: { sla?: { firstResponseMinutes: number; resolutionMinutes: number } | null; executedAt?: Date | null }) {
  const context = {
    getIncidentContext: async () => ({ incidentId: "i", investigationNumber: 1, title: "t", status: "investigating", priority: "high", alertSeverity: "high" }),
    getEvidence: async () => [],
  } as unknown as IRecommendationContextRepository;
  const evaluate = jest.fn(async () => ({ priority: opts.sla === null ? null : "P1", sla: opts.sla === undefined ? { firstResponseMinutes: 30, resolutionMinutes: 480 } : opts.sla, matchedPolicies: ["POL-003"] }));
  const policy = { evaluate } as unknown as PolicyEvaluator;
  const plans = { findAll: async () => (opts.executedAt ? [{ executedAt: opts.executedAt }] : [{ executedAt: null }]) } as unknown as IResponsePlanRepository;
  return { svc: new IncidentSlaService(context, policy, plans), evaluate };
}

describe("IncidentSlaService", () => {
  it("first response met by the first human start; resolution still on track", async () => {
    const { svc, evaluate } = service({ executedAt: min(20) });
    const r = await svc.forIncident("t", { id: "i", status: "investigating", openedAt: opened, closedAt: null }, min(60));
    expect(r.priority).toBe("P1");
    expect(r.firstResponse).toMatchObject({ targetMinutes: 30, dueAt: min(30).toISOString(), at: min(20).toISOString(), status: "MET" });
    expect(r.resolution).toMatchObject({ targetMinutes: 480, status: "ON_TRACK", at: null });
    expect(evaluate).toHaveBeenCalledWith("t", expect.objectContaining({ severity: "HIGH" }));
    expect(evaluate.mock.calls[0]).not.toContainEqual(expect.objectContaining({ riskScore: expect.anything() }));
  });

  it("nobody started responding past the due time -> first response BREACHED; late resolution -> BREACHED", async () => {
    const { svc } = service({});
    const open = await svc.forIncident("t", { id: "i", status: "investigating", openedAt: opened, closedAt: null }, min(45));
    expect(open.firstResponse?.status).toBe("BREACHED");
    const resolvedLate = await svc.forIncident("t", { id: "i", status: "resolved", openedAt: opened, closedAt: min(600) }, min(700));
    expect(resolvedLate.resolution).toMatchObject({ status: "BREACHED", at: min(600).toISOString() });
  });

  it("merged/dismissed incident -> clocks CANCELLED; escalated incident keeps its resolution clock running", async () => {
    const { svc } = service({});
    expect((await svc.forIncident("t", { id: "i", status: "dismissed", openedAt: opened, closedAt: min(5) }, min(10))).resolution?.status).toBe("CANCELLED");
    expect((await svc.forIncident("t", { id: "i", status: "escalated", openedAt: opened, closedAt: null }, min(500))).resolution?.status).toBe("BREACHED");
  });

  it("Policy gave no priority/SLA -> no clocks (never invented)", async () => {
    const { svc } = service({ sla: null });
    expect(await svc.forIncident("t", { id: "i", status: "open", openedAt: opened, closedAt: null })).toMatchObject({ priority: null, firstResponse: null, resolution: null });
  });
});
