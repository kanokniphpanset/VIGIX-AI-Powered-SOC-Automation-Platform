import { IncidentSlaService } from "../src/application/sla/IncidentSlaService";
import { IRecommendationContextRepository } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { IResponsePlanRepository } from "../src/domain/response/repositories/IResponsePlanRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";

/** SLA clocks come from Policy (priority -> minutes) and start at incident openedAt; read-only. */
const opened = new Date("2026-09-23T10:00:00Z");
const min = (m: number) => new Date(opened.getTime() + m * 60_000);

function service(opts: { sla?: { firstResponseMinutes: number; resolutionMinutes: number } | null; executedAt?: Date | null; priority?: string }) {
  const context = {
    getIncidentContext: async () => ({ incidentId: "i", investigationNumber: 1, title: "t", status: "investigating", priority: "high", alertSeverity: "high" }),
    getEvidence: async () => [],
  } as unknown as IRecommendationContextRepository;
  const evaluate = jest.fn(async () => ({ priority: opts.sla === null ? null : (opts.priority ?? "P1"), sla: opts.sla === undefined ? { firstResponseMinutes: 30, resolutionMinutes: 480 } : opts.sla, matchedPolicies: ["POL-003"] }));
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

  it("each clock carries the Policy target wording; business days are counted as calendar days (5 = 1 week)", async () => {
    const p1 = await service({}).svc.forIncident("t", { id: "i", status: "open", openedAt: opened, closedAt: null }, min(1));
    expect(p1.firstResponse?.target).toEqual({ value: 30, unit: "minute" });
    expect(p1.resolution?.target).toEqual({ value: 8, unit: "hour" });
    const p2 = await service({ priority: "P2", sla: { firstResponseMinutes: 240, resolutionMinutes: 3 * 1440 } }).svc.forIncident("t", { id: "i", status: "open", openedAt: opened, closedAt: null }, min(1));
    expect(p2.firstResponse).toMatchObject({ target: { value: 4, unit: "hour" }, dueAt: min(240).toISOString() });
    expect(p2.resolution).toMatchObject({ target: { value: 3, unit: "business_day" }, dueAt: min(3 * 1440).toISOString() });
    const p3 = await service({ priority: "P3", sla: { firstResponseMinutes: 1440, resolutionMinutes: 7 * 1440 } }).svc.forIncident("t", { id: "i", status: "open", openedAt: opened, closedAt: null }, min(1));
    expect(p3.firstResponse).toMatchObject({ target: { value: 1, unit: "business_day" }, dueAt: min(1440).toISOString() });
    expect(p3.resolution).toMatchObject({ target: { value: 5, unit: "business_day" }, dueAt: min(7 * 1440).toISOString() });
    // A policy override with other minutes has no baseline wording: the UI shows the plain duration instead.
    const custom = await service({ priority: "P2", sla: { firstResponseMinutes: 90, resolutionMinutes: 3 * 1440 } }).svc.forIncident("t", { id: "i", status: "open", openedAt: opened, closedAt: null }, min(1));
    expect(custom.firstResponse).toMatchObject({ targetMinutes: 90, target: null });
  });

  it("Policy gave no priority/SLA -> no clocks (never invented)", async () => {
    const { svc } = service({ sla: null });
    expect(await svc.forIncident("t", { id: "i", status: "open", openedAt: opened, closedAt: null })).toMatchObject({ priority: null, firstResponse: null, resolution: null });
  });
});
