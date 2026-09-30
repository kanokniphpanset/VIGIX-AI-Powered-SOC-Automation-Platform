import { RejectRecommendationUseCase } from "../src/application/recommendation/use-cases/RejectRecommendation.usecase";

/** SOC Validation REJECT -> Close Incident (main flow). */
function setup(opts: { recStatus?: string; incidentStatus?: string; tickets?: Array<{ status: string }> } = {}) {
  const recommendation = { id: "rec-1", incidentId: "inc-1", recommendationNumber: 1, status: opts.recStatus ?? "VALIDATED" };
  const recommendations = {
    findById: jest.fn().mockResolvedValue(recommendation),
    updateStatus: jest.fn().mockImplementation(async (_id: string, _t: string, status: string) => ({ ...recommendation, status })),
  };
  const incidents = {
    findById: jest.fn().mockResolvedValue({ id: "inc-1", status: opts.incidentStatus ?? "investigating" }),
    updateStatus: jest.fn().mockResolvedValue(undefined),
  };
  const responsePlans = { findByRecommendation: jest.fn().mockResolvedValue(opts.tickets ?? []) };
  const audit: Array<{ action: string; metadata: Record<string, unknown> }> = [];
  const auditLogger = { record: jest.fn().mockImplementation(async (e: (typeof audit)[number]) => void audit.push(e)) };
  const useCase = new RejectRecommendationUseCase(recommendations as any, responsePlans as any, incidents as any, auditLogger as any);
  return { useCase, recommendations, incidents, audit };
}
const run = (w: ReturnType<typeof setup>, note: string | null = "benign admin activity, confirmed with owner") =>
  w.useCase.execute({ tenantId: "t1", recommendationId: "rec-1", actor: "soc-1", note });

describe("RejectRecommendationUseCase", () => {
  it("rejects the recommendation and closes the incident (dismissed), audited", async () => {
    const w = setup();
    const r = await run(w);
    expect(r.value).toMatchObject({ status: "REJECTED" });
    expect(w.incidents.updateStatus).toHaveBeenCalledWith("inc-1", "t1", "dismissed");
    expect(w.audit.map((a) => a.action)).toEqual(["RECOMMENDATION_REJECTED_BY_SOC", "INCIDENT_CLOSED"]);
    expect(w.audit[1].metadata).toMatchObject({ to: "dismissed", reason: "SOC_REJECTED_RECOMMENDATION" });
  });

  it("requires a note", async () => {
    const w = setup();
    expect((await run(w, "  ")).error).toBe("NOTE_REQUIRED");
    expect(w.incidents.updateStatus).not.toHaveBeenCalled();
  });

  it("is refused once a live Response Ticket exists (IR owns it), for a superseded recommendation, and on a closed incident", async () => {
    expect((await run(setup({ tickets: [{ status: "PENDING_IR_DECISION" }] }))).error).toBe("ALREADY_SENT_TO_IR");
    expect((await run(setup({ recStatus: "SUPERSEDED" }))).error).toBe("RECOMMENDATION_NOT_OPEN");
    expect((await run(setup({ incidentStatus: "resolved" }))).error).toBe("INCIDENT_CLOSED");
    expect((await run(setup({ tickets: [{ status: "FAILED" }] }))).isSuccess).toBe(true);
  });
});
