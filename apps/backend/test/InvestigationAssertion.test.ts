import { CreateEvidenceUseCase } from "../src/application/investigation/use-cases/CreateEvidence.usecase";
import { subtypeFactsSchema } from "../src/application/investigation/dto/InvestigationDtos";

/** UNIT: the analyst-assertion route accepts only well-formed, secret-free, non-empty facts from an authenticated author. */
const inv = { id: "inv-1", incidentId: "inc-1", status: "ACTIVE" };
function useCase() {
  const created: any[] = [];
  const investigations = { findById: async () => inv, createEvidence: async (d: any) => { created.push(d); return { id: "ev-1", ...d }; }, findIocsByIds: async () => [] } as any;
  const uc = new CreateEvidenceUseCase(investigations, {} as any, { record: async () => undefined } as any);
  return { uc, created };
}
const body = (subtypeFacts: unknown) => ({ type: "ANALYST_ASSERTION" as const, source: "ANALYST" as const, title: "SOC assertion", structuredData: { subtypeFacts } });

describe("ANALYST_ASSERTION evidence", () => {
  it("accepts a valid assertion and stamps origin MANUAL with the authenticated author", async () => {
    const { uc, created } = useCase();
    const r = await uc.execute({ tenantId: "t", investigationId: "inv-1", createdBy: "user-7", body: body({ evidence: [{ id: "c2_web_channel_correlated", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] }] }) as any });
    expect(r.isSuccess).toBe(true);
    expect(created[0]).toMatchObject({ origin: "MANUAL", createdBy: "user-7", type: "ANALYST_ASSERTION" });
  });
  it.each([
    ["an empty assertion", {}],
    ["a bad status", { evidence: [{ id: "x_evidence", status: "MAYBE" }] }],
    ["an unknown key (strict)", { evidence: [], confidence: 0.99 }],
    ["a raw token in a target", { targets: [{ type: "session", fields: { session_ids_or_family: "Bearer abcdefghijklmnop" } }] }],
    ["a private key", { targets: [{ type: "secret_credential", fields: { note: "-----BEGIN RSA PRIVATE KEY-----" } }] }],
  ])("rejects %s", async (_n, facts) => {
    const { uc, created } = useCase();
    const r = await uc.execute({ tenantId: "t", investigationId: "inv-1", createdBy: "user-7", body: body(facts) as any });
    expect(r.isFailure).toBe(true);
    expect((r as any).error.code).toBe("INVALID_ASSERTION");
    expect(created).toHaveLength(0);
  });
  it("schema: confidence is not a field", () => {
    expect(subtypeFactsSchema.safeParse({ evidence: [{ id: "abc_def", status: "PRESENT", confidence: 0.9 }] }).success).toBe(false);
  });
});
