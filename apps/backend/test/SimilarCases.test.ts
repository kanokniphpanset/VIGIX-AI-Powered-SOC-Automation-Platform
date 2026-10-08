import { CaseFingerprint, iocKey, rankSimilarCases, similarity } from "../src/domain/incident/similarCases";
import { WorkQueries } from "../src/application/work/WorkQueries.usecases";
import { ClosedCaseRow, IWorkReadRepository } from "../src/application/work/ports/IWorkReadRepository";

const fp = (p: Partial<CaseFingerprint> = {}): CaseFingerprint => ({ iocs: [], ruleIds: [], techniques: [], hosts: [], ...p });

describe("similarity", () => {
  const target = fp({ iocs: [iocKey("IPV4", "185.1.1.1")], ruleIds: ["5712"], techniques: ["T1110"], hosts: ["web-01"] });

  it("scores shared IOC / rule / technique / host by weight and lists the shared values", () => {
    const r = similarity(target, fp({ iocs: [iocKey("ipv4", " 185.1.1.1 ")], ruleIds: ["5712"], techniques: ["t1110"], hosts: ["WEB-01"] }));
    expect(r.score).toBe(3 + 2 + 2 + 1);
    expect(r.reasons).toEqual([
      { kind: "SAME_IOC", values: ["IPV4:185.1.1.1"] },
      { kind: "SAME_RULE", values: ["5712"] },
      { kind: "SAME_TECHNIQUE", values: ["T1110"] },
      { kind: "SAME_HOST", values: ["web-01"] },
    ]);
  });

  it("never calls a case similar on a shared host alone", () => {
    expect(similarity(target, fp({ hosts: ["web-01"] }))).toEqual({ score: 0, reasons: [] });
  });

  it("caps each kind so many shared IOCs cannot drown the other signals", () => {
    const many = ["a", "b", "c", "d", "e"].map((v) => iocKey("DOMAIN", `${v}.evil`));
    expect(similarity(fp({ iocs: many }), fp({ iocs: many })).score).toBe(3 * 3);
  });

  it("ignores loopback / unspecified addresses as IOCs", () => {
    const lo = [iocKey("IPV4", "127.0.0.1"), iocKey("IPV6", "::1"), iocKey("IPV4", "0.0.0.0")];
    expect(similarity(fp({ iocs: lo, ruleIds: ["5712"] }), fp({ iocs: lo, ruleIds: ["5712"] })).reasons).toEqual([{ kind: "SAME_RULE", values: ["5712"] }]);
    expect(similarity(fp({ iocs: lo }), fp({ iocs: lo })).score).toBe(0);
  });

  it("returns nothing for unrelated cases", () => {
    expect(similarity(target, fp({ ruleIds: ["999"], techniques: ["T1059"] })).score).toBe(0);
  });
});

describe("rankSimilarCases", () => {
  const target = { id: "t", ...fp({ ruleIds: ["5712"], techniques: ["T1110"], iocs: [iocKey("IPV4", "1.2.3.4")] }) };
  const c = (id: string, closedAt: string, p: Partial<CaseFingerprint>) => ({ id, closedAt, ...fp(p) });

  it("orders best first, breaks ties by most recently closed, drops non-matches and the target itself", () => {
    const ranked = rankSimilarCases(target, [
      c("rule-old", "2026-09-01T00:00:00Z", { ruleIds: ["5712"] }),
      c("rule-new", "2026-09-20T00:00:00Z", { ruleIds: ["5712"] }),
      c("ioc+tech", "2026-08-01T00:00:00Z", { iocs: [iocKey("IPV4", "1.2.3.4")], techniques: ["T1110"] }),
      c("none", "2026-09-30T00:00:00Z", { ruleIds: ["1"] }),
      c("t", "2026-09-30T00:00:00Z", { ruleIds: ["5712"] }),
    ]);
    expect(ranked.map((r) => [r.id, r.score])).toEqual([["ioc+tech", 5], ["rule-new", 2], ["rule-old", 2]]);
  });

  it("honours the limit", () => {
    const many = Array.from({ length: 8 }, (_, i) => c(`c${i}`, `2026-09-0${i + 1}T00:00:00Z`, { ruleIds: ["5712"] }));
    expect(rankSimilarCases(target, many, 3)).toHaveLength(3);
  });
});

describe("WorkQueries.similarCases", () => {
  const closed = (p: Partial<ClosedCaseRow>): ClosedCaseRow => ({
    id: "x", title: "SSH brute force", status: "resolved", priority: "medium", openedAt: "2026-09-30T03:00:00.000Z", closedAt: "2026-09-30T04:00:00.000Z",
    investigationNumber: 1, lastVerification: "RESOLVED", actions: [{ code: "BLOCK_IP", name: "Block IP", target: "185.1.1.1", status: "COMPLETED" }], closeNote: null,
    ...fp(), ...p,
  });

  it("returns ranked cases with reasons and outcome, without the raw fingerprints", async () => {
    const repo = {
      similarCaseFacts: async () => ({
        target: { id: "t", ...fp({ ruleIds: ["5712"] }) },
        candidates: [closed({ id: "a", ruleIds: ["5712"], hosts: ["web-01"] }), closed({ id: "b", ruleIds: ["1"] })],
      }),
    } as unknown as IWorkReadRepository;
    const items = await new WorkQueries(repo).similarCases({ tenantId: "ten", incidentId: "t", limit: 5 });
    expect(items).toHaveLength(1);
    expect(items![0]).toMatchObject({ id: "a", score: 2, reasons: [{ kind: "SAME_RULE", values: ["5712"] }], lastVerification: "RESOLVED" });
    expect(items![0]).not.toHaveProperty("ruleIds");
    expect(items![0]).not.toHaveProperty("iocs");
  });

  it("is null when the incident is not in the tenant", async () => {
    const repo = { similarCaseFacts: async () => null } as unknown as IWorkReadRepository;
    expect(await new WorkQueries(repo).similarCases({ tenantId: "ten", incidentId: "nope", limit: 5 })).toBeNull();
  });
});
