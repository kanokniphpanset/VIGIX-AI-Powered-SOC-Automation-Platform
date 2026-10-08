import { RecommendationController, presentRecommendation } from "../src/presentation/http/controllers/RecommendationController";
import { ORG_SSH, allowUnreviewed, harness, orgLoader } from "./helpers/subtypeFlowHarness";
import { realAlert, resetRefs } from "./helpers/subtypeFixtures";
import { resolveAll } from "../src/domain/subtype/targets";

/** INTEGRATION (no DB, no LLM): the API presentation of a stored subtype recommendation, the audit endpoint, and the target-merge rule. */
beforeEach(() => resetRefs());
const res = () => { const r: any = { code: 200, body: undefined }; r.status = (c: number) => { r.code = c; return r; }; r.json = (b: unknown) => { r.body = b; return r; }; return r; };
const req = (id = "rec-1") => ({ params: { id }, principal: { tenantId: "tenant-1" } }) as any;

describe("API presentation keeps the user-facing format", () => {
  it("adds recommendationText from the stored steps: heading, numbered bold step, impact/verify, no internal ids / JSON / confidence; legacy recommendations are untouched", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712")], mode: "enforce", loader: orgLoader(ORG_SSH) });
      await h.run();
      const json = presentRecommendation(JSON.parse(JSON.stringify(h.created[0])));
      expect(json.recommendationText).toMatch(/^\*\*คำแนะนำเพื่อยับยั้ง Incident\*\*/);
      expect(json.recommendationText).toMatch(/\n1\. \*\*/);
      expect(json.recommendationText).toContain("*ผลกระทบ:");
      expect(json.recommendationText).toContain("*ตรวจผล:");
      expect(json.recommendationText).not.toMatch(/\b(RB|ACT|PBK|POL|BF)-|subtype|family|confidence|[{]"/i);
      expect(json.recommendationText).not.toMatch(/ดำเนินการตาม\s*RB-/);
    });
    const legacy = { steps: [{ stepType: "ACTION", instructions: [{ order: 1, instruction: "x" }] }] };
    expect(presentRecommendation(legacy)).toBe(legacy);
  });
});

describe("GET /:id/audit", () => {
  const ctl = (audit: unknown, found = true) => new RecommendationController(
    undefined as any, { execute: async () => (found ? { isFailure: false } : { isFailure: true }) } as any, undefined as any, undefined as any, undefined as any, undefined as any,
    { findByRecommendation: async () => audit } as any);
  it("returns the stored audit separately from the recommendation", async () => {
    const r = res(); await ctl({ mode: "ENFORCE", audit: { policyDecisions: [] } }).getAudit(req(), r);
    expect(r.code).toBe(200); expect(r.body.mode).toBe("ENFORCE");
  });
  it("404s when the recommendation or its audit does not exist (legacy recommendation)", async () => {
    const a = res(); await ctl(null).getAudit(req(), a); expect(a.code).toBe(404);
    const b = res(); await ctl({}, false).getAudit(req(), b); expect(b.code).toBe(404);
  });
});

describe("target merge is fail-closed", () => {
  it("identical identities merge their references; a role-less duplicate stays a separate invalid target", async () => {
    const { loader } = await import("./helpers/subtypeFixtures");
    const kb = loader.load();
    const mk = (role: string | undefined, ref: string) => ({ type: "network_source", fields: { address: "203.0.113.7", ...(role ? { source_role: role } : {}) }, evidenceRefs: [ref], origin: "ANALYST" }) as any;
    const ctx = { agentIps: new Set<string>(), agentNames: new Set<string>(), approvedAccess: [], approvedAutomation: [], trustedRmm: [] };
    const good = resolveAll(kb, [mk("attacker_source", "E1")], ctx);
    expect(good[0].validated).toBe(true);
    // identical identity (same role) from two evidence rows -> ONE target, both references, still valid
    const same = resolveAll(kb, [mk("attacker_source", "E1"), mk("attacker_source", "E2")], ctx);
    expect(same).toHaveLength(1);
    expect([...same[0].evidenceRefs].sort()).toEqual(["E1", "E2"]);
    expect(same[0].validated).toBe(true);
    // the same address WITHOUT an evidenced role is a different identity: it stays separate and invalid, and never validates the other one
    const split = resolveAll(kb, [mk(undefined, "E2"), mk("attacker_source", "E1")], ctx);
    expect(split.map((t) => [t.evidenceRefs[0], t.validated]).sort()).toEqual([["E1", true], ["E2", false]]);
  });
});
