import { ORG_SSH, allowUnreviewed, harness, orgLoader } from "./helpers/subtypeFlowHarness";
import { CreateResponsePlanUseCase } from "../src/application/response/use-cases/CreateResponsePlan.usecase";
import { evaluate, realAlert, resetRefs } from "./helpers/subtypeFixtures";

/**
 * INTEGRATION (no DB, no LLM): capability / authority gates and the "generation never executes" guarantee, on a recorded Wazuh
 * sshd brute-force alert (5712) through the real Evidence Contract v2 extractor and the real knowledge.
 */
beforeEach(() => resetRefs());
const cap = (v: string) => `enforcement_points:\n  - {host: attack-endpoint, service: "SSH (22/TCP)", enforcement_point: "perimeter firewall FW-EDGE-1"}\ncapability:\n  cap.scoped_network_enforcement: ${v}\n`;
const decision = (e: Awaited<ReturnType<typeof evaluate>>, a: string) => (e.audit as any).policyDecisions.find((d: any) => d.action === a) as any;
const ordered = (e: Awaited<ReturnType<typeof evaluate>>) => e.plan!.ordered.map((n) => n.action_id);

describe("capability gate", () => {
  it("capability unknown + platform-neutral: eligible at role level, flagged TOOL_MAPPING_REQUIRED (no invented tool)", async () => {
    const e = await evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH) });
    expect(ordered(e)).toEqual(["ACT-AUTH-SOURCE-RESTRICT"]);
    expect(JSON.stringify(decision(e, "ACT-AUTH-SOURCE-RESTRICT"))).toContain("TOOL_MAPPING_REQUIRED");
  });
  it("capability unknown + STRICT mode: UNSUPPORTED, no executable step", async () => {
    const e = await evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), strict: true });
    expect(decision(e, "ACT-AUTH-SOURCE-RESTRICT").decision).toBe("UNSUPPORTED");
    expect(ordered(e)).toEqual([]);
  });
  it("capability explicitly false (any mode): UNSUPPORTED", async () => {
    const e = await evaluate([realAlert("5712")], { loader: orgLoader(cap("false")) });
    expect(decision(e, "ACT-AUTH-SOURCE-RESTRICT").decision).toBe("UNSUPPORTED");
    expect(ordered(e)).toEqual([]);
  });
  it("capability explicitly true: eligible without the mapping flag", async () => {
    const e = await evaluate([realAlert("5712")], { loader: orgLoader(cap("true")) });
    expect(ordered(e)).toEqual(["ACT-AUTH-SOURCE-RESTRICT"]);
    expect(JSON.stringify(decision(e, "ACT-AUTH-SOURCE-RESTRICT"))).not.toContain("TOOL_MAPPING_REQUIRED");
  });
});

describe("authority gate", () => {
  it("IR execution authority explicitly denied: NEEDS_AUTHORIZATION, nothing executable, the audit says which authority", async () => {
    const e = await evaluate([realAlert("5712")], { loader: orgLoader(`${cap("true")}authority:\n  ir_execute: false\n`) });
    expect(decision(e, "ACT-AUTH-SOURCE-RESTRICT").decision).toBe("NEEDS_AUTHORIZATION");
    expect(ordered(e)).toEqual([]);
    expect(JSON.stringify(decision(e, "ACT-AUTH-SOURCE-RESTRICT"))).toContain("ir_execute");
  });
});

describe("critical workload", () => {
  it("a CRITICAL asset never lowers a gate: the action is still evidence/target/capability gated and stays an approval-required recommendation", async () => {
    const e = await evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), criticality: "CRITICAL" });
    for (const n of e.plan!.ordered) expect(["ELIGIBLE", "NEEDS_AUTHORIZATION"]).toContain(decision(e, n.action_id).decision);
    expect(e.composition!.userText).not.toMatch(/ดำเนินการแล้ว|executed/i);
  });
});

describe("generation never executes", () => {
  it("enforce generation creates only a recommendation: no response ticket / execution port is touched and no step is marked done", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712")], mode: "enforce", loader: orgLoader(ORG_SSH) });
      expect((await h.run()).isSuccess).toBe(true);
      expect(h.created).toHaveLength(1);
      expect(h.created[0].status).toBe("VALIDATED");                                   // awaiting SOC review, not approved/executed
      expect(JSON.stringify(h.created[0].steps)).not.toMatch(/"(status|state)":"(DONE|COMPLETED|EXECUTED)"/);
      expect(h.logged.map((l) => l.action).join(" ")).not.toMatch(/TICKET|EXECUT|CONTAIN_APPLIED/i);
    });
  });
});

describe("Send to IR: the ticket cites the approved recommendation version and is not an execution", () => {
  const mkUseCase = (rec: any) => {
    const created: any[] = []; const audit: any[] = [];
    const uc = new CreateResponsePlanUseCase(
      { findById: async () => rec } as any,
      { findById: async () => ({ id: "action-ACT-AUTH-SOURCE-RESTRICT", code: "ACT-AUTH-SOURCE-RESTRICT", name: "x", impactLevel: "MEDIUM" }) } as any,
      { findById: async () => null } as any,
      { evaluate: async () => ({ policy: { approvalRequired: true, responsibleRole: "IR_TEAM", approvalReason: [], matchedRules: [] }, incidentContext: {}, riskScore: 10 }), open: async () => undefined } as any,
      { findByRecommendation: async () => [], create: async (d: any) => { const p = { id: "plan-1", ...d }; created.push(p); return p; } } as any,
      { record: async (a: any) => { audit.push(a); } } as any,
      { emit: async () => undefined } as any,
      "http://vigix.test",
    );
    return { uc, created, audit };
  };
  it("an ACTION step becomes a PENDING_IR_DECISION ticket for IR_TEAM, citing recommendationNumber and the knowledge-versioned author; nothing is marked executed", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712")], mode: "enforce", loader: orgLoader(ORG_SSH) });
      await h.run();
      const rec = { ...h.created[0], id: "rec-1", tenantId: "tenant-1", incidentId: "incident-1", steps: h.created[0].steps.map((st: any, i: number) => ({ ...st, id: `step-${i}` })) };
      const stepId = rec.steps.find((st: any) => st.actionId)!.id;
      const { uc, created, audit } = mkUseCase(rec);
      const r = await uc.execute({ recommendationId: "rec-1", stepId, tenantId: "tenant-1" });
      expect(r.isSuccess).toBe(true);
      expect(created[0]).toMatchObject({ status: "PENDING_IR_DECISION", assignedRole: "IR_TEAM", approvalStatus: "PENDING", target: "172.19.0.3" });
      expect(created[0].executedAt ?? null).toBeNull();
      const meta = audit.find((a) => a.action === "RESPONSE_PLAN_CREATED").metadata;
      expect(meta.recommendationNumber).toBe(rec.recommendationNumber);
      expect(meta.recommendationCreatedBy).toMatch(/\+subtype\/2\.0\.0\+[0-9a-f]{8}$/);
    });
  });
  it("an investigation-only step cannot become a ticket (nothing for IR to execute)", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712")], mode: "enforce" });             // no enforcement point -> CHECK only
      await h.run();
      const rec = { ...h.created[0], id: "rec-1", tenantId: "tenant-1", steps: h.created[0].steps.map((st: any, i: number) => ({ ...st, id: `step-${i}` })) };
      const r = await mkUseCase(rec).uc.execute({ recommendationId: "rec-1", stepId: "step-0", tenantId: "tenant-1" });
      expect(r.isSuccess).toBe(false);
    });
  });
});
