import { ORG_SSH, allowUnreviewed, harness, orgLoader } from "./helpers/subtypeFlowHarness";
import { realAlert, resetRefs } from "./helpers/subtypeFixtures";

/**
 * INTEGRATION (no DB, no network, no LLM): the REAL GenerateRecommendationUseCase / RecommendationContextBuilder / legacy
 * RecommendationValidator + the subtype service, over in-memory repositories. Evidence = a RECORDED Wazuh alert (rule 5712, real
 * sshd brute force) through the real Evidence Contract v2 extractor. The "AI" is the deterministic FakeRecommendationAgent or a
 * scripted narrator - this is NOT an actual-LLM test.
 */
beforeEach(() => resetRefs());
const rows = () => [realAlert("5712")];

describe("enforce: the recommendation is built from the approved subtype plan", () => {
  it("persists a VALIDATED recommendation whose ACTION step is a real catalog action + runbook, with contract-format instructions", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH) });
      const r = await h.run();
      expect(r.isSuccess).toBe(true);
      const rec = h.created[0];
      expect(rec.status).toBe("VALIDATED");
      expect(rec.createdBy).toMatch(/\+subtype\/2\.0\.0\+[0-9a-f]{8}$/);                  // knowledge version stamped on the recommendation
      expect(rec.steps.filter((s) => s.stepType === "ACTION").map((s) => [s.stepType, s.actionId, s.target])).toEqual([["ACTION", "action-ACT-AUTH-SOURCE-RESTRICT", "172.19.0.3"]]);
      expect(rec.steps.filter((s) => s.stepType !== "ACTION").every((s) => s.actionId === null)).toBe(true);   // information-needed / notes are never ticketable
      expect(rec.steps[0].sourceRunbookId).toBe("runbook-RB-AUTH-SOURCE-RESTRICT");
      const ins = rec.steps[0].instructions;
      expect(ins[0].title).toContain("172.19.0.3");
      expect(ins.some((i) => i.impact)).toBe(true);
      expect(ins.some((i) => i.verify)).toBe(true);
      expect(JSON.stringify(rec.steps)).not.toMatch(/\{\{|PBK-|POL-|BF-GUESS/);
      expect(rec.summary).not.toMatch(/ACT-|RB-|BF-|subtype/i);
      expect(h.agent.generate).not.toHaveBeenCalled();                                     // no AI needed (and nothing executed) for generation
      expect(h.logged.find((l) => l.action === "RECOMMENDATION_GENERATED")?.metadata).toMatchObject({ path: "SUBTYPE_KNOWLEDGE" });
    });
  });

  it("stores the internal audit SEPARATELY (subtype, evidence refs, policy decisions, targets, versions, ordering, authority/capability) - not in the user-facing steps", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH) });
      await h.run();
      expect(h.audits).toHaveLength(1);
      const a = h.audits[0];
      expect(a).toMatchObject({ mode: "ENFORCE", recommendationId: "rec-1", knowledgeStatus: "VALID" });
      const audit = a.audit as Record<string, any>;
      expect(audit.selection.subtypes).toEqual(["BF-GUESS"]);
      expect(audit.evidence[0]).toMatchObject({ id: "bf_attempts_correlated", status: "PRESENT", refs: ["E1"] });
      expect(audit.policyDecisions[0]).toMatchObject({ action: "ACT-AUTH-SOURCE-RESTRICT", decision: "ELIGIBLE" });
      expect(audit.ordering[0].reason).toBeTruthy();
      expect(audit.actionVersions[0]).toMatchObject({ action: "ACT-AUTH-SOURCE-RESTRICT", knowledgeVersion: a.knowledgeVersion });
      expect(audit.capabilityChecks["cap.scoped_network_enforcement"]).toBe("UNKNOWN");   // never assumed
      expect(audit.authorityChecks.ir_execute).toBe(true);
      expect(audit.authorityChecks.dba).toBe("UNKNOWN");
      expect(JSON.stringify(h.created[0].steps)).not.toContain("policyDecisions");
    });
  });

  it("no enforcement point known => no executable step: the recommendation is investigation-only and asks for exactly that data (nothing invented)", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce" });
      expect((await h.run()).isSuccess).toBe(true);
      const rec = h.created[0];
      expect(rec.steps.every((s) => s.actionId === null)).toBe(true);
      expect(rec.steps.map((s) => s.stepType)).toEqual(["CHECK", "CHECK"]);                 // explanation + information needed
      expect(rec.steps[1].instructions.map((i) => i.instruction).join(" ")).toContain("จุดควบคุมการเข้าถึง");
    });
  });
});

describe("deployment policy: enforce is requested but knowledge is not deployable", () => {
  it("falls back to the legacy recommendation (unchanged) and records ENFORCE_FALLBACK with the reason", async () => {
    const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH) });
    const r = await h.run();
    expect(r.isSuccess).toBe(true);
    expect(h.created[0].createdBy).toBe("FakeRecommendationAgent/v1.0.0");                // legacy path
    expect(h.created[0].steps[0].actionId).toBe("action-ACT-BLOCK-SOURCE-IP");
    expect(h.audits[0]).toMatchObject({ mode: "ENFORCE_FALLBACK" });
    expect((h.audits[0].audit as Record<string, any>).fallbackReason).toMatch(/await IR review/);
  });
  it("shadow (the default) leaves the legacy output untouched and stores the subtype audit", async () => {
    const h = harness({ rows: rows(), loader: orgLoader(ORG_SSH) });
    expect((await h.run()).isSuccess).toBe(true);
    expect(h.created[0].steps[0].actionId).toBe("action-ACT-BLOCK-SOURCE-IP");
    expect(h.audits[0]).toMatchObject({ mode: "SHADOW", recommendationId: "rec-1" });
    expect(((h.audits[0].audit as Record<string, any>).policyDecisions as any[])[0].decision).toBe("ELIGIBLE");
  });
  it("mode off and 'no subtype integration' behave exactly like before (no audit)", async () => {
    const off = harness({ rows: rows(), mode: "off" });
    expect((await off.run()).isSuccess).toBe(true);
    expect(off.audits).toHaveLength(0);
    const none = harness({ rows: rows(), withSubtype: false });
    expect((await none.run()).isSuccess).toBe(true);
  });
});

describe("failure containment", () => {
  it("an Action missing from the catalog refuses the subtype recommendation (KNOWLEDGE_NOT_SEEDED) and falls back - nothing half-persisted", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH), seedSubtypeCatalog: false });
      expect((await h.run()).isSuccess).toBe(true);
      expect(h.created).toHaveLength(1);
      expect(h.created[0].createdBy).toBe("FakeRecommendationAgent/v1.0.0");
      expect((h.audits[0].audit as Record<string, any>).fallbackReason).toMatch(/KNOWLEDGE_NOT_SEEDED/);
    });
  });
  it("an audit-store failure never loses the recommendation; the audit moves to the generic audit log", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH), auditFails: true });
      expect((await h.run()).isSuccess).toBe(true);
      expect(h.created).toHaveLength(1);
      expect(h.logged.some((l) => l.action === "RECOMMENDATION_SUBTYPE_AUDIT" && /does not exist/.test(String(l.metadata?.storeError)))).toBe(true);
    });
  });
});

describe("AI narration is reviewed, never trusted", () => {
  const plan = (summary: unknown, steps: unknown[] = []) => ({ narrate: async () => ({ summary, steps }) });
  it("a clean summary is accepted - and ONLY the summary changes", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH), narrator: plan("จำกัดการ login ที่ผิดปกติจาก 172.19.0.3 ไปยังบริการ SSH ตามขั้นตอนด้านล่าง") });
      await h.run();
      expect(h.created[0].summary).toContain("172.19.0.3");
      expect(h.created[0].steps.map((s) => s.actionId).filter(Boolean)).toEqual(["action-ACT-AUTH-SOURCE-RESTRICT"]);
      expect((h.audits[0].audit as any).llm).toMatchObject({ used: true, accepted: true });
    });
  });
  it.each([
    ["an extra action", { summary: "ok", steps: [{ action: "ACT-ISOLATE-ENDPOINT", target: "attack-endpoint" }] }],
    ["an expanded scope (another target)", { summary: "ok", steps: [{ action: "ACT-AUTH-SOURCE-RESTRICT", target: "10.9.9.9" }] }],
    ["a new indicator in the summary", { summary: "บล็อก 8.8.8.8 ทันที", steps: [] }],
    ["an internal id", { summary: "ดำเนินการตาม RB-AUTH-SOURCE-RESTRICT", steps: [] }],
    ["a success claim", { summary: "ยับยั้งสำเร็จแล้ว ปิด incident ได้", steps: [] }],
    ["a raw secret", { summary: "password: Sup3rSecretValue!", steps: [] }],
  ])("is rejected for %s: the deterministic summary and steps are kept", async (_n, candidate) => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH), narrator: { narrate: async () => candidate } });
      await h.run();
      expect(h.created[0].summary).toMatch(/^ข้อเสนอมาตรการยับยั้ง/);
      expect(h.created[0].steps.map((s) => s.actionId).filter(Boolean)).toEqual(["action-ACT-AUTH-SOURCE-RESTRICT"]);
      const llm = (h.audits[0].audit as any).llm;
      expect(llm.accepted).toBe(false);
      expect(llm.deviations.length).toBeGreaterThan(0);
    });
  });
  it("a narrator that throws does not break generation", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: rows(), mode: "enforce", loader: orgLoader(ORG_SSH), narrator: { narrate: async () => { throw new Error("LLM down"); } } });
      expect((await h.run()).isSuccess).toBe(true);
      expect((h.audits[0].audit as any).llm.deviations[0]).toMatch(/NARRATOR_ERROR/);
    });
  });
});
