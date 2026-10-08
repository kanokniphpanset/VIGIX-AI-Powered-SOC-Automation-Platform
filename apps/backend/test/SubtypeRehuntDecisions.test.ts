import * as fs from "node:fs";
import * as path from "node:path";
import { RehuntContextRow } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { TicketRecord } from "../src/domain/subtype/actionState";
import { ORG_SSH, allowUnreviewed, harness, orgLoader } from "./helpers/subtypeFlowHarness";
import { evaluate, realAlert, resetRefs, wazuhRow } from "./helpers/subtypeFixtures";
import { EARLIER, T, recurred, rehunt, ticket } from "./helpers/formatScenarios";

/**
 * INTEGRATION (no DB, no LLM): after a Re-hunt, new activity is NOT a reason to repeat the same action automatically. The next step is chosen from
 * the IR's result, the control state the IR recorded, timestamps (execution / re-hunt / the target's own evidence) and the target + scope.
 * Evidence = recorded Wazuh sshd alert 5712 (dated 2026-10-03T12:23Z). EARLIER (2026-10-01) is BEFORE it; the default ticket time (2026-10-08) is after.
 */
beforeEach(() => resetRefs());
const loader = () => orgLoader(ORG_SSH);
const verifiedAfterEvidence = new Date("2026-10-04T00:00:00Z");
const second = () => {
  const dir = path.join(__dirname, "fixtures/wazuh-real");
  const payload = JSON.parse(fs.readFileSync(path.join(dir, fs.readdirSync(dir).find((f) => f.startsWith("5712-"))!), "utf8"));
  payload.id = "1759900001.999"; payload.data = { ...payload.data, srcip: "172.19.0.9" };
  return wazuhRow(payload);
};
const run = (o: { tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null; rows?: any[] }) =>
  evaluate(o.rows ?? [realAlert("5712")], { loader: loader(), tickets: o.tickets ?? [], rehunt: o.rehunt ?? null, investigationNumber: 2 });
type Ev = Awaited<ReturnType<typeof run>>;
const decisionFor = (e: Ev, target = T) => e.plan!.instances.find((i) => i.primary?.display === target)!;
const readyTargets = (e: Ev) => e.plan!.ordered.map((n) => n.primary?.display);

describe("first response vs later rounds", () => {
  it("first response: NEW (no history)", async () => {
    const e = await evaluate([realAlert("5712")], { loader: loader() });
    expect(decisionFor(e).rehuntDecision).toBe("NEW");
    expect(readyTargets(e)).toEqual([T]);
  });
});

describe("NO_NEW_ACTION: nothing to propose", () => {
  it("still effective: the execution record + a re-hunt that is newer than both the execution and the target's evidence, with full coverage", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ verifiedAt: verifiedAfterEvidence }) });
    expect(decisionFor(e).rehuntDecision).toBe("NO_NEW_ACTION");
    expect(decisionFor(e).state).toBe("EXECUTED_EFFECTIVE");
    expect(readyTargets(e)).toEqual([]);
  });
  it("a ticket still open: not executed, not repeated", async () => {
    const e = await run({ tickets: [ticket({ status: "PENDING_IR_DECISION" })] });
    expect(decisionFor(e).rehuntDecision).toBe("NO_NEW_ACTION");
    expect(readyTargets(e)).toEqual([]);
  });
  it("recurrence on a DIFFERENT host leaves this target's measure alone", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ result: "NOT_RESOLVED", matchingEvents: 3, affectedHosts: ["other-host"], newHosts: ["other-host"], classification: "NEW_SCOPE_ACTIVITY", verifiedAt: verifiedAfterEvidence }) });
    expect(decisionFor(e).rehuntDecision).toBe("NO_NEW_ACTION");
    expect(readyTargets(e)).toEqual([]);
  });
});

describe("INVESTIGATE: gather information first - never repeat, never call it contained", () => {
  const expectInvestigate = (e: Ev) => {
    expect(decisionFor(e).rehuntDecision).toBe("INVESTIGATE");
    expect(readyTargets(e)).toEqual([]);
    expect(e.composition!.steps.every((s) => s.stepType !== "ACTION")).toBe(true);
    expect(e.composition!.missingInfo.length).toBeGreaterThan(0);
    expect(e.composition!.userText.replace(/ไม่ถือว่า\s*contained/g, "")).not.toMatch(/contained|ยังมีผลอยู่|ปิด incident/);
  };
  it("no re-hunt for this cycle", async () => expectInvestigate(await run({ tickets: [ticket()] })));
  it("the re-hunt is older than the execution (it cannot verify it)", async () => {
    const e = await run({ tickets: [ticket({ completedAt: new Date("2026-10-08T04:00:00Z") })], rehunt: rehunt({ verifiedAt: new Date("2026-10-05T00:00:00Z") }) });
    expectInvestigate(e);
    expect(decisionFor(e).stateReason).toContain("ไม่ใหม่กว่าเวลาที่ IR ดำเนินการเสร็จ");
  });
  it("coverage incomplete (agent offline / telemetry stale)", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ coverageComplete: false, verifiedAt: verifiedAfterEvidence }) });
    expectInvestigate(e);
    expect(e.composition!.missingInfo.join(" ")).toContain("agent ออนไลน์");
  });
  it("the target has evidence NEWER than the re-hunt: 'no recurrence' is not established", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ verifiedAt: new Date("2026-10-02T00:00:00Z") }) });
    expectInvestigate(e);
    expect(decisionFor(e).stateReason).toContain("ใหม่กว่าเวลา Re-hunt");
  });
  it("recurrence in scope but the target's own evidence is older than the execution: uncorroborated", async () => {
    const e = await run({ tickets: [ticket({ completedAt: new Date("2026-10-08T04:00:00Z") })], rehunt: recurred({ verifiedAt: new Date("2026-10-09T00:00:00Z") }) });
    expectInvestigate(e);
    expect(decisionFor(e).stateReason).toContain("ยังไม่พบหลักฐานของ target นี้ที่เกิดหลังเวลาที่ IR ดำเนินการเสร็จ");
  });
  it("corroborated recurrence but the IR left no record of the control state", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER })], rehunt: recurred() });
    expectInvestigate(e);
    expect(decisionFor(e).state).toBe("RECURRED_CONTROL_UNKNOWN");
    expect(e.composition!.missingInfo.join(" ")).toContain("สถานะปัจจุบันของมาตรการเดิม");
  });
});

describe("ADJUST: do not repeat; the path / scope must be re-examined", () => {
  it("corroborated recurrence although the IR attested the control was applied", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER, executionNote: "IR ตั้ง deny ตามขั้นตอน (fixture)" })], rehunt: recurred() });
    expect(decisionFor(e).rehuntDecision).toBe("ADJUST");
    expect(decisionFor(e).state).toBe("RECURRED_CONTROL_APPLIED");
    expect(readyTargets(e)).toEqual([]);                                                   // the same action is NOT repeated
    expect(e.composition!.missingInfo.join(" ")).toContain("เส้นทาง/บริการ/บัญชีที่กิจกรรมใหม่");
    expect(e.composition!.userText).toContain("ไม่เสนอทำมาตรการเดิมซ้ำ");
  });
});

describe("REPEAT: the same action again - only when it was not (fully) applied", () => {
  it("the execution FAILED", async () => {
    const e = await run({ tickets: [ticket({ status: "FAILED", executionNote: "firewall rule rejected" })] });
    expect(decisionFor(e).rehuntDecision).toBe("REPEAT");
    expect(readyTargets(e)).toEqual([T]);
    expect(e.composition!.steps[0].instructions[0].note).toContain("firewall rule rejected");
  });
  it.each(["PARTIAL", "NOT_APPLIED"])("the IR recorded the control as %s and the activity returned after the execution", async (cs) => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER, controlState: cs })], rehunt: recurred() });
    expect(decisionFor(e).rehuntDecision).toBe("REPEAT");
    expect(decisionFor(e).state).toBe("EXECUTED_NOT_APPLIED");
    expect(readyTargets(e)).toEqual([T]);
    expect(e.composition!.steps[0].instructions[0].note).toContain("ตรวจบันทึกการดำเนินการของ IR");
  });
  it("controlState APPLIED is an attestation like a note: ADJUST, not REPEAT", async () => {
    const e = await run({ tickets: [ticket({ completedAt: EARLIER, controlState: "APPLIED" })], rehunt: recurred() });
    expect(decisionFor(e).rehuntDecision).toBe("ADJUST");
  });
});

describe("ADD: a target / scope not handled before", () => {
  it("a second attacker address is a NEW instance while the first, still effective, is left alone", async () => {
    const e = await run({ rows: [realAlert("5712"), second()], tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ verifiedAt: new Date("2026-10-06T00:00:00Z") }) });
    expect(decisionFor(e, T).rehuntDecision).toBe("NO_NEW_ACTION");
    expect(decisionFor(e, "172.19.0.9").rehuntDecision).toBe("ADD");
    expect(readyTargets(e)).toEqual(["172.19.0.9"]);
  });
  it("IR rejected the earlier ticket: the same evidence still supports the action, offered again as ADD", async () => {
    const e = await run({ tickets: [ticket({ status: "REJECTED" })] });
    expect(decisionFor(e).rehuntDecision).toBe("ADD");
    expect(readyTargets(e)).toEqual([T]);
  });
});

describe("through GenerateRecommendationUseCase: the decision is audited and nothing is executed", () => {
  const gen = (o: { tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null }) =>
    harness({ rows: [realAlert("5712")], mode: "enforce", loader: loader(), investigationNumber: 2, nextNumber: 2, tickets: o.tickets ?? [], rehunt: o.rehunt ?? null });
  it("ADJUST: no ACTION step is created; the audit records ADJUST", async () => {
    await allowUnreviewed(async () => {
      const h = gen({ tickets: [ticket({ completedAt: EARLIER, executionNote: "applied (fixture)" })], rehunt: recurred() });
      expect((await h.run()).isSuccess).toBe(true);
      expect(h.created[0].steps.every((s) => s.actionId === null)).toBe(true);
      expect((h.audits[0].audit as any).suppressed[0]).toMatchObject({ rehuntDecision: "ADJUST", state: "RECURRED_CONTROL_APPLIED" });
    });
  });
  it("REPEAT: one ACTION step with the reason; status VALIDATED (SOC review) - not approved, not executed", async () => {
    await allowUnreviewed(async () => {
      const h = gen({ tickets: [ticket({ completedAt: EARLIER, controlState: "PARTIAL" })], rehunt: recurred() });
      expect((await h.run()).isSuccess).toBe(true);
      const rec = h.created[0];
      expect(rec.status).toBe("VALIDATED");
      expect(rec.steps.filter((s) => s.actionId)).toHaveLength(1);
      expect(rec.steps.find((s) => s.actionId)!.instructions[0].note).toBeTruthy();
      expect((h.audits[0].audit as any).policyDecisions[0]).toMatchObject({ rehuntDecision: "REPEAT", state: "EXECUTED_NOT_APPLIED" });
    });
  });
});
