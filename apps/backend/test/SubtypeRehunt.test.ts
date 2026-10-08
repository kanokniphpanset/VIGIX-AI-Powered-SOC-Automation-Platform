import * as fs from "node:fs";
import * as path from "node:path";
import { RehuntContextRow } from "../src/application/recommendation/ports/IRecommendationContextRepository";
import { TicketRecord } from "../src/domain/subtype/actionState";
import { ORG_SSH, allowUnreviewed, harness, orgLoader } from "./helpers/subtypeFlowHarness";
import { evaluate, realAlert, resetRefs, wazuhRow } from "./helpers/subtypeFixtures";

/**
 * INTEGRATION (no DB, no LLM): second round after a Re-hunt. The action state comes from REAL records only: Response Tickets (status + IR note)
 * and the previous cycle's Verification/Re-hunt row (result, classification, coverage). "No new alert" is never evidence of containment.
 * Evidence = a recorded Wazuh sshd brute-force alert (rule 5712) and a variant of it from a second attacker address.
 */
beforeEach(() => resetRefs());
const loader = () => orgLoader(ORG_SSH);
const T = "172.19.0.3";
const ticket = (o: Partial<TicketRecord> = {}): TicketRecord => ({ actionCode: "ACT-AUTH-SOURCE-RESTRICT", target: T, status: "COMPLETED", investigationNumber: 1, completedAt: new Date("2026-10-08T04:00:00Z"), ...o });
const rehunt = (o: Partial<RehuntContextRow> = {}): RehuntContextRow => ({
  verificationId: "ver-1", verifiedInvestigationNumber: 1, source: "WAZUH_INDEXER", result: "RESOLVED", spreadDetected: false, matchingEvents: 0, originalHosts: ["attack-endpoint"], affectedHosts: [],
  newHosts: [], truncated: false, classification: "NO_MATCH_COVERED", coverageComplete: true, ...o,
});
const second = () => {
  const payload = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures/wazuh-real", fs.readdirSync(path.join(__dirname, "fixtures/wazuh-real")).find((f) => f.startsWith("5712-"))!), "utf8"));
  payload.id = "1759900001.999"; payload.data = { ...payload.data, srcip: "172.19.0.9" };
  return wazuhRow(payload);
};
const run = (o: { tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null; rows?: any[] }) => evaluate(o.rows ?? [realAlert("5712")], { loader: loader(), tickets: o.tickets ?? [], rehunt: o.rehunt ?? null, investigationNumber: 2 });
const proposed = (e: Awaited<ReturnType<typeof run>>) => e.plan!.ordered.map((n) => `${n.action_id}|${n.primary?.display}`);

describe("round 2: action state decides whether an action is proposed again", () => {
  it("first round: the action is proposed (baseline)", async () => {
    expect(proposed(await run({}))).toEqual([`ACT-AUTH-SOURCE-RESTRICT|${T}`]);
  });

  it("executed + a COVERED re-hunt found no recurrence -> still effective: NOT proposed again, and the output says why", async () => {
    const e = await run({ tickets: [ticket()], rehunt: rehunt() });
    expect(proposed(e)).toEqual([]);
    expect(e.plan!.suppressed[0].state).toBe("EXECUTED_EFFECTIVE");
    expect(e.composition!.userText).toContain("ยังมีผล");
    expect(e.composition!.userText).not.toMatch(/ยับยั้งสำเร็จ|ปิด incident/);          // never "the incident is contained"
  });

  it("executed but the re-hunt could NOT see everything (agent offline / stale coverage) -> UNKNOWN: not repeated, not called contained, asks for coverage", async () => {
    const e = await run({ tickets: [ticket()], rehunt: rehunt({ coverageComplete: false }) });
    expect(proposed(e)).toEqual([]);
    expect(e.plan!.suppressed[0].state).toBe("EXECUTED_UNVERIFIED");
    expect(e.composition!.missingInfo.join(" ")).toContain("telemetry ที่ครอบคลุมครบและเป็นข้อมูลล่าสุด");
    expect(e.composition!.userText.replace(/ไม่ถือว่า\s*contained/g, "")).not.toMatch(/ยังมีผลอยู่|contained|ล้มเหลวแล้ว/);   // only the explicit negation may mention "contained"
  });

  it("executed and NO usable verification at all (re-hunt incomplete/unconfirmed creates none) -> UNVERIFIED, not repeated", async () => {
    const e = await run({ tickets: [ticket()], rehunt: null });
    expect(proposed(e)).toEqual([]);
    expect(e.plan!.suppressed[0].state).toBe("EXECUTED_UNVERIFIED");
  });

  it("a re-hunt from an OLDER cycle than the ticket does not verify it", async () => {
    const e = await run({ tickets: [ticket({ investigationNumber: 2 })], rehunt: rehunt({ verifiedInvestigationNumber: 1 }) });
    expect(e.plan!.suppressed[0].state).toBe("EXECUTED_UNVERIFIED");
  });

  it("threat came back in scope but this target's own evidence is NOT newer than the execution -> uncorroborated: investigate, do NOT repeat (see SubtypeRehuntDecisions for each outcome)", async () => {
    const e = await run({ tickets: [ticket()], rehunt: rehunt({ result: "NOT_RESOLVED", matchingEvents: 4, affectedHosts: ["attack-endpoint"], classification: "IN_SCOPE_ACTIVITY" }) });
    expect(proposed(e)).toEqual([]);
    expect(e.plan!.suppressed[0].state).toBe("EXECUTED_UNVERIFIED");
    expect(e.plan!.suppressed[0].rehuntDecision).toBe("INVESTIGATE");
  });

  it("the earlier execution FAILED -> proposed again with the failure reason", async () => {
    const e = await run({ tickets: [ticket({ status: "FAILED", executionNote: "firewall rule rejected" })] });
    expect(proposed(e)).toEqual([`ACT-AUTH-SOURCE-RESTRICT|${T}`]);
    expect(e.composition!.steps[0].reason).toContain("firewall rule rejected");
  });

  it("a ticket still waiting for IR (not executed) is not proposed again, and 'ticket created' is not 'executed'", async () => {
    const e = await run({ tickets: [ticket({ status: "PENDING_IR_DECISION" })] });
    expect(proposed(e)).toEqual([]);
    expect(e.plan!.suppressed[0].state).toBe("PROPOSED_PENDING");
  });

  it("IR rejected the ticket -> treated as not executed (the same evidence still supports the action)", async () => {
    const e = await run({ tickets: [ticket({ status: "REJECTED" })] });
    expect(proposed(e)).toEqual([`ACT-AUTH-SOURCE-RESTRICT|${T}`]);
  });

  it("a NEW target (second attacker address) is proposed while the first, still-effective one is not (duplicate action, different target)", async () => {
    const e = await run({ rows: [realAlert("5712"), second()], tickets: [ticket()], rehunt: rehunt() });
    expect(proposed(e)).toEqual(["ACT-AUTH-SOURCE-RESTRICT|172.19.0.9"]);
    expect(e.plan!.suppressed.map((s) => s.primary?.display)).toEqual([T]);
  });

  it("two targets of the same action in round 1 are two separate instances (neither widened into a range)", async () => {
    const e = await run({ rows: [realAlert("5712"), second()] });
    expect(proposed(e)).toEqual([`ACT-AUTH-SOURCE-RESTRICT|${T}`, "ACT-AUTH-SOURCE-RESTRICT|172.19.0.9"]);
    expect(e.composition!.userText).not.toMatch(/172\.19\.0\.0\/|172\.19\.0\.\*|172\.19\.0\.\d+\s*-\s*172\./);
  });

  it("legacy tickets (old ACT-BLOCK-SOURCE-IP on the same target) count through the migration map", async () => {
    const e = await run({ tickets: [ticket({ actionCode: "ACT-BLOCK-SOURCE-IP" })], rehunt: rehunt() });
    expect(e.plan!.suppressed[0].state).toBe("EXECUTED_EFFECTIVE");
  });
});

describe("round 2 through GenerateRecommendationUseCase", () => {
  it("enforce: no ACTION step is created for an effective control; the new recommendation is audited as changed-after-rehunt and supersedes the previous one", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712"), second()], mode: "enforce", loader: loader(), investigationNumber: 2, nextNumber: 2, tickets: [ticket()], rehunt: rehunt(), previousSteps: [{ recommendationNumber: 1, investigationNumber: 1, actionCode: "ACT-AUTH-SOURCE-RESTRICT", target: T }] });
      expect((await h.run()).isSuccess).toBe(true);
      const rec = h.created[0];
      expect(rec.steps.filter((s) => s.actionId).map((s) => s.target)).toEqual(["172.19.0.9"]);
      expect(h.superseded).toEqual(["rec-1"]);
      expect(h.logged.find((l) => l.action === "RECOMMENDATION_GENERATED")?.metadata?.changedAfterRehunt).toBe(true);
      const audit = h.audits[0].audit as any;
      expect(audit.suppressed[0]).toMatchObject({ state: "EXECUTED_EFFECTIVE" });
      expect(audit.meta.rehunt.result).toBe("RESOLVED");
    });
  });
  it("enforce with everything effective: the recommendation contains NO executable step (no repeat, no 'contained' claim)", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712")], mode: "enforce", loader: loader(), investigationNumber: 2, nextNumber: 2, tickets: [ticket()], rehunt: rehunt() });
      expect((await h.run()).isSuccess).toBe(true);
      expect(h.created[0].steps.every((s) => s.actionId === null)).toBe(true);
    });
  });
});
