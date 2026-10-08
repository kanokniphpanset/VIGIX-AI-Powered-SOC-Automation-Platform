import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { DEFAULT_SUBTYPE_KNOWLEDGE_DIR, SubtypeKnowledgeLoader } from "../src/infrastructure/knowledge/SubtypeKnowledgeLoader";
import { ORG_SSH, allowUnreviewed, harness } from "./helpers/subtypeFlowHarness";
import { evaluate, loader as realLoader, realAlert, resetRefs } from "./helpers/subtypeFixtures";

/**
 * INTEGRATION (no DB, no LLM): action ELIGIBILITY (Policy) is separate from step READINESS. An eligible action may contain steps that cannot be
 * performed yet (no method, organization data missing, IR decision pending, prerequisite step not ready, tool unconfirmed). Such steps are never
 * executable instructions (so never in a Ticket); they become information needed and are recorded in the audit with their cause.
 * The knowledge is edited in a TEMPORARY COPY of the repository's knowledge folder; nothing in the repo or any database changes.
 */
beforeEach(() => resetRefs());
const TOOLS = `${ORG_SSH}capability:\n  cap.scoped_network_enforcement: true\n  cap.connection_state_termination: true\n`;

function copyDir(src: string, dst: string) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if (e.name === "node_modules") continue;
    const s = path.join(src, e.name); const d = path.join(dst, e.name);
    e.isDirectory() ? copyDir(s, d) : fs.copyFileSync(s, d);
  }
}
/** Loader over a temp copy of the knowledge, with one step block rewritten. */
function loaderWith(org: string, edits: { file: string; runbook: string; step: string; fn: (block: string) => string }[]) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kb-ready-"));
  copyDir(DEFAULT_SUBTYPE_KNOWLEDGE_DIR, dir);
  for (const ed of edits) {
    const f = path.join(dir, "families", ed.file);
    const text = fs.readFileSync(f, "utf8");
    const rb = text.indexOf(`  - runbook_id: ${ed.runbook}`);
    const st = text.indexOf(`      - step_id: ${ed.step}\n`, rb);
    if (rb < 0 || st < 0) throw new Error(`step not found ${ed.runbook}/${ed.step}`);
    const end = text.indexOf("\n      - step_id:", st + 5);
    const stop = end < 0 ? text.indexOf("\n    verification:", st) : end;
    fs.writeFileSync(f, text.slice(0, st) + ed.fn(text.slice(st, stop)) + text.slice(stop));
  }
  const orgFile = path.join(dir, "org-test.yaml"); fs.writeFileSync(orgFile, org);
  return new SubtypeKnowledgeLoader(dir, orgFile);
}
const bfStep = (step: string, fn: (b: string) => string) => ({ file: "BRUTE_FORCE.yaml", runbook: "RB-AUTH-SOURCE-RESTRICT", step, fn });
const dropMethod = (b: string) => b.replace(/^        method: .*\n/m, "");
const toIr = (b: string) => dropMethod(b).replace("method_basis: EXISTING", 'method_basis: IR_REVIEW_REQUIRED\n        method_requires: "IR ต้องกำหนดวิธีลงมือ (fixture)"');
const readyTitles = (e: Awaited<ReturnType<typeof evaluate>>) => e.composition!.steps.filter((s) => s.stepType === "ACTION").flatMap((s) => s.instructions.filter((i) => i.kind === "action").map((i) => i.title));
const readinessOf = (e: Awaited<ReturnType<typeof evaluate>>) => e.composition!.readiness[0];

describe("method coverage of the shipped knowledge (denominators)", () => {
  const kb = realLoader.load();
  const operational = [...kb.runbooks.values()].flatMap((r) => r.ordered_steps.filter((s) => !s.include_runbook && !s.fold && s.kind !== "verify" && !/^ตรวจ/.test(s.instruction)).map((s) => ({ r, s })));
  it("every operational step declares where its method comes from", () => {
    expect(operational.length).toBe(144);
    const by = (b: string) => operational.filter((x) => x.s.method_basis === b).length;
    expect(by("EXISTING") + by("NEUTRAL_DERIVED") + by("ORG_INPUT_REQUIRED") + by("IR_REVIEW_REQUIRED")).toBe(operational.length);
    expect([by("EXISTING"), by("NEUTRAL_DERIVED"), by("ORG_INPUT_REQUIRED"), by("IR_REVIEW_REQUIRED")]).toEqual([11, 114, 15, 4]);
  });
  it("a ready step has a method that is not its own instruction; a step without one states exactly what is missing and has no method", () => {
    for (const { s } of operational) {
      if (s.method_basis === "EXISTING" || s.method_basis === "NEUTRAL_DERIVED") { expect(s.method).toBeTruthy(); expect(s.method!.trim()).not.toBe(s.instruction.trim()); }
      else { expect(s.method).toBeUndefined(); expect(s.method_requires).toBeTruthy(); }
    }
  });
  it("folded pre-checks, verify-only and include_runbook steps are not forced into the operational schema", () => {
    const others = [...kb.runbooks.values()].flatMap((r) => r.ordered_steps).filter((s) => s.include_runbook || s.fold || s.kind === "verify" || /^ตรวจ/.test(s.instruction));
    expect(others.length).toBe(259 - 144);
    expect(others.every((s) => !s.method_basis && !s.method_requires)).toBe(true);
  });
  it("no method names a menu, an API, a URL or a command (nothing the knowledge cannot support)", () => {
    for (const { s } of operational) if (s.method) expect(s.method).not.toMatch(/\bAPI\b|เมนู|คลิก|https?:\/\/|\bcurl\b|\bkubectl\b|cmdlet/i);
  });
});

describe("eligible action, step not ready", () => {
  it("baseline: with the tools confirmed the action has two ready steps (deny rule, then cut connections)", async () => {
    const e = await evaluate([realAlert("5712")], { loader: loaderWith(TOOLS, []) });
    expect(readyTitles(e).length).toBe(2);
    expect(readinessOf(e).notReady).toEqual([]);
  });
  it("IR decision pending on the deny step: it is NOT an instruction, the dependent connection cut is blocked, and the causes are audited", async () => {
    const e = await evaluate([realAlert("5712")], { loader: loaderWith(TOOLS, [bfStep("S3", toIr)]) });
    expect(e.plan!.ordered.map((n) => n.action_id)).toEqual(["ACT-AUTH-SOURCE-RESTRICT"]);   // the ACTION is still eligible (Policy unchanged)
    expect(readyTitles(e)).toEqual([]);                                                       // but nothing is executable
    expect(e.composition!.steps.some((s) => s.stepType === "ACTION")).toBe(false);          // so no ACTION step / Ticket exists
    const causes = readinessOf(e).notReady.map((n) => n.cause).sort();
    expect(causes).toEqual(["METHOD_IR_REVIEW", "PREREQUISITE"]);
    expect(e.composition!.missingInfo.join(" ")).toContain("รอ IR กำหนด");
    expect(e.composition!.userText).toContain("IR ต้องกำหนดวิธีลงมือ (fixture)");
    expect((e.audit as any).stepReadiness[0].notReady).toHaveLength(2);                      // recorded in the audit
    expect(e.violations).toEqual([]);
  });
  it("organization data missing (approved access): the step waits; once the organization lists it, the same step is ready", async () => {
    const needsAccess = bfStep("S3", (b) => b.replace("method_basis: EXISTING", "method_basis: EXISTING\n        requires_org: [approved_access]"));
    const without = await evaluate([realAlert("5712")], { loader: loaderWith(TOOLS, [needsAccess]) });
    expect(readyTitles(without)).toEqual([]);
    expect(readinessOf(without).notReady.map((n) => n.cause)).toContain("ORG_DATA");
    expect(without.composition!.missingInfo.join(" ")).toContain("approved access");
    const withAccess = await evaluate([realAlert("5712")], { loader: loaderWith(`${TOOLS}approved_access:\n  - {match: "10.0.9.5", note: "IR jump host (fixture)"}\n`, [needsAccess]) });
    expect(readyTitles(withAccess).length).toBe(2);
  });
  it("a step that claims a method but has none makes the knowledge INVALID: no action is opened from it", async () => {
    const l = loaderWith(TOOLS, [bfStep("S3", dropMethod)]);
    const kb = l.load();
    expect(kb.status).toBe("INVALID");
    expect(kb.errors.join(" ")).toMatch(/RB-AUTH-SOURCE-RESTRICT\/S3: EXISTING step has no method/);
    const e = await evaluate([realAlert("5712")], { loader: l });
    expect(e.composition).toBeNull();                                                         // nothing is composed from invalid knowledge
    expect(e.plan?.ordered ?? []).toEqual([]);
  });
  it("prerequisite order: if 'disable' is not ready, 'stop the running instance' is not offered either (it would be relaunched)", async () => {
    // a Scheduled Task Hijack with only the task + payload known, the disable step turned into an IR decision
    const { sysmon, hijackBasic } = await import("./helpers/formatScenarios");
    const l = loaderWith("", [{ file: "POWERSHELL.yaml", runbook: "RB-PERSISTENCE-TRIGGER-DISABLE", step: "S3", fn: toIr }]);
    const e = await evaluate([sysmon(), hijackBasic()], { loader: l });
    const titles = readyTitles(e).join(" | ");
    expect(titles).not.toContain("หยุด instance");
    expect(titles).toContain("ยุติ payload process");                                       // the payload step does not depend on the disable step
    expect(readinessOf(e).notReady.map((n) => n.cause).sort()).toEqual(["METHOD_IR_REVIEW", "PREREQUISITE"]);
  });
});

describe("a Ticket only ever receives ready steps", () => {
  it("through GenerateRecommendationUseCase: the stored ACTION step carries only ready instructions; not-ready steps are in the CHECK step and the audit", async () => {
    await allowUnreviewed(async () => {
      const h = harness({ rows: [realAlert("5712")], mode: "enforce", loader: loaderWith(TOOLS, [bfStep("S4", (b) => b.replace("method_basis: EXISTING", "method_basis: EXISTING\n        requires_org: [approved_access]"))]) });
      expect((await h.run()).isSuccess).toBe(true);
      const rec = h.created[0];
      const action = rec.steps.find((s) => s.actionId)!;
      const ready = action.instructions.filter((i) => (i as any).kind === "action").map((i) => i.title);
      expect(ready).toHaveLength(1);                                                           // only the deny step
      expect(ready.join(" ")).not.toContain("ตัด session/connection");
      const check = rec.steps.find((s) => s.stepType === "CHECK" && s.title === "ข้อมูลที่ต้องตรวจเพิ่ม")!;
      expect(check.instructions.map((i) => i.instruction).join(" ")).toContain("ตัด session/connection");
      expect(check.actionId ?? null).toBeNull();           // never ticketable
      expect((h.audits[0].audit as any).stepReadiness[0].notReady[0]).toMatchObject({ cause: "ORG_DATA" });
    });
  });
});
