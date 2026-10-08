import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { ATTACK_TYPES } from "../src/domain/knowledge/knowledgeTypes";
import { ATTACK_KNOWLEDGE } from "../src/domain/knowledge/attackKnowledge";
import { ACTION_KNOWLEDGE, actionsForAttackType, findActionKnowledge } from "../src/domain/knowledge/actionKnowledge";
import { ContainmentProcedureError, ContainmentProcedureLoader, DEFAULT_PLAYBOOK_DIR, parseProcedureItem } from "../src/infrastructure/knowledge/ContainmentProcedureLoader";
import { RecommendationPromptBuilder } from "../src/infrastructure/ai/RecommendationPromptBuilder";
import { RecommendationMapper } from "../src/infrastructure/database/postgres/mappers/Recommendation.mapper";
import { evaluateContainmentRubric, RubricInput, RubricStep } from "../src/evaluation/containmentRubric";
import { RecommendationContextDto } from "../src/application/recommendation/dto/RecommendationContextDto";
import { CreateRecommendationData } from "../src/domain/recommendation/repositories/IRecommendationRepository";
import { ACTIONS, ACTION_RUNBOOK_CODES } from "../prisma/seeds/action.seed";
import { RUNBOOKS } from "../prisma/seeds/runbook.seed";
import { INCIDENT_PLAYBOOKS } from "../prisma/seeds/playbook.seed";
import { NETWORK_BLOCK_ACTIONS } from "../prisma/seeds/policy.seed";
import { INCIDENT, SCENARIOS, Scenario, TENANT, buildContext, generate, procedureLoader, validator } from "./helpers/containmentScenarios";

/**
 * Attack-specific containment procedures: YAML knowledge -> RecommendationContext -> AI candidate (CHECK / ACTION /
 * MANUAL) -> RecommendationValidator -> persisted steps -> rubric. TC-01..TC-10 run through the real pipeline with the
 * deterministic FakeRecommendationAgent; the LLM path shares the same prompt, validator and persistence.
 */

const playbookOf = (attackType: string) => INCIDENT_PLAYBOOKS.find((p) => p.code === ATTACK_KNOWLEDGE.find((a) => a.attackType === attackType)!.playbook)!;
const scenario = (caseId: string) => SCENARIOS.find((s) => s.caseId === caseId)!;
const actionItems = (attackType: string) => procedureLoader.read(attackType)!.steps.flatMap((s) => s.items.filter((i) => i.type === "ACTION").map((i) => ({ step: s.stepOrder, code: i.actionCode! })));
const firstActionStep = (attackType: string) => Math.min(...actionItems(attackType).map((a) => a.step));
const stepOf = (attackType: string, code: string) => actionItems(attackType).find((a) => a.code === code)!.step;

describe("Knowledge — attack-specific containment procedure per attack type", () => {
  it.each([...ATTACK_TYPES])("%s: loads with objective, strategy, typed steps, decisions and success criteria", (attackType) => {
    const p = procedureLoader.read(attackType)!;
    expect(p.procedureCode).toBe(attackType);
    expect(p.objective.length).toBeGreaterThan(20);
    expect(p.strategy.length).toBeGreaterThan(40);
    const types = p.steps.flatMap((s) => s.items.map((i) => i.type));
    expect(types).toContain("CHECK");
    expect(types).toContain("ACTION");
    expect(p.steps.some((s) => s.phase === "VERIFY" && s.items.some((i) => i.type === "CHECK"))).toBe(true);
    expect(p.verification.successCriteria.length).toBeGreaterThan(0);
    expect(p.decisions.length).toBeGreaterThan(0);
    // The first step is always a CHECK: containment starts from confirming the evidence, never from an action.
    expect(p.steps[0].items.every((i) => i.type === "CHECK")).toBe(true);
  });

  it.each([...ATTACK_TYPES])("%s: candidate Actions = playbook allowedActions = applicable Actions, each with a condition and its own runbook", (attackType) => {
    const p = procedureLoader.read(attackType)!;
    const candidates = p.candidateActions.map((c) => c.actionCode).sort();
    expect(candidates).toEqual([...playbookOf(attackType).allowedActions].sort());
    expect(candidates).toEqual([...actionsForAttackType(attackType)].sort());
    for (const c of p.candidateActions) {
      expect(c.condition && c.condition.length).toBeTruthy();
      expect(c.runbookRef).toBe(findActionKnowledge(c.actionCode)!.runbook);
    }
    // Every candidate is used by a step, and every step Action is a candidate (the loader rejects the reverse).
    expect([...new Set(actionItems(attackType).map((a) => a.code))].sort()).toEqual(candidates);
  });

  it("the 10 strategies are attack-specific, not one template with a different name", () => {
    const signature = (t: string) => procedureLoader.read(t)!.steps.map((s) => s.items.map((i) => (i.type === "ACTION" ? i.actionCode : i.type)).join("+")).join(" > ");
    expect(new Set(ATTACK_TYPES.map(signature)).size).toBe(ATTACK_TYPES.length);
    expect(new Set(ATTACK_TYPES.map((t) => procedureLoader.read(t)!.objective)).size).toBe(ATTACK_TYPES.length);
  });

  it("conditional Actions come after the CHECK that decides them", () => {
    // Brute force: restrict the source first; session revoke / credential reset only after the successful-login check.
    expect(stepOf("BRUTE_FORCE", "ACT-BLOCK-SOURCE-IP")).toBe(firstActionStep("BRUTE_FORCE"));
    for (const code of ["ACT-REVOKE-SESSION", "ACT-RESET-CREDENTIAL", "ACT-DISABLE-ACCOUNT"]) expect(stepOf("BRUTE_FORCE", code)).toBeGreaterThan(firstActionStep("BRUTE_FORCE"));
    // Malware / suspicious process / PowerShell: isolation is not the first response — only when compromise is evidenced.
    for (const t of ["MALWARE", "SUSPICIOUS_PROCESS_EXECUTION", "POWERSHELL"]) expect(stepOf(t, "ACT-ISOLATE-ENDPOINT")).toBeGreaterThan(firstActionStep(t));
    // C2: block the channel first, isolate when communication continues (DEC-C2-002 sits between them).
    const c2 = procedureLoader.read("COMMAND_AND_CONTROL")!;
    const decisionStep = c2.decisions.find((d) => d.id === "DEC-C2-002")!.stepRef;
    expect(stepOf("COMMAND_AND_CONTROL", "ACT-BLOCK-DESTINATION-IP")).toBeLessThan(decisionStep);
    expect(stepOf("COMMAND_AND_CONTROL", "ACT-ISOLATE-ENDPOINT")).toBeGreaterThan(decisionStep);
    // Phishing: account containment only after the user-interaction check.
    expect(stepOf("PHISHING", "ACT-RESET-CREDENTIAL")).toBeGreaterThan(procedureLoader.read("PHISHING")!.decisions.find((d) => d.id === "DEC-PH-001")!.stepRef);
  });

  it("attack-specific conditions and manual controls are carried by the knowledge", () => {
    const cond = (t: string, code: string) => procedureLoader.read(t)!.candidateActions.find((c) => c.actionCode === code)!.condition!;
    expect(cond("BRUTE_FORCE", "ACT-REVOKE-SESSION")).toMatch(/successful login|active suspicious session/i);
    expect(cond("BRUTE_FORCE", "ACT-RESET-CREDENTIAL")).toMatch(/credential compromise/i);
    expect(cond("MALWARE", "ACT-ISOLATE-ENDPOINT")).toMatch(/not for every malware alert/i);
    expect(cond("PRIVILEGE_ESCALATION", "ACT-REMOVE-PRIVILEGE")).toMatch(/never from the alert alone/i);
    const sqli = procedureLoader.read("SQL_INJECTION")!;
    expect(sqli.strategy).toMatch(/instead of assuming/i);
    const manual = sqli.steps.flatMap((s) => s.items.filter((i) => i.type === "MANUAL"));
    expect(manual.find((i) => /WAF rule/.test(i.text))).toMatchObject({ requiresApproval: true, approver: "application owner", actionCode: null });
    expect(manual.find((i) => /privileges/.test(i.text))).toMatchObject({ requiresApproval: true, approver: "DB owner / IR_TEAM" });
    expect(procedureLoader.read("ACCOUNT_COMPROMISE")!.steps.flatMap((s) => s.items).find((i) => i.type === "MANUAL")!.text).toMatch(/MFA/);
  });

  it("new containment Actions exist in every catalog layer and stay under Policy", () => {
    for (const code of ["ACT-RATE-LIMIT-SOURCE", "ACT-BLOCK-SENDER", "ACT-REMOVE-PRIVILEGE"]) {
      expect(ACTIONS.find((a) => a.code === code)?.category).toBe("CONTAINMENT");
      expect(RUNBOOKS.find((r) => r.code === ACTION_RUNBOOK_CODES[code])?.relatedActions).toEqual([code]);
    }
    expect(ACTIONS.find((a) => a.code === "ACT-REMOVE-PRIVILEGE")).toMatchObject({ impactLevel: "HIGH", defaultApprovalRequired: true }); // POL-A01
    expect(NETWORK_BLOCK_ACTIONS).toEqual(expect.arrayContaining(["ACT-RATE-LIMIT-SOURCE", "ACT-BLOCK-SENDER"])); // POL-A02
    // Checks are never Actions.
    expect(ACTION_KNOWLEDGE.map((a) => a.code).filter((c) => /IDENTIFY|CHECK|MONITOR|REVIEW/.test(c))).toEqual([]);
  });

  it("item convention: ACTION / MANUAL / CHECK markers", () => {
    const conditions = new Map([["ACT-BLOCK-SOURCE-IP", "source confirmed"]]);
    expect(parseProcedureItem("Block it (see containment.yaml: ACT-BLOCK-SOURCE-IP)", conditions)).toMatchObject({ type: "ACTION", actionCode: "ACT-BLOCK-SOURCE-IP", condition: "source confirmed", text: "Block it" });
    expect(parseProcedureItem("Apply a WAF rule (manual - outside the VIGIX Action Catalog; requires application owner approval)", conditions)).toMatchObject({ type: "MANUAL", requiresApproval: true, approver: "application owner" });
    expect(parseProcedureItem("Restrict X (manual - outside the VIGIX Action Catalog)", conditions)).toMatchObject({ type: "MANUAL", requiresApproval: false });
    expect(parseProcedureItem("Check for a successful login", conditions)).toMatchObject({ type: "CHECK", actionCode: null });
  });

  it("an inconsistent procedure is rejected, never half-loaded; an unknown attack type has none", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vigix-proc-"));
    fs.cpSync(path.join(DEFAULT_PLAYBOOK_DIR, "procedures", "SQL_INJECTION"), path.join(dir, "procedures", "SQL_INJECTION"), { recursive: true });
    const steps = path.join(dir, "procedures", "SQL_INJECTION", "steps.yaml");
    fs.writeFileSync(steps, fs.readFileSync(steps, "utf8").replace("containment.yaml: ACT-RATE-LIMIT-SOURCE", "containment.yaml: ACT-ISOLATE-ENDPOINT"));
    // (ACT-RATE-LIMIT-SOURCE is referenced by SQL_INJECTION step 2, so the replacement above makes it inconsistent)
    expect(() => new ContainmentProcedureLoader(dir).read("SQL_INJECTION")).toThrow(ContainmentProcedureError);
    expect(procedureLoader.read("WEB_ATTACK")).toBeNull();
    expect(procedureLoader.read("../etc")).toBeNull();
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe.each(SCENARIOS.map((s) => [s.caseId, s] as const))("%s — attack-specific containment recommendation", (_caseId, s: Scenario) => {
  let ctx: RecommendationContextDto;
  let rec: CreateRecommendationData;
  beforeAll(async () => {
    ctx = await buildContext(s);
    const { result, created } = await generate(s);
    expect(result.isSuccess).toBe(true);
    rec = created[0];
  });

  it("loads the attack type's own procedure into the RecommendationContext", () => {
    expect(ctx.attackType).toBe(s.attackType);
    expect(ctx.playbook?.code).toBe(s.playbook);
    expect(ctx.containmentProcedure?.procedureCode).toBe(s.attackType);
  });

  it("the prompt makes the procedure the primary strategy source", () => {
    const prompt = new RecommendationPromptBuilder().build(ctx);
    for (const line of [
      "Use the attack-specific containment procedure below as the primary strategy source.",
      "Do not invent containment steps that are not supported by the provided Knowledge.",
      "A recommendation may contain CHECK, ACTION, and MANUAL steps.",
      "ACTION steps must use an available catalog action.",
      "CHECK steps are investigation/decision steps and must not be represented as executable actions.",
      "MANUAL steps represent controls that are not currently executable by VIGIX.",
      "Preserve conditions from the procedure and policy.",
      "Do not execute or approve actions automatically.",
    ]) expect(prompt).toContain(line);
    expect(prompt).toContain(`Containment procedure ${s.attackType}`);
    expect(prompt).toContain(`Objective: ${ctx.containmentProcedure!.objective}`);
  });

  it("produces ordered CHECK + ACTION steps; ACTIONs carry their procedure condition and Policy approval", () => {
    const types = rec.steps.map((st) => st.stepType);
    expect(types[0]).toBe("CHECK");
    expect(types).toContain("ACTION");
    const procedure = ctx.containmentProcedure!;
    for (const st of rec.steps) {
      if (st.stepType === "ACTION") {
        const code = st.actionId!.replace("action-", "");
        expect(st.precondition).toBe(procedure.candidateActions.find((c) => c.actionCode === code)!.condition);
        expect(st.requiresApproval).toBe(ACTIONS.find((a) => a.code === code)!.impactLevel === "HIGH");
        expect(st.sourceRunbookId).not.toBeNull();
      } else {
        expect(st.actionId).toBeNull();
        expect(st.sourceRunbookId).toBeNull();
      }
      expect(st.verificationCriteria).toBeTruthy();
    }
  });

  it("scores 7/7 evaluable rubric criteria (no Ground Truth -> target correctness not evaluable)", () => {
    const actionsByCode = new Map(ctx.actionProcedures!.map((p) => [p.actionCode, p.policy.approvalRequired]));
    const result = evaluateContainmentRubric({
      caseId: s.caseId, expectedAttackType: s.attackType, expectedPlaybook: s.playbook, status: "VALIDATED",
      playbook: ctx.playbook!.code, procedure: ctx.containmentProcedure!, policyApproval: Object.fromEntries(actionsByCode),
      steps: rec.steps.map((st) => ({ stepType: st.stepType!, action: st.actionId?.replace("action-", "") ?? null, target: st.target, title: st.title, precondition: st.precondition, evidence: st.evidence, requiresApproval: st.requiresApproval, verificationCriteria: st.verificationCriteria })),
      groundTruth: null,
    });
    expect(result.criteria.filter((c) => c.result === "FAIL")).toEqual([]);
    expect(result).toMatchObject({ passed: 6, evaluable: 6, scorePct: 100 });
  });
});

it("TC-06 SQL injection carries MANUAL controls under the application owner's approval; TC-04 carries the MFA re-registration", async () => {
  const sqli = (await generate(scenario("TC-06"))).created[0];
  const manual = sqli.steps.filter((st) => st.stepType === "MANUAL");
  expect(manual.map((m) => m.objective)).toEqual([expect.stringMatching(/WAF rule/), expect.stringMatching(/restrict the affected endpoint/)]);
  expect(manual.every((m) => m.requiresApproval && m.actionId === null)).toBe(true);
  const ac = (await generate(scenario("TC-04"))).created[0];
  expect(ac.steps.find((st) => st.stepType === "MANUAL")!.objective).toMatch(/MFA/);
});

it("strategies differ per attack type: TC-01, TC-06 and TC-09 produce different ordered recommendations", async () => {
  const shape = async (id: string) => (await generate(scenario(id))).created[0].steps.map((st) => `${st.stepType}:${st.title.replace(/ — .*$/, "")}`).join(" > ");
  const [bf, sqli, exf] = [await shape("TC-01"), await shape("TC-06"), await shape("TC-09")];
  expect(new Set([bf, sqli, exf]).size).toBe(3);
  expect(bf).toContain("ACTION:Rate-Limit Source");
  expect(sqli).toContain("MANUAL:Manual control");
  expect(exf).toContain("ACTION:Block Destination IP");
});

describe("RecommendationValidator — typed steps (TC-01 brute force context)", () => {
  // Step 4 (revoke / reset) is evidence-gated: it exists only when the evidence records a successful login.
  const s = { ...scenario("TC-01"), facts: ["Successful SSH login for root from 185.220.101.45 after repeated failures"] };
  const base = { playbook: "PB-SSH-BRUTEFORCE", evidenceRefs: ["E1", "T1110"], missingEvidence: [], confidence: 0.7 };
  const check = (procedureStep: number, extra: Record<string, unknown> = {}) => ({
    ...base, type: "CHECK", action: null, runbook: null, procedureStep, target: null, responsibleRole: "IR_TEAM",
    objective: "Determine whether any attempt succeeded.", reason: "A successful login means account takeover.",
    instructions: [{ order: 1, instruction: "Check for a successful login for root after the failed attempts.", target: "root", expectedResult: "Classified." }],
    verificationCriteria: "Account root is classified as compromised or not.", expectedResult: null, ...extra,
  });
  const block = (extra: Record<string, unknown> = {}) => ({
    ...base, type: "ACTION", action: "ACT-BLOCK-SOURCE-IP", runbook: "RB-BLOCK-SOURCE-IP", procedureStep: 2, target: "185.220.101.45", responsibleRole: "IR_TEAM",
    condition: "185.220.101.45 is confirmed malicious (brute-force pattern) and not trusted infrastructure.",
    objective: "Stop authentication attempts from 185.220.101.45.", reason: "Repeated failed root logins from 185.220.101.45 (T1110).", evidenceRefs: ["I1", "E1", "T1110"],
    instructions: [{ order: 1, instruction: "Apply a temporary deny rule for 185.220.101.45 on the perimeter firewall.", target: "185.220.101.45", expectedResult: "Rule active." }],
    verificationCriteria: "Connection attempts from 185.220.101.45 are rejected.", expectedResult: "No further attempts.", requiresApprovalSuggested: false, ...extra,
  });
  const revoke = (extra: Record<string, unknown> = {}) => ({
    ...block(), action: "ACT-REVOKE-SESSION", runbook: "RB-REVOKE-SESSION", procedureStep: 4, target: "root", evidenceRefs: ["I2", "E1", "T1110"],
    condition: "A successful login or an active suspicious session for root is confirmed.",
    objective: "Terminate attacker sessions of root.", reason: "root was targeted by the brute force.",
    instructions: [{ order: 1, instruction: "Terminate the active sessions of root.", target: "root", expectedResult: "No sessions." }],
    verificationCriteria: "No active session of root remains.", ...extra,
  });
  const validate = async (steps: unknown[], withProcedure = true) => {
    const ctx = await buildContext(s, withProcedure);
    return validator.validate({ summary: "Brute-force containment for 185.220.101.45 against root.", steps: steps.map((st, i) => ({ ...(st as object), stepOrder: i + 1 })) }, ctx, TENANT);
  };
  const codes = (o: { violations: string[] }) => o.violations.map((v) => v.split(":")[0]);

  it("an IR-analyst strategy (CHECK -> ACTION -> CHECK -> conditional ACTION -> verify CHECK) validates", async () => {
    const o = await validate([check(1), block(), check(3), revoke(), check(6, { objective: "Confirm unauthorized authentication stopped.", instructions: [{ order: 1, instruction: "Monitor authentication of root and 185.220.101.45.", target: null, expectedResult: null }] })]);
    expect(o.violations).toEqual([]);
    expect(o.steps.map((st) => [st.stepType, st.title.split(" — ")[0]])).toEqual([
      ["CHECK", "Check"], ["ACTION", "Block Source IP"], ["CHECK", "Check"], ["ACTION", "Revoke Active Sessions"], ["CHECK", "Check"],
    ]);
    // The procedure's own condition is persisted for the conditional Action, never dropped.
    expect(o.steps[3].precondition).toMatch(/successful login or an active suspicious session/);
    expect(o.steps[0]).toMatchObject({ actionId: null, sourceRunbookId: null, requiresApproval: false });
  });

  it("CONDITION_MISSING: a conditional Action without its condition", async () => {
    expect(codes(await validate([check(1), block(), revoke({ condition: null })]))).toContain("CONDITION_MISSING");
  });
  it("STEP_TYPE_MISMATCH: a CHECK that carries an executable action", async () => {
    expect(codes(await validate([check(1, { action: "ACT-BLOCK-SOURCE-IP" }), block()]))).toContain("STEP_TYPE_MISMATCH");
  });
  it("UNGROUNDED_STEP: a CHECK on a procedure step without CHECK items, a MANUAL the procedure does not have, a CHECK without any procedure", async () => {
    expect(codes(await validate([check(2), block()]))).toContain("UNGROUNDED_STEP");
    expect(codes(await validate([check(1), block(), check(2, { type: "MANUAL" })]))).toContain("UNGROUNDED_STEP");
    expect(codes(await validate([check(1), block()], false))).toContain("UNGROUNDED_STEP");
    expect(codes(await validate([block({ procedureStep: 4 })]))).toContain("UNGROUNDED_STEP");
  });
  it("NO_ACTION_STEP: checks alone contain nothing", async () => {
    expect(codes(await validate([check(1), check(3)]))).toContain("NO_ACTION_STEP");
  });
  it("INVENTED_TARGET / INVENTED_IOC: a CHECK cannot introduce values the incident does not hold", async () => {
    const o = codes(await validate([check(1, { target: "8.8.8.8" }), block()]));
    expect(o).toEqual(expect.arrayContaining(["INVENTED_TARGET"]));
    expect(codes(await validate([check(1, { objective: "Check whether 8.8.8.8 is involved." }), block()]))).toContain("INVENTED_IOC");
  });
  it("the action-level rules still apply to ACTION steps (role, approval, evidence)", async () => {
    expect(codes(await validate([check(1), block({ responsibleRole: "SOC" })]))).toContain("WRONG_RESPONSIBLE_ROLE");
    expect(codes(await validate([check(1), block({ evidenceRefs: [] })]))).toContain("NO_EVIDENCE");
  });
});

describe("RecommendationValidator — MANUAL controls stay under their approval (TC-06 SQL injection)", () => {
  const s = scenario("TC-06");
  const manualWaf = (extra: Record<string, unknown> = {}) => ({
    type: "MANUAL", action: null, runbook: null, procedureStep: 3, target: null, responsibleRole: "IR_TEAM", playbook: "PB-SQL-INJECTION",
    objective: "Apply a temporary WAF rule for the confirmed SQL injection pattern.", reason: "A WAF rule stops the payload from any source.",
    evidenceRefs: ["E1"], instructions: [{ order: 1, instruction: "Ask the application owner to approve a temporary WAF rule for the UNION SELECT pattern.", target: null, expectedResult: "Rule approved and active." }],
    verificationCriteria: "Requests with the pattern are blocked by the WAF.", missingEvidence: [], confidence: 0.6, requiresApprovalSuggested: true, ...extra,
  });
  const block = {
    type: "ACTION", action: "ACT-BLOCK-SOURCE-IP", runbook: "RB-BLOCK-SOURCE-IP", procedureStep: 2, target: "194.87.29.10", responsibleRole: "IR_TEAM", playbook: "PB-SQL-INJECTION",
    condition: "194.87.29.10 is confirmed to send the injection payloads.", objective: "Block 194.87.29.10.", reason: "Injection payloads from 194.87.29.10 (T1190).",
    evidenceRefs: ["I1", "E1"], instructions: [{ order: 1, instruction: "Apply a deny rule for 194.87.29.10 on the WAF.", target: "194.87.29.10", expectedResult: "Rule active." }],
    verificationCriteria: "Requests from 194.87.29.10 are rejected.", missingEvidence: [], confidence: 0.7, requiresApprovalSuggested: false,
  };
  const check = { ...manualWaf(), type: "CHECK", procedureStep: 1, objective: "Identify the targeted endpoint and parameter.", instructions: [{ order: 1, instruction: "Identify the injected parameter in the web logs.", target: null, expectedResult: null }], requiresApprovalSuggested: false };
  const validate = async (steps: unknown[]) => {
    const ctx = await buildContext(s);
    return validator.validate({ summary: "Stop the SQL injection requests from 194.87.29.10 and assess database impact.", steps: steps.map((st, i) => ({ ...(st as object), stepOrder: i + 1 })) }, ctx, TENANT);
  };

  it("a MANUAL WAF rule validates, is persisted without an action and keeps its approval", async () => {
    const o = await validate([check, block, manualWaf()]);
    expect(o.violations).toEqual([]);
    expect(o.steps[2]).toMatchObject({ stepType: "MANUAL", actionId: null, sourceRunbookId: null, requiresApproval: true });
  });
  it("POLICY_BYPASS: the AI cannot waive the owner's approval of a manual control", async () => {
    expect((await validate([check, block, manualWaf({ requiresApprovalSuggested: false })])).violations.join("\n")).toMatch(/POLICY_BYPASS/);
    expect((await validate([check, block, manualWaf({ reason: "No approval needed for a temporary rule." })])).violations.join("\n")).toMatch(/POLICY_BYPASS/);
  });
});

describe("Persistence — the step type lives in recommendation_steps.phase (no schema change)", () => {
  const row = (phase: string | null, actionId: string | null) => ({
    id: "s1", recommendationId: "r1", stepOrder: 1, title: "t", objective: null, actionId, target: null, reason: "r", evidence: [], sourceRunbookId: null,
    precondition: "cond", expectedResult: null, requiresApproval: false, status: "PENDING", phase, decisionRef: null, instructions: [], verificationCriteria: null,
  });
  const map = (phase: string | null, actionId: string | null) =>
    RecommendationMapper.toDomain({ id: "r1", tenantId: TENANT, incidentId: INCIDENT, investigationNumber: 1, recommendationNumber: 1, status: "VALIDATED", summary: "s", createdBy: "a", createdAt: new Date(), updatedAt: new Date(), investigationId: null, snapshotId: null, steps: [row(phase, actionId)] } as never).steps[0];
  it("maps CHECK / MANUAL / ACTION and legacy rows", () => {
    expect(map("CHECK", null)).toMatchObject({ stepType: "CHECK", precondition: "cond" });
    expect(map("MANUAL", null).stepType).toBe("MANUAL");
    expect(map("ACTION", "a1").stepType).toBe("ACTION");
    expect(map("ACTION", null).stepType).toBe("CHECK"); // pre-step-type "investigation only" row
  });
});

describe("Containment rubric — failures are detected, wording is not judged", () => {
  const procedure = procedureLoader.read("BRUTE_FORCE")!;
  const step = (x: Partial<RubricStep>): RubricStep => ({ stepType: "CHECK", action: null, target: null, title: `Check — ${procedure.steps[0].title}`, precondition: null, evidence: [], requiresApproval: false, verificationCriteria: "done", ...x });
  const good: RubricStep[] = [
    step({}),
    step({ stepType: "ACTION", action: "ACT-BLOCK-SOURCE-IP", target: "1.2.3.4", title: "Block Source IP — 1.2.3.4", precondition: "c", evidence: ["e"] }),
    step({ title: `Check — ${procedure.steps[5].title}` }),
  ];
  const input = (steps: RubricStep[], extra: Partial<RubricInput> = {}): RubricInput => ({
    caseId: "X", expectedAttackType: "BRUTE_FORCE", expectedPlaybook: "PB-SSH-BRUTEFORCE", status: "VALIDATED", playbook: "PB-SSH-BRUTEFORCE", procedure,
    policyApproval: { "ACT-BLOCK-SOURCE-IP": false, "ACT-RESET-CREDENTIAL": true },
    groundTruth: { caseId: "X", expectedPlaybook: "PB-SSH-BRUTEFORCE", expectedRecommendations: [{ action: "ACT-BLOCK-SOURCE-IP", targets: [{ type: "ip", value: "1.2.3.4" }] }] },
    steps, ...extra,
  });
  const fails = (i: RubricInput) => evaluateContainmentRubric(i).criteria.filter((c) => c.result === "FAIL").map((c) => c.criterion);

  it("a complete, grounded strategy passes all 7", () => {
    expect(evaluateContainmentRubric(input(good))).toMatchObject({ passed: 7, evaluable: 7, scorePct: 100 });
  });
  it("detects each failure on its own criterion", () => {
    expect(fails(input(good, { expectedAttackType: "MALWARE" }))).toEqual(["ATTACK_ALIGNMENT"]);
    expect(fails(input([good[0], { ...good[1], evidence: [] }, good[2]]))).toEqual(["EVIDENCE_SUPPORT"]);
    expect(fails(input([good[1], good[2].stepType === "CHECK" ? { ...good[2], stepType: "MANUAL" } : good[2]]))).toContain("ACTION_COMPLETENESS");
    expect(fails(input([good[0], { ...good[1], target: "9.9.9.9", title: "Block Source IP — 9.9.9.9" }, good[2]]))).toEqual(expect.arrayContaining(["TARGET_CORRECTNESS"]));
    expect(fails(input([good[0], { ...good[1], precondition: null }, good[2]]))).toEqual(["POLICY_COMPLIANCE"]);
    expect(fails(input([good[0], { ...good[1], requiresApproval: true }, good[2]]))).toEqual(["POLICY_COMPLIANCE"]);
    expect(fails(input([good[2], good[1], good[0]]))).toEqual(["PLAYBOOK_ALIGNMENT"]);
    expect(fails(input([good[0], good[1]]))).toEqual(["VERIFICATION_COMPLETENESS"]);
  });
  it("without Ground Truth, target correctness is not evaluable (never a pass)", () => {
    const r = evaluateContainmentRubric(input(good, { groundTruth: null }));
    expect(r.criteria.find((c) => c.criterion === "TARGET_CORRECTNESS")!.result).toBe("NOT_EVALUABLE");
    expect(r).toMatchObject({ passed: 6, evaluable: 6 });
  });
});
