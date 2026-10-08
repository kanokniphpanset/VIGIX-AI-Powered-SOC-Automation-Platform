import { buildContext, generate, SCENARIOS, Scenario, TENANT, validator } from "./helpers/containmentScenarios";
import { FakeRecommendationAgent } from "../src/infrastructure/ai/FakeRecommendationAgent";
import { compatibleIocRole, networkRoleFromPayload } from "../src/application/recommendation/services/IocRole";
import { PrismaRecommendationContextRepository } from "../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";

const agent = new FakeRecommendationAgent();
const scenario = (id: string) => SCENARIOS.find(s => s.caseId === id)!;
const candidate = async (s: Scenario) => {
  const context = await buildContext(s);
  return { context, raw: await agent.generate(context) as any };
};

describe("Trusted IOC direction and action compatibility", () => {
  it.each([
    ["source", "ACT-BLOCK-SOURCE-IP", true],
    ["destination", "ACT-BLOCK-SOURCE-IP", false],
    ["destination", "ACT-BLOCK-DESTINATION-IP", true],
    [undefined, "ACT-BLOCK-SOURCE-IP", false],
  ])("%s -> %s = %s", (networkRole, action, expected) => {
    expect(compatibleIocRole({ affectedHosts: [], iocs: [{ iocType: "IPV4", iocValue: "45.155.205.233", networkRole, source: "ALERT", reputationScore: null }] } as any, action as string, "45.155.205.233")).toBe(expected);
  });
  it("reads source fields, never AI prose, and rejects ambiguous direction", () => {
    expect(networkRoleFromPayload({ data: { dstip: "45.155.205.233" } }, "45.155.205.233")).toBe("destination");
    expect(networkRoleFromPayload({ data: { srcip: "45.155.205.233", dstip: "45.155.205.233" } }, "45.155.205.233")).toBeUndefined();
    expect(networkRoleFromPayload({ analysis: "source IP 45.155.205.233" }, "45.155.205.233")).toBeUndefined();
  });
  it("uses the IOC's source alert instead of assigning the primary alert's source role", async () => {
    const repository = new PrismaRecommendationContextRepository({
      threatIntelIoc: { findMany: async () => [{ iocType: "IPV4", iocValue: "45.155.205.233", sourceAlert: { rawPayload: { data: { dstip: "45.155.205.233" } } } }] },
      incident: { findUnique: async () => ({ alert: { rawPayload: { data: { srcip: "45.155.205.233" } } } }) },
    } as any);
    expect((await repository.getIocs("incident", 1))[0].networkRole).toBe("destination");
  });
  it.each(["TC-01", "TC-07", "TC-09", "TC-02"])("valid source/destination/hash plan %s passes the real validator", async id => {
    const { result } = await generate(scenario(id));
    expect(result.isSuccess).toBe(true);
  });
  it("rejects an LLM source action on a destination even if cached evidence says eligible", async () => {
    const { context, raw } = await candidate(scenario("TC-01"));
    context.iocs[0].networkRole = "destination";
    const result = await validator.validate(raw, context, TENANT);
    expect(result.violations.join("\n")).toContain("IOC_ROLE_MISMATCH");
  });
  it("rejects domain with a source-IP action", async () => {
    const { context, raw } = await candidate(scenario("TC-01"));
    context.iocs[0].iocType = "DOMAIN";
    expect((await validator.validate(raw, context, TENANT)).violations.length).toBeGreaterThan(0);
  });
  it("rejects URL with a domain action without implicit extraction", async () => {
    const { context, raw } = await candidate(scenario("TC-03"));
    const step = raw.steps.find((s: any) => s.action === "ACT-BLOCK-DOMAIN");
    expect(step).toBeDefined();
    step.target = context.iocs.find(i => i.iocType === "URL")!.iocValue;
    expect((await validator.validate(raw, context, TENANT)).violations.length).toBeGreaterThan(0);
  });
  it.each(["ACT-INVENTED", "invented-target"])("rejects hallucination %s without persistence", async bad => {
    const { raw } = await candidate(scenario("TC-01"));
    const step = raw.steps.find((s: any) => s.type === "ACTION");
    if (bad === "ACT-INVENTED") step.action = bad; else step.target = "8.8.8.8";
    const result = await generate(scenario("TC-01"), { generate: async () => raw });
    expect(result.result.isSuccess).toBe(false);
    expect(result.created).toHaveLength(0);
  });
  it("AI prose does not add a trusted hostname or username to context", async () => {
    const { context, raw } = await candidate(scenario("TC-01"));
    context.aiAnalysis = { summary: "Compromised host INVENTED-HOST and user invented-user", keyFindings: [] } as any;
    raw.steps.find((s: any) => s.type === "ACTION").target = "INVENTED-HOST";
    expect((await validator.validate(raw, context, TENANT)).violations.join("\n")).toContain("INVENTED_TARGET");
  });
});

describe("PowerShell execution and persistence", () => {
  const command = require("../../../resources/mock-attacks/powershell/case-02-persistence.json").relatedAlerts[0].data.win.eventdata.commandLine as string;
  const persistence: Scenario = {
    ...scenario("TC-05"), title: "Encoded PowerShell command established Run-key persistence", host: "FILESRV-01",
    techniques: ["T1059.001", "T1547.001"],
    iocs: [
      { iocType: "COMMAND", iocValue: command },
      { iocType: "PROCESS", iocValue: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" },
      { iocType: "URL", iocValue: "http://vigix-mock-c2.net/beacon.ps1" },
      { iocType: "DOMAIN", iocValue: "vigix-mock-c2.net" },
      { iocType: "IPV4", iocValue: "45.155.205.233", networkRole: "destination" },
    ], evidenceIocs: [command, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "http://vigix-mock-c2.net/beacon.ps1", "vigix-mock-c2.net", "45.155.205.233"],
  };
  it("T1059.001 alone does not force persistence removal or isolation", async () => {
    const { raw } = await candidate(scenario("TC-05"));
    expect(raw.steps.some((s: any) => s.type === "MANUAL")).toBe(false);
    expect(raw.steps.some((s: any) => s.action === "ACT-ISOLATE-ENDPOINT")).toBe(false);
  });
  it("represents execution, persistence, retrieval, spread and verification under approval", async () => {
    const { context, raw } = await candidate(persistence);
    const checked = await validator.validate(raw, context, TENANT);
    expect(checked.violations).toEqual([]);
    expect(raw.steps.some((s: any) => s.action === "ACT-KILL-PROCESS" && s.condition)).toBe(true);
    expect(raw.steps.some((s: any) => s.action === "ACT-ISOLATE-ENDPOINT" && s.condition)).toBe(true);
    expect(raw.steps.some((s: any) => s.action === "ACT-BLOCK-SOURCE-IP")).toBe(false);
    expect(checked.steps.filter(s => s.stepType === "CHECK").length).toBeGreaterThanOrEqual(3);
    expect(checked.steps.find(s => s.stepType === "MANUAL")).toMatchObject({ actionId: null, sourceRunbookId: null, requiresApproval: true });
    expect(checked.steps.find(s => s.stepType === "MANUAL")!.precondition).toMatch(/confirmed/);
  });
  it("rejects omitted persistence control and missing manual condition", async () => {
    const { context, raw } = await candidate(persistence);
    const manual = raw.steps.find((s: any) => s.type === "MANUAL");
    manual.condition = null;
    expect((await validator.validate(raw, context, TENANT)).violations.join("\n")).toContain("CONDITION_MISSING");
    raw.steps = raw.steps.filter((s: any) => s.type !== "MANUAL").map((s: any, i: number) => ({ ...s, stepOrder: i + 1 }));
    expect((await validator.validate(raw, context, TENANT)).violations.join("\n")).toContain("PROCEDURE_REQUIREMENT_MISSING");
  });
  it("rejects controls before the checks that inform them", async () => {
    const { context, raw } = await candidate(persistence);
    raw.steps.reverse();
    raw.steps.forEach((s: any, i: number) => { s.stepOrder = i + 1; });
    expect((await validator.validate(raw, context, TENANT)).violations.join("\n")).toContain("UNGROUNDED_STEP");
  });
});
