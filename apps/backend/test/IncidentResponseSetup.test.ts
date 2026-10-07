import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { CreatePolicyUseCase } from "../src/application/policy/use-cases/CreatePolicy.usecase";
import { UpdatePolicyUseCase } from "../src/application/policy/use-cases/UpdatePolicy.usecase";
import { EnablePolicyUseCase } from "../src/application/policy/use-cases/EnablePolicy.usecase";
import { createPolicySchema } from "../src/application/policy/dto/CreatePolicyDto";
import { IncidentResponseSetupService, groupPolicyCode } from "../src/application/incident/services/IncidentResponseSetupService";
import { CaseGuidance } from "../src/application/incident/ports/IIncidentResponseSetupStore";
import { RecommendationContextBuilder } from "../src/application/recommendation/services/RecommendationContextBuilder";
import { RecommendationPromptBuilder } from "../src/infrastructure/ai/RecommendationPromptBuilder";

/** SOC response setup before a Recommendation: incident type, group (RESPONSE_GUIDANCE policy) and case guidance. */
const T = "t";
const playbook = (code: string, incidentType: string, mitreTechniques: string[], allowedActions: string[]) => ({
  id: code, code, name: code, version: "1.0", status: "ACTIVE", steps: [],
  triggerConditions: { scope: "INCIDENT", incidentType, mitreTechniques, allowedActions },
});
const action = (code: string, category = "CONTAINMENT", enabled = true) => ({ id: `a-${code}`, code, name: `Action ${code}`, description: null, category, enabled, impactLevel: "MEDIUM", runbookId: null, defaultApprovalRequired: false });
const PLAYBOOKS = [
  playbook("PB-POWERSHELL", "POWERSHELL", ["T1059.001"], ["ISOLATE_HOST", "KILL_PROCESS", "DISABLE_ACCOUNT", "OLD_DISABLED"]),
  playbook("PB-SSH-BRUTEFORCE", "SSH_BRUTE_FORCE", ["T1110"], ["BLOCK_IP", "DISABLE_ACCOUNT"]),
];
const ACTIONS = [action("ISOLATE_HOST"), action("KILL_PROCESS"), action("DISABLE_ACCOUNT"), action("BLOCK_IP"), action("OLD_DISABLED", "CONTAINMENT", false)];

function world(opts: { techniques?: string[]; severity?: string; status?: string } = {}) {
  const incident = { severity: opts.severity ?? "high", status: opts.status ?? "investigating", incidentType: null as string | null, guidance: null as CaseGuidance | null };
  const store = {
    get: async (id: string) => (id === "inc" ? { ...incident } : null),
    setIncidentType: async (_: string, __: string, t: string | null) => void (incident.incidentType = t),
    setGuidance: async (_: string, __: string, g: CaseGuidance | null) => void (incident.guidance = g),
  };
  const policies: Policy[] = [];
  const policyRepo = {
    findAllEnabled: async () => policies.filter((p) => p.enabled),
    findByCode: async (code: string) => policies.find((p) => p.code === code) ?? null,
    findById: async (id: string) => policies.find((p) => p.id === id) ?? null,
    create: async (input: { code: string; name: string; description: string | null; type: string; precedence: number; rules: { condition: unknown; result: unknown }[] }) => {
      const id = `pol-${policies.length}`;
      const p = Policy.create({
        id, tenantId: T, code: input.code, name: input.name, description: input.description, type: input.type as never, enabled: true, version: 1, precedence: input.precedence, createdAt: new Date(), updatedAt: new Date(),
        rules: input.rules.map((r, j) => PolicyRule.create({ id: `${id}-r${j}`, policyId: id, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })),
      });
      policies.push(p);
      return p;
    },
    update: async (id: string, _t: string, input: { rules?: { condition: unknown; result: unknown }[] }) => {
      const i = policies.findIndex((p) => p.id === id);
      const old = policies[i];
      policies[i] = Policy.create({
        id, tenantId: T, code: old.code, name: old.name, description: null, type: old.type, enabled: old.enabled, version: 2, precedence: 0, createdAt: new Date(), updatedAt: new Date(),
        rules: (input.rules ?? []).map((r, j) => PolicyRule.create({ id: `${id}-v2-r${j}`, policyId: id, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })),
      });
      return policies[i];
    },
    setEnabled: async (id: string) => policies.find((p) => p.id === id)!,
  };
  const policyAudit = { record: async () => {} };
  const audit: { action: string; metadata?: Record<string, unknown> }[] = [];
  const evaluator = new PolicyEvaluator(policyRepo as never);
  const svc = new IncidentResponseSetupService(
    store,
    { getMitreMappings: async () => (opts.techniques ?? ["T1059.001"]).map((techniqueId) => ({ techniqueId, tactic: "", confidence: null })) } as never,
    { findAlerts: async () => [] } as never,
    { findAll: async () => PLAYBOOKS } as never,
    { findAll: async () => ACTIONS } as never,
    evaluator,
    { record: async (e: { action: string; metadata?: Record<string, unknown> }) => void audit.push(e) },
    {
      repository: policyRepo as never,
      create: new CreatePolicyUseCase(policyRepo as never, policyAudit as never),
      update: new UpdatePolicyUseCase(policyRepo as never, policyAudit as never),
      enable: new EnablePolicyUseCase(policyRepo as never, policyAudit as never),
    }
  );
  return { svc, incident, policies, audit, evaluator };
}
const input = { tenantId: T, incidentId: "inc", actor: "soc-1" };

describe("incident type", () => {
  it("detected from MITRE; the playbook default allows its enabled CONTAINMENT actions", async () => {
    const s = (await world().svc.get("inc", T)).value;
    expect(s).toMatchObject({ severity: "HIGH", detectedType: "POWERSHELL", incidentType: "POWERSHELL", typeSource: "MITRE", group: { incidentType: "POWERSHELL", severity: "HIGH", allowedActions: null } });
    expect(s.types.map((t) => t.incidentType)).toEqual(["POWERSHELL", "SSH_BRUTE_FORCE"]);
    expect(s.playbook?.actions.map((a) => a.code)).toEqual(["ISOLATE_HOST", "KILL_PROCESS", "DISABLE_ACCOUNT"]);
    expect(s.effective).toEqual({ allowedActions: ["ISOLATE_HOST", "KILL_PROCESS", "DISABLE_ACCOUNT"], instructions: null, source: "PLAYBOOK" });
  });

  it("the SOC changes the type -> that playbook, audited; an unknown type is refused; null goes back to MITRE", async () => {
    const w = world();
    const r = (await w.svc.setIncidentType({ ...input, incidentType: "SSH_BRUTE_FORCE" })).value;
    expect(r).toMatchObject({ incidentType: "SSH_BRUTE_FORCE", typeSource: "SOC", detectedType: "POWERSHELL", playbook: { code: "PB-SSH-BRUTEFORCE" } });
    expect(w.audit[0]).toMatchObject({ action: "INCIDENT_TYPE_SET", metadata: { previous: "POWERSHELL", incidentType: "SSH_BRUTE_FORCE", source: "SOC" } });
    expect((await w.svc.setIncidentType({ ...input, incidentType: "NOPE" })).error).toBe("UNKNOWN_INCIDENT_TYPE");
    expect((await w.svc.setIncidentType({ ...input, incidentType: null })).value).toMatchObject({ incidentType: "POWERSHELL", typeSource: "MITRE" });
  });

  it("no technique matches -> no type, no playbook; guidance cannot be set", async () => {
    const w = world({ techniques: [] });
    expect((await w.svc.get("inc", T)).value).toMatchObject({ incidentType: null, typeSource: null, playbook: null, group: null, effective: { allowedActions: [], source: "PLAYBOOK" } });
    expect((await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: ["ISOLATE_HOST"], instructions: null } })).error).toBe("NO_PLAYBOOK");
  });

  it("a closed incident cannot be changed", async () => {
    expect((await world({ status: "resolved" }).svc.setIncidentType({ ...input, incidentType: "POWERSHELL" })).error).toBe("INCIDENT_CLOSED");
  });
});

describe("group guidance (RESPONSE_GUIDANCE policy) and case guidance", () => {
  it("group: saved as an audited Policy for type + severity; applies with its instruction", async () => {
    const w = world();
    const r = (await w.svc.saveGroupGuidance({ ...input, allowedActions: ["ISOLATE_HOST", "KILL_PROCESS"], note: "Isolate before killing the process" })).value;
    expect(w.policies).toHaveLength(1);
    expect(w.policies[0]).toMatchObject({ code: "RG-POWERSHELL-HIGH", type: "RESPONSE_GUIDANCE" });
    expect(r.group).toMatchObject({ policies: ["RG-POWERSHELL-HIGH"], allowedActions: ["ISOLATE_HOST", "KILL_PROCESS"], notes: ["Isolate before killing the process"] });
    expect(r.effective).toEqual({ allowedActions: ["ISOLATE_HOST", "KILL_PROCESS"], instructions: "Isolate before killing the process", source: "GROUP" });
    // Saving again updates the same policy (no duplicate).
    await w.svc.saveGroupGuidance({ ...input, allowedActions: ["ISOLATE_HOST"], note: null });
    expect(w.policies).toHaveLength(1);
    expect((await w.svc.get("inc", T)).value.effective).toEqual({ allowedActions: ["ISOLATE_HOST"], instructions: null, source: "GROUP" });
  });

  it("group policy only matches its own type AND severity", async () => {
    const w = world();
    await w.svc.saveGroupGuidance({ ...input, allowedActions: ["ISOLATE_HOST"], note: "x" });
    expect(await w.evaluator.responseGuidance(T, { incidentType: "POWERSHELL", severity: "MEDIUM" })).toEqual({ allowedActions: null, notes: [], policies: [] });
    expect(await w.evaluator.responseGuidance(T, { incidentType: "SSH_BRUTE_FORCE", severity: "HIGH" })).toEqual({ allowedActions: null, notes: [], policies: [] });
  });

  it("case guidance overrides the group; clearing it returns to the group", async () => {
    const w = world();
    await w.svc.saveGroupGuidance({ ...input, allowedActions: ["ISOLATE_HOST", "KILL_PROCESS"], note: "group note" });
    const c = (await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: ["DISABLE_ACCOUNT"], instructions: "  Only the account — host is a server  " } })).value;
    expect(c.effective).toEqual({ allowedActions: ["DISABLE_ACCOUNT"], instructions: "Only the account — host is a server", source: "CASE" });
    expect(c.caseGuidance).toMatchObject({ allowedActions: ["DISABLE_ACCOUNT"], setBy: "soc-1" });
    expect(w.audit.map((a) => a.action)).toContain("RESPONSE_GUIDANCE_SET");
    const cleared = (await w.svc.setCaseGuidance({ ...input, guidance: null })).value;
    expect(cleared.effective.source).toBe("GROUP");
    expect(w.audit.map((a) => a.action)).toContain("RESPONSE_GUIDANCE_CLEARED");
  });

  it("only the playbook's actions can be chosen, and at least one", async () => {
    const w = world();
    expect((await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: ["BLOCK_IP"], instructions: null } })).error).toBe("ACTION_NOT_IN_PLAYBOOK");
    expect((await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: ["OLD_DISABLED"], instructions: null } })).error).toBe("ACTION_NOT_IN_PLAYBOOK");
    expect((await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: [], instructions: null } })).error).toBe("NO_ACTION_SELECTED");
    expect((await w.svc.saveGroupGuidance({ ...input, allowedActions: ["BLOCK_IP"], note: null })).error).toBe("ACTION_NOT_IN_PLAYBOOK");
  });

  it("changing the type clears the case guidance (it named the old playbook's actions)", async () => {
    const w = world();
    await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: ["KILL_PROCESS"], instructions: null } });
    const r = (await w.svc.setIncidentType({ ...input, incidentType: "SSH_BRUTE_FORCE" })).value;
    expect(r.caseGuidance).toBeNull();
    expect(r.effective).toEqual({ allowedActions: ["BLOCK_IP", "DISABLE_ACCOUNT"], instructions: null, source: "PLAYBOOK" });
  });

  it("group policy code and schema accept the new fields", () => {
    expect(groupPolicyCode("SSH_BRUTE_FORCE", "CRITICAL")).toBe("RG-SSH-BRUTE-FORCE-CRITICAL");
    const parsed = createPolicySchema.safeParse({
      code: "RG-X-HIGH", name: "x", type: "RESPONSE_GUIDANCE",
      rules: [{ condition: { all: [{ field: "incidentType", operator: "eq", value: "X" }, { field: "severity", operator: "eq", value: "HIGH" }] }, result: { allowedActions: ["A"], guidanceNote: "n" } }],
    });
    expect(parsed.success).toBe(true);
  });
});

describe("Recommendation follows the setup", () => {
  it("only the guided actions are offered; the SOC instruction reaches the prompt", async () => {
    const w = world();
    await w.svc.setCaseGuidance({ ...input, guidance: { allowedActions: ["ISOLATE_HOST"], instructions: "Do not reboot the host" } });
    const ctxRepo = {
      getIncidentContext: async () => ({ incidentId: "inc", investigationNumber: 1, title: "t", status: "investigating", priority: "high", alertSeverity: "high" }),
      getIocs: async () => [], getMitreMappings: async () => [{ techniqueId: "T1059.001", tactic: "execution", confidence: 1 }], getEvidence: async () => [], getLatestAiAnalysis: async () => null,
    };
    const builder = new RecommendationContextBuilder(ctxRepo as never, { findAll: async () => ACTIONS } as never, { findAll: async () => [] } as never, { findAll: async () => PLAYBOOKS } as never, undefined, undefined, w.svc);
    const ctx = (await builder.build("inc", T)).value;
    expect(ctx.playbook).toMatchObject({ code: "PB-POWERSHELL", allowedActions: ["ISOLATE_HOST"] });
    expect(ctx.actionProcedures?.map((p) => p.actionCode)).toEqual(["ISOLATE_HOST"]);
    expect(ctx.socGuidance).toEqual({ source: "CASE", allowedActions: ["ISOLATE_HOST"], instructions: "Do not reboot the host" });
    const prompt = new RecommendationPromptBuilder().build(ctx);
    expect(prompt).toContain("SOC response guidance (set by the SOC for this incident)");
    expect(prompt).toContain("Instruction: Do not reboot the host");
  });

  it("the SOC-chosen type picks the playbook even when MITRE points elsewhere", async () => {
    const w = world();
    await w.svc.setIncidentType({ ...input, incidentType: "SSH_BRUTE_FORCE" });
    const ctxRepo = {
      getIncidentContext: async () => ({ incidentId: "inc", investigationNumber: 1, title: "t", status: "investigating", priority: "high", alertSeverity: "high" }),
      getIocs: async () => [], getMitreMappings: async () => [{ techniqueId: "T1059.001", tactic: "", confidence: 1 }], getEvidence: async () => [], getLatestAiAnalysis: async () => null,
    };
    const builder = new RecommendationContextBuilder(ctxRepo as never, { findAll: async () => ACTIONS } as never, { findAll: async () => [] } as never, { findAll: async () => PLAYBOOKS } as never, undefined, undefined, w.svc);
    const ctx = (await builder.build("inc", T)).value;
    expect(ctx.incidentType).toBe("SSH_BRUTE_FORCE");
    expect(ctx.actionProcedures?.map((p) => p.actionCode)).toEqual(["BLOCK_IP", "DISABLE_ACCOUNT"]);
    // Default playbook guidance adds nothing to the prompt.
    expect(new RecommendationPromptBuilder().build(ctx)).not.toContain("SOC response guidance");
  });
});
