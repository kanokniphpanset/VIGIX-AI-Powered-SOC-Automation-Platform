import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IPolicyRepository } from "../../../domain/policy/repositories/IPolicyRepository";
import { Severity } from "../../../domain/policy/entities/PolicyEvaluationTypes";
import { summarizeAlert } from "../../../domain/alert/alertSummary";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { PlaybookSelector, SelectedPlaybook } from "../../recommendation/services/PlaybookSelector";
import { CaseGuidance, IIncidentResponseSetupStore } from "../ports/IIncidentResponseSetupStore";
import type { PolicyEvaluator } from "../../../infrastructure/policy-engine/PolicyEvaluator";
import type { CreatePolicyUseCase } from "../../policy/use-cases/CreatePolicy.usecase";
import type { UpdatePolicyUseCase } from "../../policy/use-cases/UpdatePolicy.usecase";
import type { EnablePolicyUseCase } from "../../policy/use-cases/EnablePolicy.usecase";
import { Result } from "../../../shared/result/Result";

export type GuidanceSource = "CASE" | "GROUP" | "PLAYBOOK";

export interface ResponseSetup {
  /** Incident severity (the group key together with the type). */
  severity: Severity;
  /** Type detected from MITRE techniques (incident mappings + the alerts' Wazuh techniques). */
  detectedType: string | null;
  /** Type in effect: the SOC's choice, else the detected one. */
  incidentType: string | null;
  typeSource: "SOC" | "MITRE" | null;
  /** Types the SOC can choose (one per incident-level playbook). */
  types: { incidentType: string; playbookCode: string; playbookName: string }[];
  playbook: { code: string; name: string; version: string; matchedTechniques: string[]; actions: { code: string; name: string; impactLevel: string }[] } | null;
  /** The group's RESPONSE_GUIDANCE policy result (null when the incident has no type yet). */
  group: { incidentType: string; severity: Severity; policies: string[]; allowedActions: string[] | null; notes: string[] } | null;
  caseGuidance: CaseGuidance | null;
  /** What a Recommendation must follow now. */
  effective: { allowedActions: string[]; instructions: string | null; source: GuidanceSource };
}

export type ResponseSetupError = "INCIDENT_NOT_FOUND" | "INCIDENT_CLOSED" | "UNKNOWN_INCIDENT_TYPE" | "NO_PLAYBOOK" | "ACTION_NOT_IN_PLAYBOOK" | "NO_ACTION_SELECTED";

const CLOSED = ["resolved", "dismissed"];
const toSeverity = (v: string): Severity => (["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(v.toUpperCase()) ? (v.toUpperCase() as Severity) : "MEDIUM");
/** RESPONSE_GUIDANCE policy code of a group, e.g. POWERSHELL + HIGH -> RG-POWERSHELL-HIGH. */
export const groupPolicyCode = (incidentType: string, severity: Severity) => `RG-${incidentType.toUpperCase().replace(/[^A-Z0-9]+/g, "-")}-${severity}`;

/**
 * IncidentResponseSetupService — the SOC's response setup for one incident, before a Recommendation:
 *   1. incident type: the SOC confirms or changes the type detected from MITRE (one per incident-level playbook);
 *      the type + severity form the incident's group (e.g. POWERSHELL · HIGH);
 *   2. group guidance: a RESPONSE_GUIDANCE Policy per group (which playbook actions, an instruction) — saved through
 *      the audited Policy use cases and applied to every incident of that group;
 *   3. case guidance: this incident only, overriding the group's.
 * Precedence: case > group > playbook default (all its actions). Actions are always limited to the playbook's
 * enabled CONTAINMENT actions — the same list RecommendationContextBuilder offers the AI.
 */
export class IncidentResponseSetupService {
  private readonly selector = new PlaybookSelector();

  constructor(
    private readonly store: IIncidentResponseSetupStore,
    private readonly context: IRecommendationContextRepository,
    private readonly incidents: IIncidentRepository,
    private readonly playbooks: IPlaybookRepository,
    private readonly actions: IActionRepository,
    private readonly policy: Pick<PolicyEvaluator, "responseGuidance">,
    private readonly auditLogger: { record(input: { tenantId: string; actor: string; action: string; entity: string; entityId: string; metadata?: Record<string, unknown> }): Promise<void> },
    private readonly policies?: {
      repository: Pick<IPolicyRepository, "findByCode">;
      create: Pick<CreatePolicyUseCase, "execute">;
      update: Pick<UpdatePolicyUseCase, "execute">;
      enable: Pick<EnablePolicyUseCase, "execute">;
    }
  ) {}

  /** The selected playbook (SOC type first, else the MITRE match) — also used by RecommendationContextBuilder. */
  async resolve(incidentId: string, tenantId: string): Promise<Result<ResponseSetup & { selected: SelectedPlaybook | null }, "INCIDENT_NOT_FOUND">> {
    const incident = await this.store.get(incidentId, tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    const [mappings, alerts, playbooks, actions] = await Promise.all([
      this.context.getMitreMappings(incidentId),
      this.incidents.findAlerts(incidentId, tenantId),
      this.playbooks.findAll(tenantId),
      this.actions.findAll(tenantId),
    ]);
    const alertTechniques = alerts.flatMap((a) => summarizeAlert(a.rawPayload).mitreTechniques);
    const techniques = [...new Set([...mappings.map((m) => m.techniqueId), ...alertTechniques])];
    const detected = this.selector.select(playbooks, techniques, alertTechniques);
    const chosen = incident.incidentType ? this.selector.selectByType(playbooks, incident.incidentType, techniques) : null;
    const selected = chosen ?? detected;
    const severity = toSeverity(incident.severity);

    const playbookActions = (selected?.allowedActions ?? [])
      .map((code) => actions.find((a) => a.code === code && a.enabled && a.category === "CONTAINMENT"))
      .filter((a): a is NonNullable<typeof a> => !!a)
      .map((a) => ({ code: a.code, name: a.name, impactLevel: a.impactLevel }));
    const inPlaybook = (codes: string[]) => codes.filter((c) => playbookActions.some((a) => a.code === c));

    const group = selected
      ? { incidentType: selected.incidentType, severity, ...(await this.policy.responseGuidance(tenantId, { incidentType: selected.incidentType, severity })) }
      : null;
    const caseGuidance = incident.guidance;

    let effective: ResponseSetup["effective"];
    if (caseGuidance) effective = { allowedActions: inPlaybook(caseGuidance.allowedActions), instructions: caseGuidance.instructions, source: "CASE" };
    else if (group && (group.allowedActions !== null || group.notes.length))
      effective = { allowedActions: group.allowedActions === null ? playbookActions.map((a) => a.code) : inPlaybook(group.allowedActions), instructions: group.notes.join("\n") || null, source: "GROUP" };
    else effective = { allowedActions: playbookActions.map((a) => a.code), instructions: null, source: "PLAYBOOK" };

    return Result.ok({
      severity,
      detectedType: detected?.incidentType ?? null,
      incidentType: selected?.incidentType ?? null,
      typeSource: chosen ? "SOC" : detected ? "MITRE" : null,
      types: this.selector.incidentPlaybooks(playbooks).map((p) => ({ incidentType: String(p.triggerConditions.incidentType), playbookCode: String(p.code), playbookName: p.name })),
      playbook: selected ? { code: selected.code, name: selected.name, version: selected.version, matchedTechniques: selected.matchedTechniques, actions: playbookActions } : null,
      group: group ? { incidentType: group.incidentType, severity: group.severity, policies: group.policies, allowedActions: group.allowedActions, notes: group.notes } : null,
      caseGuidance,
      effective,
      selected,
    });
  }

  async get(incidentId: string, tenantId: string): Promise<Result<ResponseSetup, "INCIDENT_NOT_FOUND">> {
    const r = await this.resolve(incidentId, tenantId);
    if (r.isFailure) return Result.fail(r.error);
    const { selected: _selected, ...setup } = r.value;
    return Result.ok(setup);
  }

  /** SOC confirms / changes the type (null = back to the MITRE detection). A changed type clears the case guidance. */
  async setIncidentType(input: { tenantId: string; incidentId: string; actor: string; incidentType: string | null }): Promise<Result<ResponseSetup, ResponseSetupError>> {
    const incident = await this.store.get(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    if (CLOSED.includes(incident.status)) return Result.fail("INCIDENT_CLOSED");
    if (input.incidentType) {
      const types = this.selector.incidentPlaybooks(await this.playbooks.findAll(input.tenantId)).map((p) => p.triggerConditions.incidentType);
      if (!types.includes(input.incidentType)) return Result.fail("UNKNOWN_INCIDENT_TYPE");
    }
    const before = await this.get(input.incidentId, input.tenantId);
    const previous = before.isSuccess ? before.value.incidentType : null;
    await this.store.setIncidentType(input.incidentId, input.tenantId, input.incidentType);
    const after = await this.get(input.incidentId, input.tenantId);
    if (after.isFailure) return Result.fail(after.error);
    if (incident.guidance && after.value.incidentType !== previous) await this.store.setGuidance(input.incidentId, input.tenantId, null);
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "INCIDENT_TYPE_SET",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: { previous, incidentType: after.value.incidentType, source: after.value.typeSource, detectedType: after.value.detectedType },
    });
    return this.get(input.incidentId, input.tenantId);
  }

  /** Case guidance for this incident (null = clear it: the group / playbook default applies again). */
  async setCaseGuidance(input: { tenantId: string; incidentId: string; actor: string; guidance: { allowedActions: string[]; instructions: string | null } | null }): Promise<Result<ResponseSetup, ResponseSetupError>> {
    const setup = await this.writable(input.incidentId, input.tenantId);
    if (setup.isFailure) return Result.fail(setup.error);
    let guidance: CaseGuidance | null = null;
    if (input.guidance) {
      const invalid = this.checkActions(setup.value, input.guidance.allowedActions);
      if (invalid) return Result.fail(invalid);
      guidance = { allowedActions: [...new Set(input.guidance.allowedActions)], instructions: input.guidance.instructions?.trim() || null, setBy: input.actor, setAt: new Date().toISOString() };
    }
    await this.store.setGuidance(input.incidentId, input.tenantId, guidance);
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: guidance ? "RESPONSE_GUIDANCE_SET" : "RESPONSE_GUIDANCE_CLEARED",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: { scope: "CASE", incidentType: setup.value.incidentType, severity: setup.value.severity, allowedActions: guidance?.allowedActions ?? null, instructions: guidance?.instructions ?? null },
    });
    return this.get(input.incidentId, input.tenantId);
  }

  /**
   * Group guidance: create or update the RESPONSE_GUIDANCE policy of this incident's group (type + severity) through
   * the audited Policy use cases. It applies to every incident of the group that has no case guidance.
   */
  async saveGroupGuidance(input: { tenantId: string; incidentId: string; actor: string; allowedActions: string[]; note: string | null }): Promise<Result<ResponseSetup, ResponseSetupError>> {
    if (!this.policies) throw new Error("Policy use cases are not wired");
    const setup = await this.writable(input.incidentId, input.tenantId);
    if (setup.isFailure) return Result.fail(setup.error);
    const invalid = this.checkActions(setup.value, input.allowedActions);
    if (invalid) return Result.fail(invalid);
    const type = setup.value.incidentType!;
    const severity = setup.value.severity;
    const code = groupPolicyCode(type, severity);
    const note = input.note?.trim() || undefined;
    const rules = [
      {
        condition: { all: [{ field: "incidentType", operator: "eq", value: type }, { field: "severity", operator: "eq", value: severity }] },
        result: { allowedActions: [...new Set(input.allowedActions)], ...(note ? { guidanceNote: note } : {}) },
      },
    ] as never;
    const existing = await this.policies.repository.findByCode(code, input.tenantId);
    if (existing) {
      await this.policies.update.execute({ id: existing.id, tenantId: input.tenantId, actor: input.actor, rules } as never);
      if (!existing.enabled) await this.policies.enable.execute({ id: existing.id, tenantId: input.tenantId, actor: input.actor } as never);
    } else {
      await this.policies.create.execute({
        tenantId: input.tenantId,
        actor: input.actor,
        code,
        name: `Response guidance ${type} · ${severity}`,
        description: `SOC response guidance for ${type} incidents of ${severity} severity (set from incident ${input.incidentId}).`,
        type: "RESPONSE_GUIDANCE",
        precedence: 0,
        rules,
      } as never);
    }
    return this.get(input.incidentId, input.tenantId);
  }

  private async writable(incidentId: string, tenantId: string): Promise<Result<ResponseSetup, ResponseSetupError>> {
    const incident = await this.store.get(incidentId, tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    if (CLOSED.includes(incident.status)) return Result.fail("INCIDENT_CLOSED");
    const setup = await this.get(incidentId, tenantId);
    if (setup.isFailure) return Result.fail(setup.error);
    if (!setup.value.playbook || !setup.value.incidentType) return Result.fail("NO_PLAYBOOK");
    return Result.ok(setup.value);
  }

  private checkActions(setup: ResponseSetup, codes: string[]): ResponseSetupError | null {
    if (!codes.length) return "NO_ACTION_SELECTED";
    const allowed = new Set(setup.playbook?.actions.map((a) => a.code) ?? []);
    return codes.every((c) => allowed.has(c)) ? null : "ACTION_NOT_IN_PLAYBOOK";
  }
}
