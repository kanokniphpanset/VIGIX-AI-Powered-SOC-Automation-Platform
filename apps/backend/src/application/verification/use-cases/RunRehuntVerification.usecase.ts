import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IVerificationRepository } from "../../../domain/verification/repositories/IVerificationRepository";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { Verification } from "../../../domain/verification/entities/Verification.entity";
import { Result } from "../../../shared/result/Result";
import { CreateVerificationUseCase, CreateVerificationError } from "./CreateVerification.usecase";
import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { ISiemRehuntPort, RehuntCorrelationKeys, RehuntError, RehuntIoc, RehuntResult, RehuntRuleSignature } from "../ports/ISiemRehuntPort";
import { REHUNT_IOC_TYPES } from "../../../domain/investigation/alertIocs";
import { DuplicateIocError, IocType } from "../../../domain/investigation/Investigation.types";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";

export type RunRehuntError =
  | CreateVerificationError
  | "REHUNT_NOT_CONFIGURED"
  | "REHUNT_INSUFFICIENT_CRITERIA"
  | "REHUNT_UNREACHABLE"
  | "REHUNT_QUERY_FAILED"
  | "REHUNT_TIMEOUT"
  /** The search could not see everything it needed (coverage / cap / skipped IOC types): "not seen" cannot be claimed. */
  | "REHUNT_INCOMPLETE"
  /** IOC values matched but nothing ties them to the incident: neither "recurred" nor "contained" may be recorded. */
  | "REHUNT_UNCONFIRMED";

export interface RunRehuntOutput {
  verification: Verification;
  evidence: RehuntResult;
}

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const HASH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

/** Pulls the host and detection rule out of the incident's originating alert, for both Wazuh's native shape and simplified payloads. */
export function extractAlertSignature(raw: Record<string, unknown>): { hosts: string[]; agentIds: string[]; rule?: RehuntRuleSignature; correlation: RehuntCorrelationKeys } {
  const agent = raw.agent;
  const agentName = typeof agent === "string" ? agent : (agent as { name?: string } | undefined)?.name;
  const agentId = typeof agent === "object" && agent ? (agent as { id?: unknown }).id : undefined;
  const rule = raw.rule;
  let signature: RehuntRuleSignature | undefined;
  if (typeof rule === "string") {
    signature = { description: rule };
  } else if (rule && typeof rule === "object") {
    const r = rule as { id?: unknown; description?: unknown; groups?: unknown };
    if (r.id !== undefined || r.description !== undefined) {
      const groups = Array.isArray(r.groups) ? r.groups.map((g) => String(g).trim()).filter(Boolean) : [];
      signature = { id: r.id !== undefined ? String(r.id) : undefined, description: typeof r.description === "string" ? r.description : undefined, ...(groups.length ? { groups } : {}) };
    }
  }
  // Identifiers of the original evidence that a later event can be correlated by (an IOC value alone never corroborates).
  const at = (path: string): unknown => path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), raw);
  const text = (v: unknown) => (typeof v === "string" && v.trim() ? v.trim() : null);
  const guid = text(at("data.win.eventdata.processGuid"));
  const path = text(at("syscheck.path")) ?? text(at("data.file"));
  return {
    hosts: agentName ? [agentName] : [],
    agentIds: typeof agentId === "string" || typeof agentId === "number" ? [String(agentId)] : [],
    rule: signature,
    correlation: { processGuids: guid ? [guid] : [], filePaths: path ? [path] : [] },
  };
}

/**
 * RunRehuntVerificationUseCase — builds the re-hunt query from what VIGIX already
 * knows (the incident's alert host + rule, its IOCs, the ticket's target and the
 * time the response completed), asks the SIEM for EVIDENCE, and hands that
 * evidence to CreateVerificationUseCase. It never sets a result itself and
 * accepts none from the caller: CreateVerification derives RESOLVED / NOT_RESOLVED
 * (and Policy decides whether Investigation #2 opens) exactly as for manual entry.
 */
export class RunRehuntVerificationUseCase {
  constructor(
    private readonly rehunt: ISiemRehuntPort,
    private readonly createVerification: CreateVerificationUseCase,
    private readonly incidentRepository: IIncidentRepository,
    private readonly alertRepository: IAlertRepository,
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly verificationRepository: IVerificationRepository,
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly investigations?: IInvestigationRepository,
    private readonly auditLogger?: AuditLogger
  ) {}

  async execute(input: {
    incidentId: string;
    responseId: string;
    tenantId: string;
    verifiedBy: string;
    notes?: string | null;
  }): Promise<Result<RunRehuntOutput, RunRehuntError>> {
    if (!this.rehunt.isConfigured()) return Result.fail("REHUNT_NOT_CONFIGURED");

    const incident = await this.incidentRepository.findById(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");

    const response = await this.responsePlanRepository.findById(input.responseId, input.tenantId);
    if (!response || response.incidentId !== input.incidentId) return Result.fail("RESPONSE_NOT_FOUND");
    if (response.status !== "COMPLETED") return Result.fail("RESPONSE_NOT_COMPLETED");
    const existing = await this.verificationRepository.findAllByIncident(input.incidentId, input.tenantId);
    if (existing.some((v) => v.responseId === response.id)) return Result.fail("ALREADY_VERIFIED");

    const alert = await this.alertRepository.findById(incident.alertId, input.tenantId);
    const signature = alert ? extractAlertSignature(alert.rawPayload) : { hosts: [] as string[], agentIds: [] as string[], rule: undefined, correlation: {} as RehuntCorrelationKeys };

    // Only environment-wide indicators are hunted: host facts (user, process, command line...) would phrase-match
    // benign events and fake a recurrence.
    const iocs: RehuntIoc[] = (await this.contextRepository.getIocs(input.incidentId))
      .filter((i) => REHUNT_IOC_TYPES.includes(i.iocType.toUpperCase()))
      .map((i) => ({ type: i.iocType, value: i.iocValue }));
    const hosts = [...signature.hosts];
    const target = response.target?.trim();
    if (target) {
      // The ticket's target is either an indicator (blocked IP / hash / URL) or a host (isolated endpoint).
      if (IPV4.test(target) || HASH.test(target) || /^https?:\/\//i.test(target)) {
        if (!iocs.some((i) => i.value === target)) iocs.push({ type: IPV4.test(target) ? "ip" : HASH.test(target) ? "hash" : "url", value: target });
      } else if (!hosts.some((h) => h.toLowerCase() === target.toLowerCase())) {
        hosts.push(target);
      }
    }

    // The alert's own endpoint (agent.name / agent.ip) is the victim, not an indicator: hunting it would match the
    // endpoint's normal traffic. Excluded from the search only — the stored IOC records are left untouched.
    const identity = endpointIdentity(alert?.rawPayload);
    const excludedIocs = iocs
      .filter((i) => identity.has(i.value.trim().toLowerCase()))
      .map((i) => ({ type: i.type, value: i.value, reason: "Endpoint identity of the alerting agent (agent.name / agent.ip)" }));
    const huntedIocs = iocs.filter((i) => !identity.has(i.value.trim().toLowerCase()));

    const numberBefore = incident.investigationNumber;
    const start = response.completedAt ?? response.updatedAt;
    const end = new Date();

    await this.auditLogger?.record({
      tenantId: input.tenantId,
      actor: input.verifiedBy,
      action: "REHUNT_STARTED",
      entity: "ResponsePlan",
      entityId: response.id,
      metadata: { incidentId: input.incidentId, investigationNumber: numberBefore, hosts, iocCount: huntedIocs.length, timeRange: { start: start.toISOString(), end: end.toISOString() } },
    });

    let evidence: RehuntResult;
    try {
      evidence = await this.rehunt.rehunt({
        incidentId: input.incidentId,
        responseId: response.id,
        hosts,
        iocs: huntedIocs,
        rule: signature.rule,
        timeRange: { start, end },
        investigationNumber: numberBefore,
        agentIds: signature.agentIds,
        scopeAgents: signature.hosts,
        correlation: signature.correlation,
      });
    } catch (err) {
      // A failed re-hunt proves nothing: no Verification is created, the incident is not touched.
      if (err instanceof RehuntError) {
        const map = {
          NOT_CONFIGURED: "REHUNT_NOT_CONFIGURED",
          INSUFFICIENT_CRITERIA: "REHUNT_INSUFFICIENT_CRITERIA",
          UNREACHABLE: "REHUNT_UNREACHABLE",
          QUERY_FAILED: "REHUNT_QUERY_FAILED",
          TIMEOUT: "REHUNT_TIMEOUT",
        } as const;
        await this.auditLogger?.record({
          tenantId: input.tenantId,
          actor: input.verifiedBy,
          action: "REHUNT_FAILED",
          entity: "ResponsePlan",
          entityId: response.id,
          metadata: { incidentId: input.incidentId, code: err.code, message: err.message, investigationNumber: numberBefore, excludedIocs },
        });
        return Result.fail(map[err.code]);
      }
      throw err;
    }

    // A correlating provider can say it could not decide. Then NO verification is created (same principle as a failed query):
    // recording RESOLVED would claim an absence that was not established, recording NOT_RESOLVED would claim a recurrence that was not.
    if (evidence.classification === "INCOMPLETE" || evidence.classification === "UNCORROBORATED_MATCH") {
      const incomplete = evidence.classification === "INCOMPLETE";
      await this.auditLogger?.record({
        tenantId: input.tenantId,
        actor: input.verifiedBy,
        action: "REHUNT_FAILED",
        entity: "ResponsePlan",
        entityId: response.id,
        metadata: {
          incidentId: input.incidentId,
          code: incomplete ? "INCOMPLETE" : "UNCONFIRMED",
          classification: evidence.classification,
          investigationNumber: numberBefore,
          totalMatched: evidence.totalMatched ?? null,
          gaps: evidence.coverage?.gaps ?? [],
          excludedIocs,
        },
      });
      return Result.fail(incomplete ? "REHUNT_INCOMPLETE" : "REHUNT_UNCONFIRMED");
    }

    // Recurrence evidence must exist in the NEW cycle before its recommendation is generated, so it goes in through
    // CreateVerification's reopen hook. The post-verification call below stays as a fallback for callers whose
    // verification step does not invoke the hook.
    let evidenceRecorded = false;

    const created = await this.createVerification.execute({
      incidentId: input.incidentId,
      tenantId: input.tenantId,
      verifiedBy: input.verifiedBy,
      responseId: response.id,
      wazuhIndex: evidence.index,
      query: evidence.query,
      timeRangeStart: start,
      timeRangeEnd: end,
      matchingEvents: evidence.matchingEvents,
      affectedHosts: evidence.affectedHosts,
      iocRecurrence: evidence.iocRecurrence,
      spreadDetected: evidence.spreadDetected,
      threatContained: evidence.threatContained,
      beforeState: { criteria: { hosts, iocs: huntedIocs, excludedIocs, rule: signature.rule ?? null } },
      afterState: {
        events: evidence.events,
        truncated: evidence.truncated,
        searchedIocs: evidence.searchedIocs ?? huntedIocs,
        skippedIocTypes: evidence.skippedIocTypes ?? [],
        skippedIocs: evidence.skippedIocs ?? [],
        excludedIocs,
        // Phase 2D: why the verdict inputs are what they are (only present for a correlating provider).
        ...(evidence.classification
          ? {
              classification: evidence.classification,
              totalMatched: evidence.totalMatched ?? null,
              ignoredEvents: evidence.ignoredEvents ?? 0,
              correlationReasons: evidence.correlationReasons ?? {},
              coverage: evidence.coverage ?? null,
              pagination: evidence.pagination ?? null,
            }
          : {}),
      },
      notes: input.notes ?? null,
      evidenceSource: evidence.source,
      onInvestigationReopened: async () => {
        await this.recordRecurrenceEvidence(input, numberBefore, null, evidence);
        evidenceRecorded = true;
      },
    });
    if (created.isFailure) return Result.fail(created.error);

    if (!evidenceRecorded) await this.recordRecurrenceEvidence(input, numberBefore, created.value.id, evidence);

    return Result.ok({ verification: created.value, evidence });
  }

  /**
   * If this verification reopened the incident (Investigation #N+1), the events that showed the threat
   * recurring are recorded as system-derived Evidence in that NEW investigation. A failure here never
   * undoes the verification.
   */
  private async recordRecurrenceEvidence(
    input: { incidentId: string; tenantId: string; verifiedBy: string },
    numberBefore: number,
    verificationId: string | null,
    evidence: RehuntResult
  ): Promise<void> {
    if (!this.investigations || evidence.events.length === 0) return;
    try {
      const incident = await this.incidentRepository.findById(input.incidentId, input.tenantId);
      if (!incident || incident.investigationNumber <= numberBefore) return;
      const current = (await this.investigations.listByIncident(input.incidentId, input.tenantId)).find((i) => i.isCurrent);
      if (!current) return;
      for (const e of evidence.events) {
        const ts = new Date(e.timestamp);
        if (Number.isNaN(ts.getTime())) continue;
        const iocIds = await this.carryForwardIocs(input, current.id, e.matchedIocValues ?? [], ts);
        await this.investigations.createEvidence({
          investigationId: current.id,
          alertId: null,
          type: "WAZUH_EVENT",
          source: evidence.source,
          origin: "SYSTEM",
          timestamp: ts,
          title: `Rule ${e.ruleId ?? "?"}: ${e.ruleDescription ?? "event"}`,
          description: verificationId
            ? `Activity found by the post-containment re-hunt (verification ${verificationId}).`
            : "Activity found by the post-containment re-hunt that reopened this investigation.",
          rawData: null,
          structuredData: {
            ruleId: e.ruleId,
            level: e.ruleLevel,
            agent: e.host,
            description: e.ruleDescription,
            timestamp: e.timestamp,
            matchedIoc: e.matchedIoc,
            indexerEventId: e.id,
            // Phase 2D (correlating provider only): the full document reference and why the event was tied to the incident.
            indexerIndex: e.index,
            wazuhAlertId: e.alertId,
            provenanceClass: e.provenanceClass,
            inScope: e.inScope,
            correlationReasons: e.correlation?.reasons,
            verificationId,
          },
          confidence: null,
          relevance: e.matchedIoc ? "HIGH" : "MEDIUM",
          createdBy: input.verifiedBy,
          iocIds,
        });
      }
    } catch (err) {
      console.error("Failed to record re-hunt events as evidence for verification", verificationId, err);
    }
  }

  /**
   * IOCs a re-hunt event provably contained (matchedIocValues) become IOCs of the NEW cycle, so its evidence and
   * recommendation can reference them. A value is only carried when the provider named it; nothing is inferred.
   */
  private async carryForwardIocs(
    input: { incidentId: string; tenantId: string; verifiedBy: string },
    investigationId: string,
    values: string[],
    seenAt: Date
  ): Promise<string[]> {
    if (!this.investigations || values.length === 0) return [];
    const ids: string[] = [];
    for (const value of [...new Set(values)]) {
      const iocType = rehuntIocType(value);
      try {
        const ioc = await this.investigations.createIoc({
          incidentId: input.incidentId,
          investigationId,
          iocType,
          iocValue: iocType === "URL" || iocType === "IPV4" ? value : value.toLowerCase(),
          source: "REHUNT",
          reputationScore: null,
          confidence: null,
          status: "ACTIVE",
          firstSeen: seenAt,
          lastSeen: seenAt,
          createdBy: input.verifiedBy,
        });
        ids.push(ioc.id);
      } catch (err) {
        if (err instanceof DuplicateIocError && err.existingIocId) ids.push(err.existingIocId);
        else throw err;
      }
    }
    return ids;
  }
}

function rehuntIocType(value: string): IocType {
  if (IPV4.test(value)) return "IPV4";
  if (/^[a-f0-9]{32}$/i.test(value)) return "MD5";
  if (/^[a-f0-9]{40}$/i.test(value)) return "SHA1";
  if (/^[a-f0-9]{64}$/i.test(value)) return "SHA256";
  if (/^https?:\/\//i.test(value)) return "URL";
  if (/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(value)) return "DOMAIN";
  return "OTHER";
}

/** Lower-cased agent.name / agent.ip of the alert's own endpoint (whatever of them the raw payload carries). */
function endpointIdentity(rawPayload: unknown): Set<string> {
  const agent = (rawPayload as { agent?: { name?: unknown; ip?: unknown } } | null | undefined)?.agent;
  const values = new Set<string>();
  for (const v of [agent?.name, agent?.ip]) if (typeof v === "string" && v.trim()) values.add(v.trim().toLowerCase());
  return values;
}
