import { randomUUID } from "node:crypto";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { NormalizedAlertInput } from "../../../infrastructure/external-services/siem/ISiemAdapter";
import { AiAnalysisJob, AiJobTrigger } from "../../agent-orchestration/ports/IAiAnalysisJobRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";
import { autoIncidentBySeverity, inSocWorkflow } from "../../../domain/alert/triageWorkflow";
import { summarizeAlert } from "../../../domain/alert/alertSummary";
import type { CreateIncidentUseCase } from "../../incident/use-cases/CreateIncident.usecase";
import type { IncidentPriority } from "../../../domain/incident/entities/Incident.entity";
import { MergeBlockedError } from "../../../domain/incident/repositories/IIncidentRepository";
import type { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { CorrelationCandidate, CorrelationMatch, CorrelationReason, findCorrelatedIncident } from "../../../domain/alert/alertCorrelation";

export interface IngestAlertFromSiemInput extends NormalizedAlertInput {
  tenantId: string;
}

/** The queue side ingestion needs (AiAnalysisJobService implements it). */
export interface IAiAnalysisJobQueue {
  enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: AiJobTrigger }): Promise<AiAnalysisJob>;
  latestForIncident(incidentId: string): Promise<AiAnalysisJob | null>;
}

/** Policy INTAKE evaluation (PolicyEvaluator): whether an ingested alert opens an incident automatically (HIGH / CRITICAL). */
export interface IIncidentIntakePolicy {
  evaluate(input: { tenantId: string; severity: string }): Promise<{ autoCreateIncident: boolean; matchedPolicies: string[] }>;
}

/** Open incidents (open / investigating) that may hold activity related to the alert (alertCorrelation.ts decides). */
export interface IIncidentCorrelationReader {
  openCandidates(input: { tenantId: string; alertId: string; rawPayload: unknown; receivedAt: Date }): Promise<CorrelationCandidate[]>;
}

/** Automatic alert correlation: a related alert joins the open incident instead of opening a second one. */
export interface AlertCorrelationDeps {
  reader: IIncidentCorrelationReader;
  investigations: Pick<IInvestigationRepository, "syncIncident">;
}

export interface IngestAlertFromSiemOutput {
  alert: Alert;
  /** The incident the alert belongs to: opened automatically (HIGH / CRITICAL) or, for a duplicate, the existing one. */
  incidentId: string | null;
  /** That incident's latest AI analysis job (queued by incident creation). */
  aiJob: { id: string; status: string } | null;
  /** True when this exact SIEM alert (same source + external id) was already ingested — nothing new was created. */
  duplicate: boolean;
  /** True when the new alert waits in the Alert Inbox for SOC review (MEDIUM, or HIGH / CRITICAL whose incident failed). */
  triageRequired: boolean;
  /** Set when the alert joined an already-open incident (automatic correlation) instead of opening its own. */
  correlation?: { incidentId: string; reasons: CorrelationReason[]; sharedIocs: string[] };
}

const INGEST_ACTOR = "vigix-ingest";

/**
 * Ingestion step (automatic, no human): Wazuh alert (idempotent per SIEM source + external alert id), severity from the
 * deterministic Wazuh rule-level mapping (never from AI):
 *   LOW              stored only — never enters the SOC workflow (audit ALERT_OUTSIDE_SOC_WORKFLOW)
 *   MEDIUM           Alert Inbox -> SOC review (close, or create an incident)      (audit ALERT_ROUTED_TO_TRIAGE)
 *   HIGH / CRITICAL  an incident is opened automatically (Policy INTAKE RULE-I03/I04; when Policy is unavailable the
 *                    same deterministic severity rule applies) with the alert's severity; CreateIncidentUseCase queues
 *                    the AI analysis and notifies the SOC (audit ALERT_ESCALATED_TO_INCIDENT, trigger AUTOMATIC).
 *                    If the incident cannot be opened, the alert stays in the Alert Inbox for the SOC.
 *                    Correlation first: when the alert is evidently part of an incident that is still open (shared
 *                    indicator, same attacker IP, same host + technique / rule — domain/alert/alertCorrelation.ts),
 *                    it joins that incident (WAZUH_ALERT evidence + IOCs of Investigation #1, so the next
 *                    recommendation and every re-hunt include its indicators) instead of opening a second one
 *                    (audit ALERT_CORRELATED_TO_INCIDENT). A correlation failure falls back to a new incident.
 * Nothing here recommends, approves, executes or emails.
 */
export class IngestAlertFromSiemUseCase {
  constructor(
    private readonly alertRepository: IAlertRepository,
    private readonly incidentRepository: IIncidentRepository,
    private readonly aiJobs: IAiAnalysisJobQueue,
    private readonly auditLogger?: AuditLogger,
    private readonly intakePolicy?: IIncidentIntakePolicy,
    private readonly createIncident?: Pick<CreateIncidentUseCase, "execute">,
    private readonly correlation?: AlertCorrelationDeps
  ) {}

  async execute(input: IngestAlertFromSiemInput): Promise<Result<IngestAlertFromSiemOutput>> {
    // Idempotency: the same SIEM alert delivered again (retry, replay) returns what already exists.
    const existing = await this.alertRepository.findByExternalId(input.siemSource, input.externalAlertId, input.tenantId);
    if (existing.length > 0) {
      const linked = await this.incidentRepository.findLinkedIncidents(existing.map((a) => a.id), input.tenantId);
      const alert = existing.find((a) => linked.has(a.id)) ?? existing[0];
      const incidentId = linked.get(alert.id) ?? null;
      const job = incidentId ? await this.aiJobs.latestForIncident(incidentId) : null;
      return Result.ok({ alert, incidentId, aiJob: job ? { id: job.id, status: job.status } : null, duplicate: true, triageRequired: false });
    }

    const saved = await this.alertRepository.save(
      Alert.create({
        id: randomUUID(),
        tenantId: input.tenantId,
        externalAlertId: input.externalAlertId,
        siemSource: input.siemSource,
        rawPayload: input.rawPayload,
        severity: input.severity,
        status: "received",
        receivedAt: input.receivedAt,
        createdAt: new Date(),
      })
    );

    const audit = (action: string, metadata: Record<string, unknown>) =>
      this.auditLogger
        ?.record({ tenantId: saved.tenantId, actor: INGEST_ACTOR, action, entity: "Alert", entityId: saved.id, metadata: { severity: saved.severity, externalAlertId: saved.externalAlertId, siemSource: saved.siemSource, ...metadata } })
        .catch((err) => console.error("Ingestion: audit failed", saved.id, err instanceof Error ? err.message : err));

    if (!inSocWorkflow(saved.severity)) {
      await audit("ALERT_OUTSIDE_SOC_WORKFLOW", { reason: "LOW severity alerts do not enter the SOC workflow" });
      return Result.ok({ alert: saved, incidentId: null, aiJob: null, duplicate: false, triageRequired: false });
    }

    const intake = await this.intakePolicy?.evaluate({ tenantId: saved.tenantId, severity: saved.severity }).catch((err) => {
      console.error("Ingestion: intake policy unavailable (deterministic severity rule applied)", saved.id, err instanceof Error ? err.message : err);
      return null;
    });
    const autoCreate = intake ? intake.autoCreateIncident : autoIncidentBySeverity(saved.severity);
    const matchedPolicies = intake?.matchedPolicies ?? [];

    if (autoCreate && this.correlation) {
      const joined = await this.joinCorrelatedIncident(saved, matchedPolicies, audit);
      if (joined) {
        const job = await this.aiJobs.latestForIncident(joined.incidentId).catch(() => null);
        return Result.ok({
          alert: (await this.alertRepository.findById(saved.id, saved.tenantId)) ?? saved,
          incidentId: joined.incidentId,
          aiJob: job ? { id: job.id, status: job.status } : null,
          duplicate: false,
          triageRequired: false,
          correlation: joined,
        });
      }
    }

    if (autoCreate && this.createIncident) {
      const summary = summarizeAlert(saved.rawPayload);
      const severity = saved.severity.toLowerCase() as IncidentPriority;
      const created = await this.createIncident
        .execute({
          tenantId: saved.tenantId,
          createdBy: INGEST_ACTOR,
          title: (summary.ruleDescription || `Alert ${saved.externalAlertId}`).slice(0, 200),
          priority: severity,
          alertIds: [saved.id],
          note: null,
          timelineDescription: `Incident opened automatically: ${severity.toUpperCase()} Wazuh alert${summary.ruleId ? ` (rule ${summary.ruleId}, level ${summary.ruleLevel ?? "?"})` : ""}${matchedPolicies.length ? ` — Policy ${matchedPolicies.join(", ")}` : " — deterministic severity rule"}.`,
        })
        .catch((err) => {
          console.error("Ingestion: automatic incident failed (alert stays in the Alert Inbox)", saved.id, err instanceof Error ? err.message : err);
          return null;
        });
      if (created?.isSuccess) {
        const incidentId = created.value.id;
        await audit("ALERT_ESCALATED_TO_INCIDENT", { alertId: saved.id, incidentId, trigger: "AUTOMATIC", matchedPolicies, assignedRole: "SOC" });
        const job = await this.aiJobs.latestForIncident(incidentId).catch(() => null);
        return Result.ok({ alert: (await this.alertRepository.findById(saved.id, saved.tenantId)) ?? saved, incidentId, aiJob: job ? { id: job.id, status: job.status } : null, duplicate: false, triageRequired: false });
      }
      await audit("ALERT_ROUTED_TO_TRIAGE", { matchedPolicies, assignedRole: "SOC", autoIncidentFailed: created ? created.error.code : "ERROR" });
      return Result.ok({ alert: saved, incidentId: null, aiJob: null, duplicate: false, triageRequired: true });
    }

    await audit("ALERT_ROUTED_TO_TRIAGE", { matchedPolicies, assignedRole: "SOC" });
    return Result.ok({ alert: saved, incidentId: null, aiJob: null, duplicate: false, triageRequired: true });
  }

  /**
   * Links the alert to the open incident it correlates with (the Set Group repository write: incident_alerts,
   * alert escalated, timeline) and syncs that incident's investigation (evidence + IOCs). Null — the caller opens a
   * new incident — when nothing correlates, the lookup fails, or the incident closed in the meantime.
   */
  private async joinCorrelatedIncident(
    alert: Alert,
    matchedPolicies: string[],
    audit: (action: string, metadata: Record<string, unknown>) => Promise<void> | undefined
  ): Promise<CorrelationMatch | null> {
    const deps = this.correlation!;
    let match: CorrelationMatch | null;
    try {
      const candidates = await deps.reader.openCandidates({ tenantId: alert.tenantId, alertId: alert.id, rawPayload: alert.rawPayload, receivedAt: alert.receivedAt });
      match = findCorrelatedIncident({ rawPayload: alert.rawPayload, receivedAt: alert.receivedAt }, candidates);
    } catch (err) {
      console.error("Ingestion: alert correlation lookup failed (a new incident is opened)", alert.id, err instanceof Error ? err.message : err);
      return null;
    }
    if (!match) return null;

    try {
      await this.incidentRepository.absorbIntoIncident({
        tenantId: alert.tenantId,
        targetIncidentId: match.incidentId,
        sourceIncidentIds: [],
        unlinkedAlertIds: [alert.id],
        actor: INGEST_ACTOR,
        timelineDescription: (externalId) => `Alert ${externalId} correlated into the incident automatically (${match!.reasons.join(", ")}${match!.sharedIocs.length ? `: ${match!.sharedIocs.join(", ")}` : ""}).`,
      });
    } catch (err) {
      if (!(err instanceof MergeBlockedError)) console.error("Ingestion: alert correlation failed (a new incident is opened)", alert.id, err instanceof Error ? err.message : err);
      return null;
    }

    // Evidence + IOCs of the joined alert; the read path syncs again as a fallback.
    await deps.investigations
      .syncIncident(match.incidentId, alert.tenantId)
      .catch((err) => console.error("Ingestion: investigation sync after correlation failed", match!.incidentId, err instanceof Error ? err.message : err));
    await audit("ALERT_CORRELATED_TO_INCIDENT", { alertId: alert.id, incidentId: match.incidentId, reasons: match.reasons, sharedIocs: match.sharedIocs, trigger: "AUTOMATIC", matchedPolicies });
    return match;
  }
}
