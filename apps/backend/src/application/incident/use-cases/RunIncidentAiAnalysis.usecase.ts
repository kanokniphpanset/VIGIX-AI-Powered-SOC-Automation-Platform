import { Result } from "../../../shared/result/Result";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { AiAnalysisRunnerError, IAiAnalysisRunnerPort } from "../../agent-orchestration/ports/IAiAnalysisRunnerPort";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { GetIncidentAiAnalysisUseCase, IncidentAiAnalysis } from "./GetIncidentAiAnalysis.usecase";

/** Read-only checks the manual run needs before calling the pipeline. */
export interface IAiAnalysisRunGuard {
  /** True when a pipeline execution for this incident is QUEUED or RUNNING and was queued/started after `since`. */
  hasRunningExecution(incidentId: string, since: Date): Promise<boolean>;
  /** Incidents whose primary alert is `alertId` (the pipeline attaches results to that incident). */
  incidentsWithPrimaryAlert(alertId: string, tenantId: string): Promise<string[]>;
}

export type RunIncidentAiAnalysisError =
  | "INCIDENT_NOT_FOUND"
  | "INCIDENT_HAS_NO_ALERT"
  | "ALERT_OWNED_BY_OTHER_INCIDENT"
  | "ANALYSIS_IN_PROGRESS"
  | "AI_UNAVAILABLE"
  | "AI_FAILED"
  /** The pipeline ran but the LLM analysis failed — no AI analysis was produced (reason audited). */
  | "AI_ANALYSIS_FAILED";

export interface RunIncidentAiAnalysisOutput {
  incidentId: string;
  graphRunId: string;
  status: "SUCCESS" | "PARTIAL_SUCCESS";
  rerun: boolean;
  analysis: IncidentAiAnalysis;
}

/** A RUNNING execution older than this is treated as abandoned (e.g. the orchestrator was restarted mid-run). */
const STALE_RUN_MS = 15 * 60_000;

/**
 * Run / Re-run AI Analysis for an existing incident — reuses the existing AI pipeline (IAiAnalysisRunnerPort →
 * orchestrator /pipeline/run in analysis-only mode) on the incident's own alert. It never creates an alert, never
 * creates a second incident (the alert must belong to exactly this incident), never changes the incident's status and
 * never executes, hands off or notifies anything. One run per incident at a time. Every attempt is audited.
 */
export class RunIncidentAiAnalysisUseCase {
  private readonly running = new Set<string>();

  constructor(
    private readonly incidents: IIncidentRepository,
    private readonly guard: IAiAnalysisRunGuard,
    private readonly runner: IAiAnalysisRunnerPort,
    private readonly investigations: IInvestigationRepository,
    private readonly getAnalysis: GetIncidentAiAnalysisUseCase,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { tenantId: string; incidentId: string; actor: string }): Promise<Result<RunIncidentAiAnalysisOutput, RunIncidentAiAnalysisError>> {
    const key = `${input.tenantId}:${input.incidentId}`;
    // Claimed synchronously (before any await) so two concurrent requests can never both start a run.
    if (this.running.has(key)) return Result.fail("ANALYSIS_IN_PROGRESS");
    this.running.add(key);
    try {
      const incident = await this.incidents.findById(input.incidentId, input.tenantId);
      if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
      if (!incident.alertId) return Result.fail("INCIDENT_HAS_NO_ALERT");

      // The pipeline attaches results to "the incident whose alert_id is this alert" and would open a NEW incident if
      // none existed — so only run when that incident is exactly this one.
      const owners = await this.guard.incidentsWithPrimaryAlert(incident.alertId, input.tenantId);
      if (owners.length !== 1 || owners[0] !== incident.id) return Result.fail("ALERT_OWNED_BY_OTHER_INCIDENT");
      if (await this.guard.hasRunningExecution(incident.id, new Date(Date.now() - STALE_RUN_MS))) return Result.fail("ANALYSIS_IN_PROGRESS");

      const before = await this.getAnalysis.execute({ tenantId: input.tenantId, incidentId: incident.id });
      const rerun = before.isSuccess && before.value.summary !== null;

      let run;
      try {
        run = await this.runner.runAnalysis({ alertId: incident.alertId, tenantId: input.tenantId });
      } catch (err) {
        const code = err instanceof AiAnalysisRunnerError ? err.code : "AI_FAILED";
        const reason = err instanceof AiAnalysisRunnerError ? err.reason : null;
        await this.audit(input, { outcome: "FAILED", rerun, error: code, reason, message: err instanceof Error ? err.message.slice(0, 500) : null });
        return Result.fail(code);
      }
      if (run.incidentId !== incident.id) {
        // Guarded above; recorded if the orchestrator ever disagrees.
        await this.audit(input, { outcome: "FAILED", rerun, error: "INCIDENT_MISMATCH", graphRunId: run.graphRunId, pipelineIncidentId: run.incidentId });
        return Result.fail("AI_FAILED");
      }

      // Same follow-up as ingestion: attach the new pipeline data (IOCs, evidence) to the current investigation.
      await this.investigations.syncIncident(incident.id, input.tenantId).catch((err) =>
        console.error("Failed to sync investigation after AI analysis run", incident.id, err instanceof Error ? err.message : "unknown")
      );
      const after = await this.getAnalysis.execute({ tenantId: input.tenantId, incidentId: incident.id });
      await this.audit(input, { outcome: run.status, rerun, graphRunId: run.graphRunId });
      return Result.ok({
        incidentId: incident.id,
        graphRunId: run.graphRunId,
        status: run.status,
        rerun,
        analysis: after.isSuccess ? after.value : { summary: null, keyFindings: [], grounding: null, source: null, model: null, generatedAt: null, latestRun: null },
      });
    } finally {
      this.running.delete(key);
    }
  }

  private audit(input: { tenantId: string; incidentId: string; actor: string }, metadata: Record<string, unknown>): Promise<void> {
    return this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "AI_ANALYSIS_RUN",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: { trigger: "manual", ...metadata },
    });
  }
}
