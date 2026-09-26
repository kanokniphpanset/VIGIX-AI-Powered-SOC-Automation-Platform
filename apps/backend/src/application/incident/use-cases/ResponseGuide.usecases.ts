import { incidentSeverity } from "../../../domain/incident/severity";
import { Result } from "../../../shared/result/Result";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IrEmailOutcome, IrEmailService, IrRecipientPreview, safeSubject } from "../../notification/services/IrEmailService";
import { EmailPreview } from "../../knowledge/use-cases/KnowledgeArticles.usecases";

/** Read-only lookup of the playbook a recommendation was built from (its snapshot). */
export interface IPlaybookSnapshotReader {
  findPlaybook(snapshotId: string): Promise<{ code: string; version: string } | null>;
}

export interface ResponseGuideStep {
  stepOrder: number;
  action: string;
  target: string | null;
  reason: string;
  instructions: { order: number; instruction: string; expectedResult: string | null }[];
  verificationCriteria: string | null;
  runbook: { code: string; name: string } | null;
}

export interface ResponseGuide {
  incidentId: string;
  title: string;
  severity: string;
  priority: string;
  status: string;
  investigationNumber: number;
  mitre: { techniqueId: string; tactic: string }[];
  iocs: { type: string; value: string; source: string }[];
  recommendation: { id: string; number: number; summary: string; status: string } | null;
  playbook: { code: string; version: string } | null;
  /** Set when the guide was requested from a response ticket: the email then covers that ticket's step. */
  ticket: { id: string; status: string; target: string | null } | null;
  steps: ResponseGuideStep[];
}

export type ResponseGuideError = "INCIDENT_NOT_FOUND" | "RESPONSE_NOT_FOUND";

/**
 * Builds the incident's response guide from what VIGIX already holds: incident + severity + MITRE + current-cycle IOCs,
 * and the current recommendation's steps (action, target, instructions) with their runbook and playbook sources.
 * With a responseId (from a response ticket) the guide uses that ticket's own recommendation and step — even if a
 * newer recommendation superseded it — and references the ticket; the ticket must belong to the incident.
 */
export class GetResponseGuideUseCase {
  constructor(
    private readonly context: IRecommendationContextRepository,
    private readonly recommendations: IRecommendationRepository,
    private readonly runbooks: IRunbookRepository,
    private readonly snapshots: IPlaybookSnapshotReader,
    private readonly responsePlans: IResponsePlanRepository
  ) {}

  async execute(input: { tenantId: string; incidentId: string; responseId?: string | null }): Promise<Result<ResponseGuide, ResponseGuideError>> {
    const incident = await this.context.getIncidentContext(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    const plan = input.responseId ? await this.responsePlans.findById(input.responseId, input.tenantId) : null;
    if (input.responseId && (!plan || plan.incidentId !== input.incidentId)) return Result.fail("RESPONSE_NOT_FOUND");
    const [mitre, iocs, recs] = await Promise.all([
      this.context.getMitreMappings(input.incidentId),
      this.context.getIocs(input.incidentId, incident.investigationNumber),
      this.recommendations.findAllByIncident(input.incidentId, input.tenantId),
    ]);
    const byNewest = [...recs].sort((a, b) => b.recommendationNumber - a.recommendationNumber);
    const rec = plan
      ? recs.find((r) => r.id === plan.recommendationId) ?? null
      : byNewest.find((r) => r.status === "VALIDATED" && r.investigationNumber === incident.investigationNumber) ??
        byNewest.find((r) => r.status === "VALIDATED") ??
        null;
    const steps = rec
      ? [...rec.steps].filter((s) => !plan?.recommendationStepId || s.id === plan.recommendationStepId).sort((a, b) => a.stepOrder - b.stepOrder)
      : [];
    const runbookIds = [...new Set(steps.map((s) => s.sourceRunbookId).filter((x): x is string => !!x))];
    const runbooks = new Map(
      (await Promise.all(runbookIds.map((id) => this.runbooks.findById(id, input.tenantId)))).flatMap((r) => (r ? [[r.toJSON().id, { code: r.toJSON().code, name: r.toJSON().name }] as const] : []))
    );
    const playbook = rec?.snapshotId ? await this.snapshots.findPlaybook(rec.snapshotId) : null;

    return Result.ok({
      incidentId: incident.incidentId,
      title: incident.title,
      severity: incidentSeverity(incident),
      priority: incident.priority,
      status: incident.status,
      investigationNumber: incident.investigationNumber,
      mitre: mitre.map((m) => ({ techniqueId: m.techniqueId, tactic: m.tactic })),
      iocs: iocs.map((i) => ({ type: i.iocType, value: i.iocValue, source: i.source })),
      recommendation: rec ? { id: rec.id, number: rec.recommendationNumber, summary: rec.summary, status: rec.status } : null,
      playbook,
      ticket: plan ? { id: plan.id, status: plan.status, target: plan.target } : null,
      steps: steps.map((s) => ({
        stepOrder: s.stepOrder,
        action: s.title,
        target: s.target,
        reason: s.reason,
        instructions: [...s.instructions].sort((a, b) => a.order - b.order).map((i) => ({ order: i.order, instruction: i.instruction, expectedResult: i.expectedResult })),
        verificationCriteria: s.verificationCriteria,
        runbook: s.sourceRunbookId ? runbooks.get(s.sourceRunbookId) ?? null : null,
      })),
    });
  }
}

export function renderResponseGuideEmail(g: ResponseGuide, baseUrl: string): EmailPreview {
  const label = `INC-${g.incidentId.slice(0, 8).toUpperCase()}`;
  const stepLines = g.steps.length
    ? g.steps.flatMap((s) => [
        `${s.stepOrder}. ${s.action}`,
        `   Target: ${s.target ?? "—"}`,
        `   Why: ${s.reason}`,
        `   Source runbook: ${s.runbook ? `${s.runbook.code} — ${s.runbook.name}` : "—"}`,
        "   Instructions:",
        ...s.instructions.map((i) => `     ${i.order}) ${i.instruction}${i.expectedResult ? ` [expected: ${i.expectedResult}]` : ""}`),
        ...(s.verificationCriteria ? [`   Verify: ${s.verificationCriteria}`] : []),
        "",
      ])
    : ["No validated recommendation yet for this incident.", ""];
  return {
    subject: safeSubject(`[VIGIX] Response guide — ${label}${g.ticket ? ` ticket ${g.ticket.id.slice(0, 8)}` : ""} ${g.title}`),
    body: [
      "VIGIX Incident Response Guide — for the IR Team",
      "",
      `Incident ID: ${g.incidentId} (${label})`,
      `Title: ${g.title}`,
      `Severity: ${g.severity.toUpperCase()} · Status: ${g.status} · Investigation #${g.investigationNumber}`,
      `MITRE ATT&CK: ${g.mitre.length ? g.mitre.map((m) => `${m.techniqueId} (${m.tactic})`).join(", ") : "not mapped"}`,
      "",
      "Relevant IOCs:",
      ...(g.iocs.length ? g.iocs.map((i) => `  ${i.type}: ${i.value} (source: ${i.source})`) : ["  none recorded"]),
      "",
      ...(g.ticket ? [`Response ticket: ${g.ticket.id} · status ${g.ticket.status}`, ""] : []),
      `Recommended response${g.recommendation ? ` (recommendation #${g.recommendation.number})` : ""}:`,
      ...(g.recommendation ? [`  ${g.recommendation.summary}`, ""] : []),
      ...stepLines,
      "—",
      `Source: VIGIX${g.playbook ? ` · playbook ${g.playbook.code} v${g.playbook.version}` : ""}${g.steps.some((s) => s.runbook) ? ` · runbooks ${[...new Set(g.steps.flatMap((s) => (s.runbook ? [s.runbook.code] : [])))].join(", ")}` : ""}`,
      `VIGIX incident: ${baseUrl}/incidents/${g.incidentId}`,
      g.ticket
        ? `VIGIX response ticket: ${baseUrl}/tickets/${g.ticket.id} (ticket ${g.ticket.id.slice(0, 8)}, status ${g.ticket.status})`
        : `VIGIX response tickets: ${baseUrl}/tickets?incident=${g.incidentId}`,
    ].join("\n"),
  };
}

export class PreviewResponseGuideUseCase {
  constructor(private readonly getGuide: GetResponseGuideUseCase, private readonly irEmail: IrEmailService, private readonly baseUrl: string) {}

  async execute(input: { tenantId: string; incidentId: string; responseId?: string | null }): Promise<Result<{ guide: ResponseGuide; email: EmailPreview; recipient: IrRecipientPreview }, ResponseGuideError>> {
    const guide = await this.getGuide.execute(input);
    if (guide.isFailure) return Result.fail(guide.error);
    return Result.ok({ guide: guide.value, email: renderResponseGuideEmail(guide.value, this.baseUrl), recipient: await this.irEmail.previewRecipient(input.tenantId) });
  }
}

export class SendResponseGuideToIrUseCase {
  constructor(private readonly getGuide: GetResponseGuideUseCase, private readonly irEmail: IrEmailService, private readonly baseUrl: string) {}

  async execute(input: {
    tenantId: string;
    incidentId: string;
    actor: string;
    subject?: string | null;
    responseId?: string | null;
    idempotencyKey?: string | null;
  }): Promise<Result<IrEmailOutcome, ResponseGuideError>> {
    const found = await this.getGuide.execute(input);
    if (found.isFailure) return Result.fail(found.error);
    const email = renderResponseGuideEmail(found.value, this.baseUrl);
    return Result.ok(
      await this.irEmail.send({
        tenantId: input.tenantId,
        actor: input.actor,
        action: "RESPONSE_GUIDE_SENT_TO_IR",
        entity: "Incident",
        entityId: input.incidentId,
        incidentId: input.incidentId,
        subject: input.subject?.trim() ? input.subject : email.subject,
        body: email.body,
        idempotencyKey: input.idempotencyKey ?? null,
        metadata: {
          incidentId: input.incidentId,
          responseId: found.value.ticket?.id ?? null,
          recommendationId: found.value.recommendation?.id ?? null,
          investigationNumber: found.value.investigationNumber,
        },
      })
    );
  }
}
