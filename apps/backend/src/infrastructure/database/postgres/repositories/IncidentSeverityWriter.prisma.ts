import { PrismaClient } from "@prisma/client";
import { IIncidentSeverityWriter } from "../../../../application/triage/ports/IIncidentSeverityWriter";
import { IIncidentSeverityReader, IncidentSeverityFacts } from "../../../../application/triage/IncidentSeverity.usecase";
import { Severity } from "../../../../domain/policy/entities/PolicyEvaluationTypes";

export class PrismaIncidentSeverityWriter implements IIncidentSeverityWriter {
  constructor(private readonly prisma: PrismaClient) {}

  async setSeverity(input: { tenantId: string; incidentId: string; severity: Severity; actor: string; description: string }): Promise<void> {
    await this.prisma.$transaction(async tx => {
      await tx.incident.updateMany({ where: { id: input.incidentId, tenantId: input.tenantId }, data: { priority: input.severity.toLowerCase() } });
      await tx.incidentTimeline.create({ data: { incidentId: input.incidentId, eventType: "SEVERITY_VALIDATED", description: input.description, actor: input.actor } });
    });
  }

  async ticketStatuses(tenantId: string, incidentId: string): Promise<string[]> {
    const rows = await this.prisma.responsePlan.findMany({ where: { tenantId, incidentId }, select: { status: true } });
    return rows.map((r) => r.status);
  }
}

/** Stored facts behind an incident's severity: incident severity, primary Wazuh alert (rule level), latest SOC decision. */
export class PrismaIncidentSeverityReader implements IIncidentSeverityReader {
  constructor(private readonly prisma: PrismaClient) {}

  async read(tenantId: string, incidentId: string): Promise<IncidentSeverityFacts | null> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, tenantId }, select: { priority: true, alert: { select: { severity: true, rawPayload: true } } } });
    if (!incident) return null;
    const rule = ((incident.alert?.rawPayload ?? {}) as { rule?: { level?: unknown; id?: unknown } }).rule ?? {};
    const audit = await this.prisma.auditLog.findFirst({ where: { tenantId, entity: "Incident", entityId: incidentId, action: "SEVERITY_VALIDATED" }, orderBy: { createdAt: "desc" } });
    const m = (audit?.metadata ?? {}) as { severity?: unknown; reason?: unknown; note?: unknown };
    return {
      incidentSeverity: incident.priority,
      alertSeverity: incident.alert?.severity ?? null,
      ruleLevel: typeof rule.level === "number" ? rule.level : null,
      ruleId: rule.id !== undefined && rule.id !== null ? String(rule.id) : null,
      latestValidation: audit
        ? { severity: typeof m.severity === "string" ? m.severity : null, reason: typeof m.reason === "string" ? m.reason : typeof m.note === "string" ? m.note : null, actor: audit.actor, at: audit.createdAt }
        : null,
    };
  }
}
