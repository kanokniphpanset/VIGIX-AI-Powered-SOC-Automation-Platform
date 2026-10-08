import { networkRoleFromPayload } from "../../../../application/recommendation/services/IocRole";
import { iocKind } from "../../../../domain/knowledge/knowledgeTypes";
import { Prisma, PrismaClient } from "@prisma/client";
import {
  AiAnalysisContextRow,
  EvidenceContextRow,
  IRecommendationContextRepository,
  IncidentContextRow,
  IocContextRow,
  AnalysisRunRow,
  MitreMappingContextRow,
  PreviousRecommendationStepRow,
  RehuntContextRow,
} from "../../../../application/recommendation/ports/IRecommendationContextRepository";
import type { TicketRecord } from "../../../../domain/subtype/actionState";
import type { SubtypeEvidenceRow } from "../../../../application/subtype/factBuilder";
import { checkGrounding, stringLeaves, stripAiSeverity } from "../../../../domain/ai/aiGrounding";
import { classifyAnalysisSource, isTrustedAnalysisSource } from "../../../../domain/ai/analysisSource";

export class PrismaRecommendationContextRepository implements IRecommendationContextRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async getRehuntContext(incidentId: string, tenantId: string, investigationNumber: number): Promise<RehuntContextRow | null> {
    if (investigationNumber < 2) return null;
    const row = await this.prisma.verification.findFirst({
      where: { incidentId, tenantId, incident: { tenantId }, afterState: { path: ["verifiedInvestigationNumber"], equals: investigationNumber - 1 } },
      orderBy: { verifiedAt: "desc" },
    });
    if (!row) return null;
    const after = row.afterState as Record<string, unknown> | null;
    const before = row.beforeState as { criteria?: { hosts?: unknown } } | null;
    const source = after?.evidenceSource;
    if (source !== "WAZUH_INDEXER" && source !== "MOCK_REHUNT") return null;
    const strings = (value: unknown) => Array.isArray(value) ? [...new Set(value.filter((v): v is string => typeof v === "string" && !!v))] : [];
    const originalHosts = strings(before?.criteria?.hosts);
    const affectedHosts = strings(row.affectedHosts);
    // Only names observed in this re-hunt and absent from the original host scope are newly affected.
    const newHosts = originalHosts.length ? affectedHosts.filter(host => !originalHosts.includes(host)) : [];
    return {
      verificationId: row.id, verifiedInvestigationNumber: investigationNumber - 1, source,
      result: row.result === "RESOLVED" ? "RESOLVED" : "NOT_RESOLVED",
      spreadDetected: row.spreadDetected, matchingEvents: row.matchingEvents ?? 0,
      originalHosts, affectedHosts, newHosts, truncated: after?.truncated === true,
      classification: typeof after?.classification === "string" ? after.classification : null,
      coverageComplete: typeof (after?.coverage as { complete?: unknown } | null | undefined)?.complete === "boolean" ? (after!.coverage as { complete: boolean }).complete : null,
      verifiedAt: row.verifiedAt,
    };
  }

  async getIncidentContext(incidentId: string, tenantId: string): Promise<IncidentContextRow | null> {
    const incident = await this.prisma.incident.findFirst({
      where: { id: incidentId, tenantId },
      include: { alert: true },
    });
    if (!incident) return null;
    return {
      incidentId: incident.id,
      investigationNumber: incident.investigationNumber,
      title: incident.title,
      status: incident.status,
      priority: incident.priority,
      alertSeverity: incident.alert.severity,
    };
  }

  async getIocs(incidentId: string, investigationNumber?: number): Promise<IocContextRow[]> {
    const rows = await this.prisma.threatIntelIoc.findMany({
      where:
        investigationNumber === undefined
          ? { incidentId }
          : {
              incidentId,
              OR: [{ investigation: { investigationNumber } }, ...(investigationNumber === 1 ? [{ investigationId: null }] : [])],
            },
      include: { sourceAlert: { select: { externalAlertId: true, rawPayload: true } } },
    });
    // Prefer the IOC's attributed source alert; legacy IOCs fall back to the triggering alert's explicit fields.
    // Neither AI prose nor an IP's presence establishes direction; both/neither source and destination stays unknown.
    const alert = (await this.prisma.incident.findUnique({ where: { id: incidentId }, select: { alert: { select: { rawPayload: true } } } }))?.alert;
    return rows.map((r) => ({
      iocType: r.iocType,
      iocValue: r.iocValue,
      source: r.source,
      reputationScore: r.reputationScore,
      ...(iocKind(r.iocType) === "ip" ? { networkRole: networkRoleFromPayload(r.sourceAlert?.rawPayload ?? alert?.rawPayload, r.iocValue) } : {}),
      manual: !!r.createdBy && r.createdBy !== "system",
      id: r.id,
      createdBy: r.createdBy,
      createdAt: r.createdAt,
      sourceAlertId: r.sourceAlertId,
      sourceExternalAlertId: r.sourceAlert?.externalAlertId ?? null,
      addedReason: r.addedReason,
    }));
  }

  async getMitreMappings(incidentId: string): Promise<MitreMappingContextRow[]> {
    const rows = await this.prisma.mitreMapping.findMany({ where: { incidentId } });
    return rows.map((r) => ({
      techniqueId: r.techniqueId,
      tactic: r.tactic,
      confidence: r.confidence,
    }));
  }

  async getEvidence(incidentId: string, investigationNumber: number): Promise<EvidenceContextRow[]> {
    const rows = await this.prisma.evidence.findMany({
      where: { investigation: { incidentId, investigationNumber } },
      include: { iocLinks: { include: { ioc: { select: { iocValue: true } } } } },
      orderBy: { timestamp: "asc" },
    });
    return rows.map((r) => {
      const s = (r.structuredData && typeof r.structuredData === "object" && !Array.isArray(r.structuredData) ? r.structuredData : {}) as Record<string, unknown>;
      return {
        type: r.type,
        source: r.source,
        origin: r.origin,
        title: r.title,
        timestamp: r.timestamp,
        host: typeof s.agent === "string" ? s.agent : null,
        ruleId: s.ruleId !== undefined && s.ruleId !== null ? String(s.ruleId) : null,
        iocValues: r.iocLinks.map((l) => l.ioc.iocValue),
      };
    });
  }

  async getSubtypeEvidence(incidentId: string, tenantId: string, investigationNumber: number): Promise<SubtypeEvidenceRow[]> {
    // Same ordering as getEvidence, so the E<n> citation ids are identical across the context and the subtype facts.
    const rows = await this.prisma.evidence.findMany({
      where: { investigation: { incidentId, investigationNumber, incident: { tenantId } } },
      orderBy: { timestamp: "asc" },
    });
    return rows.map((r, n) => {
      const s = r.structuredData && typeof r.structuredData === "object" && !Array.isArray(r.structuredData) ? (r.structuredData as Record<string, unknown>) : null;
      return {
        id: r.id, ref: `E${n + 1}`, type: r.type, origin: r.origin === "SYSTEM" ? "SYSTEM" : "MANUAL", createdBy: r.createdBy, timestamp: r.timestamp, title: r.title,
        host: s && typeof s.agent === "string" ? s.agent : null, structured: s,
      };
    });
  }

  async getTicketHistory(incidentId: string, tenantId: string): Promise<TicketRecord[]> {
    const rows = await this.prisma.responsePlan.findMany({
      where: { incidentId, tenantId, actionId: { not: null }, target: { not: null } },
      select: { status: true, target: true, executionResult: true, completedAt: true, action: { select: { code: true } }, recommendation: { select: { investigationNumber: true } } },
      orderBy: { createdAt: "asc" },
    });
    return rows.filter((r) => r.action && r.target).map((r) => {
      const res = r.executionResult && typeof r.executionResult === "object" && !Array.isArray(r.executionResult) ? (r.executionResult as Record<string, unknown>) : {};
      const note = [res.note, res.actualResult, res.summary, res.message].find((x) => typeof x === "string") as string | undefined;
      const cs = typeof res.controlState === "string" ? res.controlState : null;   // optional, IR-written; never inferred
      return { actionCode: r.action!.code, target: r.target!, status: r.status, executionNote: note ?? null, controlState: cs, completedAt: r.completedAt, investigationNumber: r.recommendation.investigationNumber };
    });
  }

  async getPreviousRecommendationSteps(incidentId: string, tenantId: string): Promise<PreviousRecommendationStepRow[]> {
    const rows = await this.prisma.recommendationStep.findMany({
      where: { recommendation: { incidentId, tenantId }, actionId: { not: null }, target: { not: null } },
      select: { target: true, action: { select: { code: true } }, recommendation: { select: { recommendationNumber: true, investigationNumber: true } } },
      orderBy: [{ recommendation: { recommendationNumber: "asc" } }, { stepOrder: "asc" }],
    });
    return rows
      .filter((r) => r.action && r.target)
      .map((r) => ({
        recommendationNumber: r.recommendation.recommendationNumber,
        investigationNumber: r.recommendation.investigationNumber,
        actionCode: r.action!.code,
        target: r.target!,
      }));
  }

  /** Most recent llm_analyst outputs with their classified source (historical rows are never modified). */
  private async analysisRows(incidentId: string, take: number) {
    // The run's output contract has recorded analysis.source / model since the LLM-analyst fix; the agent_results row
    // itself only since a later orchestrator change — so the contract fills the gap for rows written in between.
    const rows = await this.prisma.$queryRaw<{ output: unknown; created_at: Date; exec_source: string | null; exec_model: string | null }[]>(Prisma.sql`
      SELECT ar.output, ar.created_at,
             ae.output_contract->'analysis'->>'source' AS exec_source,
             ae.output_contract->'analysis'->>'model'  AS exec_model
        FROM agent_results ar
        JOIN agent_executions ae ON ae.id = ar.agent_execution_id
       WHERE ae.incident_id = ${incidentId} AND ar.agent_name = 'llm_analyst'
       ORDER BY ar.created_at DESC
       LIMIT ${take}`);
    return rows.map((row) => {
      const raw = (row.output && typeof row.output === "object" && !Array.isArray(row.output) ? row.output : null) as Record<string, unknown> | null;
      const out = raw && !raw.analysis_source && row.exec_source ? { ...raw, analysis_source: row.exec_source, model: raw.model ?? row.exec_model } : raw;
      return { out, createdAt: new Date(row.created_at), source: classifyAnalysisSource(out) };
    });
  }

  async getLatestAnalysisRun(incidentId: string): Promise<AnalysisRunRow | null> {
    const [latest] = await this.analysisRows(incidentId, 1);
    return latest ? { source: latest.source, generatedAt: latest.createdAt } : null;
  }

  async getLatestAiAnalysis(incidentId: string): Promise<AiAnalysisContextRow | null> {
    // Only a real LLM analysis is served / used as context — never a heuristic template or a failed run.
    const trusted = (await this.analysisRows(incidentId, 20)).find((r) => isTrustedAnalysisSource(r.source));
    if (!trusted) return null;
    const out = trusted.out;
    // Legacy AI output may carry a model severity suggestion: never served (VIGIX severity = Wazuh rule level only).
    const summary = stripAiSeverity(typeof out?.llm_summary === "string" ? out.llm_summary : "").text;
    if (!summary) return null;
    const findings = Array.isArray(out?.llm_key_findings) ? out.llm_key_findings : [];
    const keyFindings = findings
      .map((f) => (typeof f === "string" ? f : f && typeof f === "object" && typeof (f as { finding?: unknown }).finding === "string" ? (f as { finding: string }).finding : null))
      .filter((f): f is string => !!f)
      .map((f) => stripAiSeverity(f).text)
      .filter((f) => !!f);
    const grounding = checkGrounding([summary, ...keyFindings].join(" "), await this.groundingSources(incidentId));
    return { summary, keyFindings, grounding, source: trusted.source, model: typeof out?.model === "string" ? out.model : null, generatedAt: trusted.createdAt };
  }

  /** Everything the incident actually holds: its alerts' raw payloads, its evidence, its IOCs and MITRE mappings. */
  private async groundingSources(incidentId: string): Promise<string[]> {
    const [incident, links, evidence, iocs, mitre] = await Promise.all([
      this.prisma.incident.findUnique({ where: { id: incidentId }, select: { title: true, alert: { select: { rawPayload: true } } } }),
      this.prisma.incidentAlert.findMany({ where: { incidentId }, select: { alert: { select: { rawPayload: true } } } }),
      this.prisma.evidence.findMany({ where: { investigation: { incidentId } }, select: { title: true, description: true, rawData: true, structuredData: true } }),
      this.prisma.threatIntelIoc.findMany({ where: { incidentId }, select: { iocValue: true } }),
      this.prisma.mitreMapping.findMany({ where: { incidentId }, select: { techniqueId: true } }),
    ]);
    return [
      incident?.title ?? "",
      ...stringLeaves(incident?.alert?.rawPayload),
      ...links.flatMap((l) => stringLeaves(l.alert.rawPayload)),
      ...evidence.flatMap((e) => [e.title, e.description ?? "", ...stringLeaves(e.rawData), ...stringLeaves(e.structuredData)]),
      ...iocs.map((i) => i.iocValue),
      ...mitre.map((m) => m.techniqueId),
    ];
  }
}
