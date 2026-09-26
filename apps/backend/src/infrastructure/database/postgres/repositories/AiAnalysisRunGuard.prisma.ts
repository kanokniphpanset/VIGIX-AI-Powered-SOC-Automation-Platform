import { PrismaClient } from "@prisma/client";
import { IAiAnalysisRunGuard } from "../../../../application/incident/use-cases/RunIncidentAiAnalysis.usecase";

export class PrismaAiAnalysisRunGuard implements IAiAnalysisRunGuard {
  constructor(private readonly prisma: PrismaClient) {}

  async hasRunningExecution(incidentId: string, since: Date): Promise<boolean> {
    // RUNNING: a pipeline run in flight (orchestrator); QUEUED: a job waiting for the backend worker.
    const running = await this.prisma.agentExecution.count({
      where: { incidentId, status: { in: ["RUNNING", "running", "QUEUED"] }, startedAt: { gte: since } },
    });
    return running > 0;
  }

  async incidentsWithPrimaryAlert(alertId: string, tenantId: string): Promise<string[]> {
    const rows = await this.prisma.incident.findMany({ where: { alertId, tenantId }, select: { id: true } });
    return rows.map((r) => r.id);
  }
}
