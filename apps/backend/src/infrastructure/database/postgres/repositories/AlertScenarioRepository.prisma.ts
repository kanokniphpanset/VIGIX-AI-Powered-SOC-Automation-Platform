import { PrismaClient } from "@prisma/client";
import { AlertScenarioTagRecord, IAlertScenarioRepository } from "../../../../domain/alert/repositories/IAlertScenarioRepository";

export class PrismaAlertScenarioRepository implements IAlertScenarioRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findByAlertIds(alertIds: string[], tenantId: string): Promise<Map<string, AlertScenarioTagRecord>> {
    if (!alertIds.length) return new Map();
    const rows = await this.prisma.alertScenarioTag.findMany({ where: { tenantId, alertId: { in: alertIds } } });
    return new Map(rows.map((r) => [r.alertId, { alertId: r.alertId, scenarioId: r.scenarioId, taggedBy: r.taggedBy, taggedAt: r.taggedAt }]));
  }

  async set(alertId: string, tenantId: string, scenarioId: string, taggedBy: string): Promise<AlertScenarioTagRecord> {
    const r = await this.prisma.alertScenarioTag.upsert({
      where: { alertId },
      create: { alertId, tenantId, scenarioId, taggedBy },
      update: { scenarioId, taggedBy, taggedAt: new Date() },
    });
    return { alertId: r.alertId, scenarioId: r.scenarioId, taggedBy: r.taggedBy, taggedAt: r.taggedAt };
  }

  async clear(alertId: string, tenantId: string): Promise<void> {
    await this.prisma.alertScenarioTag.deleteMany({ where: { alertId, tenantId } });
  }
}
