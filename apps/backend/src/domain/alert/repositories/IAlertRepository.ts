import { Alert } from "../entities/Alert.entity";

/**
 * IAlertRepository — port (interface) owned by the domain.
 * The infrastructure layer implements this (e.g. AlertRepository.prisma.ts).
 * Application/domain code depends ONLY on this interface, never on Prisma directly.
 */
export interface IAlertRepository {
  findById(id: string, tenantId: string): Promise<Alert | null>;
  findAll(tenantId: string, limit?: number, offset?: number): Promise<Alert[]>;
  countAll(tenantId: string): Promise<number>;
  save(alert: Alert): Promise<Alert>;
}
