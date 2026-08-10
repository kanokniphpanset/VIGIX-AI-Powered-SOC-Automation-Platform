import { Incident } from "../entities/Incident.entity";

export interface IncidentTimelineEntry {
  id: string;
  incidentId: string;
  eventType: string;
  description: string;
  actor: string;
  occurredAt: Date;
}

export interface IIncidentRepository {
  findById(id: string, tenantId: string): Promise<Incident | null>;
  findAll(tenantId: string, limit?: number, offset?: number): Promise<Incident[]>;
  countAll(tenantId: string): Promise<number>;
  findTimeline(incidentId: string): Promise<IncidentTimelineEntry[]>;
  updateStatus(id: string, tenantId: string, status: Incident["status"]): Promise<Incident>;
}
