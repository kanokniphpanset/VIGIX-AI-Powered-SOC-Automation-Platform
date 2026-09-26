import { Incident as PrismaIncident, IncidentTimeline as PrismaTimeline } from "@prisma/client";
import {
  Incident,
  IncidentPriority,
  IncidentStatus,
} from "../../../../domain/incident/entities/Incident.entity";
import { IncidentTimelineEntry } from "../../../../domain/incident/repositories/IIncidentRepository";

export class IncidentMapper {
  static toDomain(raw: PrismaIncident): Incident {
    return Incident.create({
      id: raw.id,
      tenantId: raw.tenantId,
      alertId: raw.alertId,
      title: raw.title,
      status: raw.status as IncidentStatus,
      priority: raw.priority as IncidentPriority,
      openedAt: raw.openedAt,
      closedAt: raw.closedAt,
      mttdSeconds: raw.mttdSeconds,
      mttrSeconds: raw.mttrSeconds,
      investigationNumber: raw.investigationNumber,
    });
  }

  static timelineToDomain(raw: PrismaTimeline): IncidentTimelineEntry {
    return {
      id: raw.id,
      incidentId: raw.incidentId,
      eventType: raw.eventType,
      description: raw.description,
      actor: raw.actor,
      occurredAt: raw.occurredAt,
    };
  }
}
