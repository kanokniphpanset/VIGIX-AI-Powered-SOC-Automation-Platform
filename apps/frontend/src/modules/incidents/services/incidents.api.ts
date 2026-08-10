import { httpClient } from "../../../shared/services/httpClient";

export interface IncidentDto {
  id: string;
  tenantId: string;
  alertId: string;
  title: string;
  status: string;
  priority: string;
  openedAt: string;
  closedAt: string | null;
  mttdSeconds: number | null;
  mttrSeconds: number | null;
}

export interface IncidentTimelineEntryDto {
  id: string;
  incidentId: string;
  eventType: string;
  description: string;
  actor: string;
  occurredAt: string;
}

export interface IncidentListResponse {
  items: IncidentDto[];
  total: number;
  limit: number;
  offset: number;
}

export const incidentsApi = {
  async list(): Promise<IncidentListResponse> {
    const { data } = await httpClient.get<IncidentListResponse>("/incidents");
    return data;
  },

  async getById(id: string): Promise<IncidentDto> {
    const { data } = await httpClient.get<IncidentDto>(`/incidents/${id}`);
    return data;
  },

  async getTimeline(id: string): Promise<IncidentTimelineEntryDto[]> {
    const { data } = await httpClient.get<IncidentTimelineEntryDto[]>(
      `/incidents/${id}/timeline`
    );
    return data;
  },

  async updateStatus(id: string, status: string): Promise<IncidentDto> {
    const { data } = await httpClient.patch<IncidentDto>(`/incidents/${id}/status`, { status });
    return data;
  },
};
