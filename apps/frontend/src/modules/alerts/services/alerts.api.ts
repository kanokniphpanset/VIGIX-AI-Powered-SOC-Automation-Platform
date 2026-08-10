import { httpClient } from "../../../shared/services/httpClient";

export interface AlertDto {
  id: string;
  tenantId: string;
  externalAlertId: string;
  siemSource: string;
  rawPayload: Record<string, unknown>;
  severity: string;
  status: string;
  receivedAt: string;
  createdAt: string;
}

export interface AlertListResponse {
  items: AlertDto[];
  total: number;
  limit: number;
  offset: number;
}

export const alertsApi = {
  async list(): Promise<AlertListResponse> {
    const { data } = await httpClient.get<AlertListResponse>("/alerts");
    return data;
  },

  async getById(id: string): Promise<AlertDto> {
    const { data } = await httpClient.get<AlertDto>(`/alerts/${id}`);
    return data;
  },
};
