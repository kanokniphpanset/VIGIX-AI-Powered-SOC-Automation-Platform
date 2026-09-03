import { executionsHttpClient, httpClient } from "../../../shared/services/httpClient";

export interface AlertProps {
  id: string;
  tenantId: string;
  externalAlertId: string;
  siemSource: string;
  rawPayload: unknown;
  severity: "low" | "medium" | "high" | "critical";
  status: "received" | "analyzing" | "escalated" | "closed";
  receivedAt: string;
  createdAt: string;
}

export interface ExecutionListItem {
  executionId: string;
  alertId: string;
  incidentId: string | null;
  externalAlertId: string;
  title: string;
  sourceIp: string | null;
  user: string | null;
  siemSource: string | null;
  riskScore: number | null;
  status: string;
  alertStatus: string;
  severity: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  verdict: "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN" | null;
  topTechniqueId: string | null;
  topTechniqueConfidence: number | null;
}

export interface ExecutionListResponse {
  items: ExecutionListItem[];
  total: number;
}

export const alertsApi = {
  async list(params: { q?: string; status?: string; alertStatus?: string; limit?: number; offset?: number } = {}): Promise<ExecutionListResponse> {
    const { data } = await executionsHttpClient.get<ExecutionListResponse>("", { params: { limit: 50, offset: 0, ...params } });
    return data;
  },

  async getAlert(id: string): Promise<AlertProps> {
    const { data } = await httpClient.get<AlertProps>(`/alerts/${id}`);
    return data;
  },
};
