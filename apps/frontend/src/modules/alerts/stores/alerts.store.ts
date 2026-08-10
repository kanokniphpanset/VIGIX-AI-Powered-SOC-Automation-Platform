import { defineStore } from "pinia";
import { alertsApi, AlertDto } from "../services/alerts.api";

interface AlertsState {
  items: AlertDto[];
  total: number;
  isLoading: boolean;
  error: string | null;
}

export const useAlertsStore = defineStore("alerts", {
  state: (): AlertsState => ({
    items: [],
    total: 0,
    isLoading: false,
    error: null,
  }),

  actions: {
    async fetchAlerts() {
      this.isLoading = true;
      this.error = null;
      try {
        const res = await alertsApi.list();
        this.items = res.items;
        this.total = res.total;
      } catch (err) {
        this.error = err instanceof Error ? err.message : "Failed to load alerts";
      } finally {
        this.isLoading = false;
      }
    },
  },
});
