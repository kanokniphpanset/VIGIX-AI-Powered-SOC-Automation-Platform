import { defineStore } from "pinia";
import { incidentsApi, IncidentDto, IncidentTimelineEntryDto } from "../services/incidents.api";

interface IncidentsState {
  items: IncidentDto[];
  total: number;
  isLoading: boolean;
  error: string | null;

  current: IncidentDto | null;
  timeline: IncidentTimelineEntryDto[];
  isLoadingDetail: boolean;
}

export const useIncidentsStore = defineStore("incidents", {
  state: (): IncidentsState => ({
    items: [],
    total: 0,
    isLoading: false,
    error: null,

    current: null,
    timeline: [],
    isLoadingDetail: false,
  }),

  actions: {
    async fetchIncidents() {
      this.isLoading = true;
      this.error = null;
      try {
        const res = await incidentsApi.list();
        this.items = res.items;
        this.total = res.total;
      } catch (err) {
        this.error = err instanceof Error ? err.message : "Failed to load incidents";
      } finally {
        this.isLoading = false;
      }
    },

    async fetchIncidentDetail(id: string) {
      this.isLoadingDetail = true;
      this.error = null;
      try {
        const [incident, timeline] = await Promise.all([
          incidentsApi.getById(id),
          incidentsApi.getTimeline(id),
        ]);
        this.current = incident;
        this.timeline = timeline;
      } catch (err) {
        this.error = err instanceof Error ? err.message : "Failed to load incident";
      } finally {
        this.isLoadingDetail = false;
      }
    },

    async changeStatus(id: string, status: string) {
      const updated = await incidentsApi.updateStatus(id, status);
      this.current = updated;
      const idx = this.items.findIndex((i) => i.id === id);
      if (idx !== -1) this.items[idx] = updated;
    },
  },
});
