<template>
  <div class="detail-view">
    <RouterLink to="/incidents" class="back-link">← Incidents</RouterLink>

    <div v-if="store.isLoadingDetail" class="state-msg">Loading…</div>
    <div v-else-if="store.error" class="state-msg error">{{ store.error }}</div>
    <template v-else-if="store.current">
      <header class="detail-header">
        <div>
          <span
            class="priority-badge"
            :style="{
              color: severityMeta(store.current.priority).color,
              background: severityMeta(store.current.priority).bg,
            }"
          >
            {{ severityMeta(store.current.priority).label }}
          </span>
          <h1>{{ store.current.title }}</h1>
          <p class="subtitle mono">
            Opened {{ formatDate(store.current.openedAt) }} · Alert
            {{ store.current.alertId.slice(0, 8) }}
          </p>
        </div>

        <select
          class="status-select"
          :value="store.current.status"
          @change="onStatusChange(($event.target as HTMLSelectElement).value)"
        >
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="dismissed">Dismissed</option>
        </select>
      </header>

      <section class="panel">
        <h2>Timeline</h2>
        <IncidentTimeline :entries="store.timeline" />
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue";
import { useRoute } from "vue-router";
import { useIncidentsStore } from "../stores/incidents.store";
import { severityMeta } from "../../../shared/utils/severity";
import IncidentTimeline from "../components/IncidentTimeline.vue";

const route = useRoute();
const store = useIncidentsStore();

onMounted(() => {
  store.fetchIncidentDetail(route.params.id as string);
});

function onStatusChange(status: string) {
  if (!store.current) return;
  store.changeStatus(store.current.id, status);
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
</script>

<style scoped>
.detail-view {
  padding: var(--space-6);
  max-width: 800px;
}

.back-link {
  display: inline-block;
  color: var(--text-secondary);
  text-decoration: none;
  font-size: 13px;
  margin-bottom: var(--space-5);
}

.back-link:hover {
  color: var(--accent);
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--space-6);
}

h1 {
  font-family: var(--font-display);
  font-size: 20px;
  font-weight: 600;
  margin: var(--space-2) 0 0;
}

.subtitle {
  color: var(--text-muted);
  font-size: 12px;
  margin: var(--space-1) 0 0;
}

.priority-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
}

.status-select {
  background: var(--bg-surface);
  color: var(--text-primary);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-sm);
  padding: var(--space-2) var(--space-3);
  font-size: 13px;
}

.panel {
  background: var(--bg-surface);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-md);
  padding: var(--space-5);
}

.panel h2 {
  font-size: 14px;
  font-weight: 600;
  margin: 0 0 var(--space-4);
  color: var(--text-secondary);
}

.mono {
  font-family: var(--font-mono);
}

.state-msg {
  padding: var(--space-6);
  text-align: center;
  color: var(--text-secondary);
}

.state-msg.error {
  color: var(--severity-critical);
}
</style>
