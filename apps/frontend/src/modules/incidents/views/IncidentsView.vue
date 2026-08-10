<template>
  <div class="incidents-view">
    <header class="view-header">
      <div>
        <h1>Incidents</h1>
        <p class="subtitle">Alerts that were escalated for investigation.</p>
      </div>
    </header>

    <div v-if="store.isLoading" class="state-msg">Loading incidents…</div>
    <div v-else-if="store.error" class="state-msg error">{{ store.error }}</div>
    <div v-else-if="store.items.length === 0" class="state-msg">
      No incidents yet. Incidents are created once an alert is escalated.
    </div>
    <div v-else class="incident-list">
      <RouterLink
        v-for="incident in store.items"
        :key="incident.id"
        :to="`/incidents/${incident.id}`"
        class="incident-card"
      >
        <span
          class="priority-dot"
          :style="{ background: severityMeta(incident.priority).color }"
        ></span>
        <div class="incident-info">
          <div class="incident-title">{{ incident.title }}</div>
          <div class="incident-meta mono">
            {{ incident.status }} · opened {{ formatDate(incident.openedAt) }}
          </div>
        </div>
        <span
          class="priority-badge"
          :style="{
            color: severityMeta(incident.priority).color,
            background: severityMeta(incident.priority).bg,
          }"
        >
          {{ severityMeta(incident.priority).label }}
        </span>
      </RouterLink>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue";
import { useIncidentsStore } from "../stores/incidents.store";
import { severityMeta } from "../../../shared/utils/severity";

const store = useIncidentsStore();

onMounted(() => {
  store.fetchIncidents();
});

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
</script>

<style scoped>
.incidents-view {
  padding: var(--space-6);
  max-width: 1100px;
}

.view-header {
  margin-bottom: var(--space-5);
}

h1 {
  font-family: var(--font-display);
  font-size: 22px;
  font-weight: 600;
  margin: 0;
}

.subtitle {
  color: var(--text-secondary);
  font-size: 13px;
  margin: var(--space-1) 0 0;
}

.incident-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.incident-card {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  background: var(--bg-surface);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  text-decoration: none;
  color: inherit;
  transition: border-color 0.15s ease;
}

.incident-card:hover {
  border-color: var(--accent-dim);
}

.priority-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.incident-info {
  flex: 1;
  min-width: 0;
}

.incident-title {
  font-size: 14px;
  font-weight: 500;
}

.incident-meta {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 2px;
}

.mono {
  font-family: var(--font-mono);
}

.priority-badge {
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
  flex-shrink: 0;
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
