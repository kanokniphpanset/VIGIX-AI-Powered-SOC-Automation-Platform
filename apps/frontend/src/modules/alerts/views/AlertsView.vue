<template>
  <div class="alerts-view">
    <header class="view-header">
      <div>
        <h1>Alerts</h1>
        <p class="subtitle">Raw signal from connected SIEMs, before triage.</p>
      </div>
      <button class="refresh-btn" @click="store.fetchAlerts" :disabled="store.isLoading">
        {{ store.isLoading ? "Refreshing…" : "Refresh" }}
      </button>
    </header>

    <AlertTable :alerts="store.items" :is-loading="store.isLoading" :error="store.error" />
  </div>
</template>

<script setup lang="ts">
import { onMounted } from "vue";
import { useAlertsStore } from "../stores/alerts.store";
import AlertTable from "../components/AlertTable.vue";

const store = useAlertsStore();

onMounted(() => {
  store.fetchAlerts();
});
</script>

<style scoped>
.alerts-view {
  padding: var(--space-6);
  max-width: 1100px;
}

.view-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
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

.refresh-btn {
  background: transparent;
  border: 1px solid var(--border-hairline);
  color: var(--text-primary);
  padding: var(--space-2) var(--space-4);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-size: 13px;
}

.refresh-btn:hover:not(:disabled) {
  border-color: var(--accent);
  color: var(--accent);
}

.refresh-btn:disabled {
  opacity: 0.5;
  cursor: default;
}
</style>
