<template>
  <div class="alert-table">
    <div v-if="isLoading" class="state-msg">Loading alerts…</div>
    <div v-else-if="error" class="state-msg error">{{ error }}</div>
    <div v-else-if="alerts.length === 0" class="state-msg">
      No alerts yet. Once a SIEM sends one in, it'll show up here.
    </div>
    <table v-else>
      <thead>
        <tr>
          <th class="col-signal"></th>
          <th>Alert</th>
          <th>Source</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Received</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="alert in sortedAlerts" :key="alert.id">
          <td class="col-signal">
            <span
              class="signal-bar"
              :style="{ background: severityMeta(alert.severity).color }"
              :aria-label="`${alert.severity} severity`"
            ></span>
          </td>
          <td>
            <div class="alert-id">{{ alert.externalAlertId }}</div>
            <div class="alert-rule" v-if="alert.rawPayload?.rule">
              {{ alert.rawPayload.rule }}
            </div>
          </td>
          <td class="mono">{{ alert.siemSource }}</td>
          <td>
            <span
              class="severity-badge"
              :style="{
                color: severityMeta(alert.severity).color,
                background: severityMeta(alert.severity).bg,
              }"
            >
              {{ severityMeta(alert.severity).label }}
            </span>
          </td>
          <td class="text-secondary">{{ alert.status }}</td>
          <td class="mono text-secondary">{{ formatDate(alert.receivedAt) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { AlertDto } from "../services/alerts.api";
import { severityMeta, severityRank } from "../../../shared/utils/severity";

const props = defineProps<{
  alerts: AlertDto[];
  isLoading: boolean;
  error: string | null;
}>();

const sortedAlerts = computed(() =>
  [...props.alerts].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
);

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
.alert-table {
  background: var(--bg-surface);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-md);
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
}

thead th {
  text-align: left;
  font-size: 11px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 600;
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--border-hairline);
}

tbody tr {
  border-bottom: 1px solid var(--border-hairline);
}

tbody tr:last-child {
  border-bottom: none;
}

tbody tr:hover {
  background: var(--bg-surface-raised);
}

td {
  padding: var(--space-3) var(--space-4);
  vertical-align: middle;
}

.col-signal {
  width: 4px;
  padding: 0;
}

.signal-bar {
  display: block;
  width: 4px;
  height: 32px;
  border-radius: 2px;
}

.alert-id {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text-primary);
}

.alert-rule {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 2px;
}

.mono {
  font-family: var(--font-mono);
  font-size: 12px;
}

.text-secondary {
  color: var(--text-secondary);
}

.severity-badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 600;
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
