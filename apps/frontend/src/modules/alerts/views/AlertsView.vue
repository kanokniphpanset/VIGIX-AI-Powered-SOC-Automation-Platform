<template>
  <div class="alerts">
    <Card flush>
      <div class="alerts__toolbar">
        <div class="alerts__search">
          <Icon name="search" :size="15" />
          <input v-model="search" type="text" placeholder="Search alert ID, IP, or user…" @keyup.enter="reload" />
        </div>
        <div class="alerts__filters">
          <button
            v-for="opt in severityFilters"
            :key="opt.value"
            class="alerts__chip"
            :class="{ 'alerts__chip--active': activeSeverity === opt.value }"
            type="button"
            @click="activeSeverity = opt.value"
          >
            {{ opt.label }}
          </button>
        </div>
        <AppButton size="sm" :loading="loading" @click="reload">Refresh</AppButton>
      </div>

      <table class="st-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Alert</th>
            <th>Source</th>
            <th>Source IP</th>
            <th>MITRE</th>
            <th>Risk Score</th>
            <th>Status</th>
            <th>Time</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in filteredRows"
            :key="row.executionId"
            :class="{ alerts__row: true, 'alerts__row--clickable': row.incidentId }"
            @click="row.incidentId && router.push(`/incidents/${row.incidentId}`)"
          >
            <td>
              <Badge :tone="severityTone(row.severity)" dot>{{ row.severity }}</Badge>
            </td>
            <td>
              <div class="alerts__title">{{ row.title || row.externalAlertId }}</div>
              <div class="alerts__subtitle">{{ row.externalAlertId }}</div>
            </td>
            <td class="st-table__muted">{{ row.siemSource ?? "—" }}</td>
            <td class="st-table__muted mono">{{ row.sourceIp ?? "—" }}</td>
            <td>
              <span v-if="row.topTechniqueId" class="alerts__mitre">
                {{ row.topTechniqueId }}
                <span v-if="row.topTechniqueConfidence" class="st-table__muted"> · {{ (row.topTechniqueConfidence * 100).toFixed(0) }}%</span>
              </span>
              <span v-else class="st-table__muted">—</span>
            </td>
            <td>
              <span class="alerts__risk" :class="riskClass(row.riskScore)">{{ row.riskScore ?? "—" }}</span>
            </td>
            <td>
              <Badge :tone="statusTone(row.status)">{{ row.status }}</Badge>
            </td>
            <td class="st-table__muted">{{ relativeTime(row.startedAt) }}</td>
            <td>
              <span v-if="row.incidentId" class="alerts__view">Investigate →</span>
              <span v-else class="st-table__muted alerts__view--pending">Analyzing…</span>
            </td>
          </tr>
        </tbody>
      </table>

      <div v-if="!loading && filteredRows.length === 0" class="st-empty">
        <Icon name="alertTriangle" :size="24" />
        No alerts match the current filters.
      </div>
      <div class="alerts__footer" v-if="!loading">
        Showing {{ filteredRows.length }} of {{ total }} alerts
      </div>
    </Card>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import Card from "../../../shared/ui/Card.vue";
import Badge from "../../../shared/ui/Badge.vue";
import Icon from "../../../shared/ui/Icon.vue";
import AppButton from "../../../shared/ui/AppButton.vue";
import { alertsApi, ExecutionListItem } from "../services/alerts.api";
import { relativeTime, severityTone, statusTone } from "../../../shared/utils/format";

const router = useRouter();
const rows = ref<ExecutionListItem[]>([]);
const total = ref(0);
const loading = ref(true);
const search = ref("");
const activeSeverity = ref("all");

const severityFilters = [
  { value: "all", label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const filteredRows = computed(() => {
  if (activeSeverity.value === "all") return rows.value;
  return rows.value.filter((r) => (r.severity ?? "").toLowerCase() === activeSeverity.value);
});

function riskClass(score: number | null) {
  if (score === null) return "";
  if (score >= 75) return "alerts__risk--critical";
  if (score >= 50) return "alerts__risk--high";
  if (score >= 25) return "alerts__risk--medium";
  return "alerts__risk--low";
}

async function reload() {
  loading.value = true;
  try {
    const res = await alertsApi.list({ q: search.value || undefined, limit: 50 });
    rows.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

onMounted(reload);
</script>

<style scoped>
.alerts {
  display: flex;
  flex-direction: column;
  gap: var(--space-5);
}

.alerts__toolbar {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-4) var(--space-5);
  border-bottom: 1px solid var(--border-default);
  flex-wrap: wrap;
}

.alerts__search {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 1;
  min-width: 220px;
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  padding: 8px 12px;
  color: var(--text-muted);
  background: var(--bg-surface);
}

.alerts__search input {
  border: none;
  outline: none;
  flex: 1;
  font-size: 13px;
  color: var(--text-primary);
  background: transparent;
}

.alerts__filters {
  display: flex;
  gap: 6px;
}

.alerts__chip {
  border: 1px solid var(--border-default);
  background: var(--bg-surface);
  color: var(--text-secondary);
  border-radius: 999px;
  padding: 5px 12px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
}

.alerts__chip:hover {
  background: var(--bg-subtle);
}

.alerts__chip--active {
  background: var(--accent-light);
  border-color: var(--accent-border);
  color: var(--accent);
}

.alerts__title {
  font-weight: 600;
  color: var(--text-primary);
  font-size: 13px;
}

.alerts__subtitle {
  font-size: 11.5px;
  color: var(--text-muted);
  margin-top: 1px;
}

.mono {
  font-family: var(--font-mono);
  font-size: 12.5px;
}

.alerts__mitre {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-primary);
}

.alerts__risk {
  font-weight: 700;
  font-size: 13.5px;
  color: var(--text-secondary);
}
.alerts__risk--critical {
  color: var(--severity-critical);
}
.alerts__risk--high {
  color: var(--severity-high);
}
.alerts__risk--medium {
  color: var(--severity-medium);
}
.alerts__risk--low {
  color: var(--severity-low);
}

.alerts__row--clickable {
  cursor: pointer;
}

.alerts__view {
  color: var(--accent);
  font-size: 12.5px;
}

.alerts__view--pending {
  font-size: 12px;
}

.alerts__footer {
  padding: var(--space-3) var(--space-5);
  font-size: 12px;
  color: var(--text-muted);
  border-top: 1px solid var(--border-light);
}
</style>
