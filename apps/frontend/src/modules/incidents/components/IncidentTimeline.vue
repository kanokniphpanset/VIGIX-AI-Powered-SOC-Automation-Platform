<template>
  <div class="timeline">
    <div v-if="entries.length === 0" class="empty">No timeline events yet.</div>
    <ol v-else class="timeline-list">
      <li v-for="entry in entries" :key="entry.id" class="timeline-item">
        <span class="timeline-dot"></span>
        <div class="timeline-content">
          <div class="timeline-row">
            <span class="timeline-type">{{ entry.eventType }}</span>
            <span class="timeline-time mono">{{ formatDate(entry.occurredAt) }}</span>
          </div>
          <p class="timeline-desc">{{ entry.description }}</p>
          <span class="timeline-actor">by {{ entry.actor }}</span>
        </div>
      </li>
    </ol>
  </div>
</template>

<script setup lang="ts">
import { IncidentTimelineEntryDto } from "../services/incidents.api";

defineProps<{
  entries: IncidentTimelineEntryDto[];
}>();

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
.timeline-list {
  list-style: none;
  margin: 0;
  padding: 0;
  position: relative;
}

.timeline-item {
  display: flex;
  gap: var(--space-3);
  padding-bottom: var(--space-5);
  position: relative;
}

.timeline-item:not(:last-child)::before {
  content: "";
  position: absolute;
  left: 5px;
  top: 14px;
  bottom: -8px;
  width: 1px;
  background: var(--border-hairline);
}

.timeline-dot {
  width: 11px;
  height: 11px;
  border-radius: 50%;
  background: var(--accent);
  border: 2px solid var(--bg-surface);
  box-shadow: 0 0 0 1px var(--accent-dim);
  margin-top: 3px;
  flex-shrink: 0;
}

.timeline-content {
  flex: 1;
}

.timeline-row {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
}

.timeline-type {
  font-weight: 600;
  font-size: 13px;
  text-transform: capitalize;
}

.timeline-time {
  font-size: 11px;
  color: var(--text-muted);
}

.timeline-desc {
  margin: var(--space-1) 0;
  color: var(--text-secondary);
  font-size: 13px;
}

.timeline-actor {
  font-size: 11px;
  color: var(--text-muted);
}

.mono {
  font-family: var(--font-mono);
}

.empty {
  color: var(--text-secondary);
  font-size: 13px;
  padding: var(--space-4) 0;
}
</style>
