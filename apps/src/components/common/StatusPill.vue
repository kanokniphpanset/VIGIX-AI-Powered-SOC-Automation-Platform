<script setup lang="ts">
import { statusClass, statusLabel } from '@/utils/vigix'
defineProps<{ status: string }>()
</script>

<template>
  <span class="inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="statusClass(status)">
    {{ statusLabel(status) }}
  </span>
</template>
