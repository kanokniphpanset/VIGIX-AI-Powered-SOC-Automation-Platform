<script setup lang="ts">
withDefaults(defineProps<{ title: string; description?: string; icon?: string }>(), {})
</script>

<template>
  <div class="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-200 bg-slate-50/60 px-6 py-14 text-center">
    <div v-if="icon" class="mb-3 text-3xl">{{ icon }}</div>
    <p class="text-sm font-semibold text-slate-600">{{ title }}</p>
    <p v-if="description" class="mt-1 max-w-sm text-xs text-slate-400">{{ description }}</p>
    <div v-if="$slots.action" class="mt-4"><slot name="action" /></div>
  </div>
</template>
