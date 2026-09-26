<script setup lang="ts">
withDefaults(defineProps<{ title: string; description?: string }>(), {})
</script>

<template>
  <div class="mb-7 flex flex-wrap items-start justify-between gap-3">
    <div>
      <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ title }}</h1>
      <p v-if="description" class="mt-2 text-sm text-slate-500">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="flex shrink-0 items-center gap-2">
      <slot name="actions" />
    </div>
  </div>
</template>
