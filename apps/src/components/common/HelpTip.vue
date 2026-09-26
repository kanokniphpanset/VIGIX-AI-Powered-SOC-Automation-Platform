<script setup lang="ts">
// (?) help tip for jargon (SLA, MTTR, Re-hunt, MITRE…): shows a short plain-language explanation on hover or keyboard
// focus. The text is also the button's accessible name, so screen readers read it too.
defineProps<{ text: string }>()
</script>

<template>
  <span class="group relative inline-flex align-middle">
    <button type="button" :aria-label="text" class="inline-flex size-4 items-center justify-center rounded-full border border-slate-300 text-[10px] font-bold leading-none text-slate-500 hover:border-slate-400 hover:text-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-500">?</button>
    <span role="tooltip" class="pointer-events-none absolute left-1/2 top-6 z-30 hidden w-60 max-w-[calc(100vw-2rem)] -translate-x-1/2 rounded-lg bg-slate-900 px-3 py-2 text-xs font-normal normal-case leading-relaxed tracking-normal text-white shadow-lg group-hover:block group-focus-within:block">{{ text }}</span>
  </span>
</template>
