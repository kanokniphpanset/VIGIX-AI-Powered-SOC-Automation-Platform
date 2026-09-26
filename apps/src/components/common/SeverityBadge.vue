<script setup lang="ts">
import { computed } from 'vue'
import type { Severity } from '@/types'
import { SEVERITY_CLASSES, SEVERITY_LABEL } from '@/utils/formatters'

const props = withDefaults(
  defineProps<{
    severity: Severity
    size?: 'sm' | 'md'
    dotOnly?: boolean
  }>(),
  { size: 'md', dotOnly: false },
)

const classes = computed(() => SEVERITY_CLASSES[props.severity])
const label = computed(() => SEVERITY_LABEL[props.severity])
</script>

<template>
  <span
    v-if="!dotOnly"
    class="inline-flex items-center gap-1.5 rounded-md border font-semibold whitespace-nowrap"
    :class="[classes.bg, classes.text, classes.border, size === 'sm' ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-1 text-xs']"
  >
    <span class="size-1.5 rounded-full" :class="classes.dot" />
    {{ label }}
  </span>
  <span v-else class="inline-flex size-2 rounded-full" :class="classes.dot" :title="label" />
</template>
