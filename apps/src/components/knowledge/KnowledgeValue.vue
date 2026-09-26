<script setup lang="ts">
import { useI18n } from '@/i18n'

defineProps<{ value: unknown }>()
const { t } = useI18n()
const label = (key: string) => key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/_/g, ' ')
</script>
<template>
  <ul v-if="Array.isArray(value)" class="space-y-2 border-l border-slate-200 pl-3"><li v-for="(entry,i) in value" :key="i"><KnowledgeValue :value="entry" /></li></ul>
  <dl v-else-if="value && typeof value === 'object'" class="space-y-1"><div v-for="(entry,key) in value" :key="key"><dt class="font-medium capitalize text-slate-500">{{ label(String(key)) }}</dt><dd class="pl-2"><KnowledgeValue :value="entry" /></dd></div></dl>
  <span v-else class="whitespace-pre-wrap break-all">{{ typeof value === 'boolean' ? value ? t('kbv.yes') : t('kbv.no') : value ?? '—' }}</span>
</template>
