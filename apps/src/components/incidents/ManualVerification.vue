<script setup lang="ts">
import { computed } from 'vue'
import BackendForm from '@/components/common/BackendForm.vue'
import { workflowApi, type ResponsePlan } from '@/api/vigix'
import type { FormField } from '@/utils/forms'
import { useI18n } from '@/i18n'
const props = defineProps<{ incidentId: string; responses: ResponsePlan[]; reload: () => Promise<unknown> }>()
const { t } = useI18n()
const fields = computed<FormField[]>(() => [
  { key: 'responseId', label: t('mv.response'), type: 'select', required: true, options: props.responses.map(r => r.id) },
  { key: 'query', label: t('mv.query'), type: 'textarea', required: true },
  { key: 'matchingEvents', label: t('mv.matching'), type: 'number', min: 0, required: true },
  { key: 'threatContained', label: t('mv.contained'), type: 'checkbox' },
  { key: 'iocRecurrence', label: t('mv.recurrence'), type: 'checkbox' },
  { key: 'spreadDetected', label: t('mv.spread'), type: 'checkbox' },
  { key: 'affectedHosts', label: t('mv.hosts'), type: 'lines' },
  { key: 'timeRangeStart', label: t('mv.start'), type: 'datetime-local' },
  { key: 'timeRangeEnd', label: t('mv.end'), type: 'datetime-local' },
  { key: 'notes', label: t('mv.notes'), type: 'textarea' },
])
</script>
<template><BackendForm :label="t('mv.submit')" :fields="fields" :disabled="!responses.length" :action="body => workflowApi.submitVerification(incidentId, body)" :reload="reload" :description="t('mv.description')" /></template>
