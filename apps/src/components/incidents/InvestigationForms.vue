<script setup lang="ts">
import BackendForm from '@/components/common/BackendForm.vue'
import { incidentsApi } from '@/api/vigix'
import type { FormField } from '@/utils/forms'
import { computed } from 'vue'
import { useI18n } from '@/i18n'
defineProps<{ investigationId: string; reload: () => Promise<unknown> }>()
const { t } = useI18n()
const evidence = computed<FormField[]>(() => [
  { key: 'title', label: t('invf.title'), required: true },
  { key: 'type', label: t('invf.type'), type: 'select', required: true, options: ['WINDOWS_EVENT','LINUX_LOG','PROCESS_EVENT','NETWORK_CONNECTION','AUTHENTICATION_EVENT','FILE_EVENT','REGISTRY_EVENT','EMAIL','THREAT_INTELLIGENCE','ANALYST_NOTE','SCREENSHOT_ARTIFACT','QUERY_RESULT','OTHER'] },
  { key: 'source', label: t('invf.source'), type: 'select', required: true, options: ['WAZUH','SPLUNK','DEFENDER','ELK','EDR','FIREWALL','EMAIL_GATEWAY','ANALYST','OTHER'] },
  { key: 'description', label: t('invf.description'), type: 'textarea' },
  { key: 'timestamp', label: t('invf.observedAt'), type: 'datetime-local' },
  { key: 'confidence', label: t('invf.confidence'), type: 'number', min: 0, max: 1 },
])
const ioc = computed<FormField[]>(() => [
  { key: 'iocType', label: t('invf.iocType'), type: 'select', required: true, options: ['IPV4','IPV6','DOMAIN','URL','MD5','SHA1','SHA256','FILE_NAME','FILE_PATH','REGISTRY_KEY','REGISTRY_VALUE','EMAIL','USERNAME','PROCESS_NAME','PROCESS_ID','HOSTNAME','MAC','CVE','CERT_FINGERPRINT','COMMAND_LINE','HTTP_REQUEST','OTHER'] },
  { key: 'iocValue', label: t('invf.value'), required: true }, { key: 'source', label: t('invf.iocSource'), required: true },
  { key: 'status', label: t('invf.status'), type: 'select', options: ['ACTIVE','BENIGN','FALSE_POSITIVE'] },
  { key: 'confidence', label: t('invf.confidence'), type: 'number', min: 0, max: 1 },
])
</script>
<template><div class="my-3 flex flex-wrap gap-2"><BackendForm :label="t('invf.addEvidence')" :fields="evidence" :action="body => incidentsApi.addEvidence(investigationId, body)" :reload="reload" :description="t('invf.manualNote')" /><BackendForm :label="t('invf.addIoc')" :fields="ioc" :action="body => incidentsApi.addIoc(investigationId, body)" :reload="reload" /></div></template>
