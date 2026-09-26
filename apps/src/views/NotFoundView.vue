<script setup lang="ts">
import { useI18n } from '@/i18n'
const { t } = useI18n()
</script>

<template>
  <div class="flex flex-col items-center justify-center py-24 text-center">
    <p class="text-4xl font-bold text-slate-200">404</p>
    <p class="mt-2 text-sm font-semibold text-slate-600">{{ t('ui.notFound') }}</p>
    <router-link to="/dashboard" class="mt-4 rounded-lg bg-navy-900 px-4 py-2 text-xs font-semibold text-white hover:bg-navy-800">{{ t('ui.backToDashboard') }}</router-link>
  </div>
</template>
