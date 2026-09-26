<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { RotateCw } from 'lucide-vue-next'
import PageHeader from '@/components/layout/PageHeader.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import StatusPill from '@/components/common/StatusPill.vue'
import { workApi, type WorkIncident } from '@/api/work'
import { incidentLabel, statusLabel, toSeverity, timeAgo } from '@/utils/vigix'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { useI18n } from '@/i18n'
import { INCIDENT_VIEWS } from '@/utils/workspace'

/**
 * One shared incident list for every role (Incident = shared source of truth). Presets are server-side filters:
 * ?view=critical | escalated | investigation | recommendation. Every column is a stored backend value.
 */
const router = useRouter()
const { t } = useI18n()
const route = useRoute()
const view = computed(() => (typeof route.query.view === 'string' && INCIDENT_VIEWS[route.query.view] ? route.query.view : 'all'))
const preset = computed(() => INCIDENT_VIEWS[view.value]!)

const PAGE = 50
const items = ref<WorkIncident[]>([])
const total = ref(0)
const offset = ref(0)
const loading = ref(true)
const error = ref('')
const search = ref(typeof route.query.search === 'string' ? route.query.search : '')
const status = ref(typeof route.query.status === 'string' ? route.query.status.toLowerCase() : '')
const priority = ref('')
const hideMerged = ref(true)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const statusFilter = status.value || preset.value.status || (hideMerged.value ? 'open,investigating,escalated,resolved' : undefined)
    const res = await workApi.incidents({ status: statusFilter, priority: priority.value || preset.value.priority, search: search.value.trim() || undefined, limit: PAGE, offset: offset.value })
    items.value = res.items
    total.value = res.total
  } catch {
    error.value = t('il.loadFailed')
  } finally {
    loading.value = false
  }
}
onMounted(load)
watch(offset, load)
watch([view, status, priority, hideMerged], () => { if (offset.value) offset.value = 0; else void load() })
let timer: ReturnType<typeof setTimeout> | undefined
watch(search, () => { clearTimeout(timer); timer = setTimeout(() => { if (offset.value) offset.value = 0; else void load() }, 300) })

const open = (i: WorkIncident) => router.push(`/incidents/${i.id}${view.value === 'recommendation' ? '?tab=recommendation' : view.value === 'investigation' ? '?tab=investigation' : ''}`)
const aiTone = (s: string) => (s === 'FAILED' ? 'text-rose-700' : s === 'RUNNING' || s === 'QUEUED' ? 'text-violet-700' : s === 'PARTIAL_SUCCESS' ? 'text-amber-700' : 'text-emerald-700')
</script>

<template>
  <div>
    <PageHeader :title="preset.title" :description="preset.description">
      <template #actions>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" :disabled="loading" @click="load"><RotateCw class="size-4" :class="loading ? 'animate-spin' : ''" /> {{ t('c.refresh') }}</button>
      </template>
    </PageHeader>

    <div class="mb-4 flex flex-wrap items-end gap-3 text-sm">
      <label class="flex min-w-0 flex-1 flex-col gap-1 sm:max-w-xs"><span class="text-xs text-slate-500">{{ t('c.search') }}</span>
        <input v-model="search" type="search" :placeholder="t('il.searchPlaceholder')" class="rounded-lg border border-slate-300 px-3 py-2" />
      </label>
      <label v-if="!preset.status" class="flex flex-col gap-1"><span class="text-xs text-slate-500">{{ t('il.status') }}</span>
        <select v-model="status" class="rounded-lg border border-slate-300 px-2 py-2"><option value="">{{ t('il.any') }}</option><option v-for="s in ['open','investigating','escalated','resolved','dismissed']" :key="s" :value="s">{{ statusLabel(s) }}</option></select>
      </label>
      <label v-if="!preset.priority" class="flex flex-col gap-1"><span class="text-xs text-slate-500">{{ t('il.severity') }}</span>
        <select v-model="priority" class="rounded-lg border border-slate-300 px-2 py-2"><option value="">{{ t('il.any') }}</option><option v-for="s in ['critical','high','medium','low']" :key="s" :value="s">{{ SEVERITY_LABEL[toSeverity(s)] }}</option></select>
      </label>
      <label v-if="!preset.status && !status" class="flex items-center gap-2 pb-2 text-slate-600"><input v-model="hideMerged" type="checkbox" class="size-4" /> {{ t('il.hideMerged') }}</label>
    </div>

    <p v-if="error" class="mb-4 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ error }} <button type="button" class="underline" @click="load">{{ t('c.retry') }}</button></p>
    <p v-if="loading && !items.length" class="rounded-xl border border-slate-200 bg-white px-4 py-10 text-center text-sm text-slate-500">{{ t('il.loading') }}</p>
    <p v-else-if="!loading && !error && !items.length" class="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-10 text-center text-sm text-slate-500">{{ t('il.empty') }}</p>

    <template v-if="items.length">
      <!-- Desktop / tablet: table (scrolls inside its own box, never the page) -->
      <div class="hidden overflow-x-auto rounded-xl border border-slate-200 bg-white md:block">
        <table class="w-full min-w-[900px] text-sm">
          <thead class="border-b border-slate-100 text-left text-xs text-slate-400">
            <tr>
              <th class="px-3 py-2">{{ t('il.col.incident') }}</th><th class="px-3 py-2">{{ t('il.col.type') }}</th><th class="px-3 py-2">{{ t('il.col.severity') }}</th>
              <th class="px-3 py-2">{{ t('il.col.status') }}</th><th class="px-3 py-2">{{ t('il.col.responsible') }}</th><th class="px-3 py-2">{{ t('il.col.approval') }}</th><th class="px-3 py-2">{{ t('il.col.response') }}</th>
              <th class="px-3 py-2">{{ t('il.col.ai') }}</th><th class="px-3 py-2">{{ t('il.col.updated') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr v-for="i in items" :key="i.id" class="cursor-pointer hover:bg-slate-50" tabindex="0" @click="open(i)" @keydown.enter="open(i)">
              <td class="px-3 py-2 font-mono text-xs">{{ incidentLabel(i.id) }}<span class="block text-[10px] text-slate-400">{{ t('il.cycle', { n: i.investigationNumber }) }}</span></td>
              <td class="max-w-[280px] px-3 py-2"><span class="line-clamp-2 font-medium text-slate-800">{{ i.title }}</span></td>
              <td class="px-3 py-2"><SeverityBadge :severity="toSeverity(i.priority)" size="sm" /></td>
              <td class="px-3 py-2"><StatusPill :status="i.status" /></td>
              <td class="px-3 py-2 text-xs">{{ i.responsibleRole ?? '—' }}</td>
              <td class="px-3 py-2 text-xs"><template v-if="i.currentApproval">{{ t('il.step', { n: i.currentApproval.stepOrder }) }} · <strong>{{ i.currentApproval.role }}</strong></template><span v-else class="text-slate-400">—</span></td>
              <td class="px-3 py-2"><StatusPill v-if="i.responseStatus" :status="i.responseStatus" /><span v-else class="text-xs text-slate-400">{{ t('il.noTicket') }}</span></td>
              <td class="px-3 py-2 text-xs"><span v-if="i.aiJob" :class="aiTone(i.aiJob.status)">{{ statusLabel(i.aiJob.status) }}</span><span v-else class="text-slate-400">—</span></td>
              <td class="whitespace-nowrap px-3 py-2 text-xs text-slate-500" :title="formatDateTime(i.updatedAt)">{{ timeAgo(i.updatedAt) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <!-- Mobile: cards -->
      <ul class="space-y-2 md:hidden">
        <li v-for="i in items" :key="i.id">
          <button type="button" class="w-full rounded-xl border border-slate-200 bg-white p-3 text-left" @click="open(i)">
            <p class="flex flex-wrap items-center gap-1.5 text-xs text-slate-500"><span class="font-mono">{{ incidentLabel(i.id) }}</span><SeverityBadge :severity="toSeverity(i.priority)" size="sm" /><StatusPill :status="i.status" /></p>
            <p class="mt-1 line-clamp-2 text-sm font-medium text-slate-800">{{ i.title }}</p>
            <p class="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-slate-600">
              <span>{{ i.responsibleRole ?? t('il.notAssigned') }}</span>
              <span v-if="i.currentApproval">{{ t('il.approval', { role: i.currentApproval.role ?? '—' }) }}</span>
              <span class="ml-auto text-slate-400">{{ timeAgo(i.updatedAt) }}</span>
            </p>
          </button>
        </li>
      </ul>
      <div class="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
        <span>{{ t('c.pageOf', { from: offset + 1, to: Math.min(offset + PAGE, total), total }) }}</span>
        <span class="flex gap-1">
          <button type="button" class="rounded border border-slate-200 bg-white px-2 py-1 disabled:opacity-40" :disabled="loading || offset === 0" @click="offset = Math.max(0, offset - PAGE)">{{ t('c.previous') }}</button>
          <button type="button" class="rounded border border-slate-200 bg-white px-2 py-1 disabled:opacity-40" :disabled="loading || offset + PAGE >= total" @click="offset += PAGE">{{ t('c.next') }}</button>
        </span>
      </div>
    </template>
  </div>
</template>
