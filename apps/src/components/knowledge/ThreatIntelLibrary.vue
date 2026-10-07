<script setup lang="ts">
import { computed, ref } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import StatusPill from '@/components/common/StatusPill.vue'
import EmptyState from '@/components/common/EmptyState.vue'
import type { IocLibraryItem } from '@/api/work'
import { incidentLabel, timeAgo } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { useI18n } from '@/i18n'

/**
 * Threat-intelligence library: every indicator VIGIX recorded on any incident, grouped by type + value (most-sighted
 * first). Read-only; a row expands to the incidents it was seen on, each opening the incident.
 */
const props = defineProps<{ items: IocLibraryItem[]; search: string }>()
const { t } = useI18n()

type Group = 'all' | 'ip' | 'domain' | 'hash' | 'url' | 'other'
const groupOf = (type: string): Exclude<Group, 'all'> => {
  const s = type.toUpperCase()
  if (s.startsWith('IP')) return 'ip'
  if (s === 'DOMAIN' || s === 'HOSTNAME') return 'domain'
  if (['MD5', 'SHA1', 'SHA256', 'SHA512', 'HASH'].includes(s)) return 'hash'
  if (s === 'URL') return 'url'
  return 'other'
}
const GROUP_TONE: Record<Exclude<Group, 'all'>, string> = {
  ip: 'bg-rose-50 text-rose-700 ring-rose-200',
  domain: 'bg-amber-50 text-amber-800 ring-amber-200',
  hash: 'bg-violet-50 text-violet-700 ring-violet-200',
  url: 'bg-sky-50 text-sky-700 ring-sky-200',
  other: 'bg-slate-100 text-slate-600 ring-slate-200',
}
const group = ref<Group>('all')
const counts = computed(() => {
  const c: Record<Group, number> = { all: props.items.length, ip: 0, domain: 0, hash: 0, url: 0, other: 0 }
  for (const i of props.items) c[groupOf(i.iocType)]++
  return c
})
const GROUPS: Group[] = ['all', 'ip', 'domain', 'hash', 'url', 'other']

const visible = computed(() => {
  const q = props.search.trim().toLowerCase()
  return props.items.filter((i) =>
    (group.value === 'all' || groupOf(i.iocType) === group.value) &&
    (!q || `${i.iocType} ${i.iocValue} ${i.sources.join(' ')}`.toLowerCase().includes(q)))
})

/** Stored reputation is 0–100 (higher = worse); null when no provider scored the indicator. */
const reputation = (score: number | null) => {
  if (score == null) return { label: t('ti.repNone'), tone: 'bg-slate-100 text-slate-500 ring-slate-200' }
  const n = Math.round(score)
  if (n >= 70) return { label: t('ti.repHigh', { n }), tone: 'bg-rose-50 text-rose-700 ring-rose-200' }
  if (n >= 40) return { label: t('ti.repMedium', { n }), tone: 'bg-amber-50 text-amber-800 ring-amber-200' }
  return { label: t('ti.repLow', { n }), tone: 'bg-emerald-50 text-emerald-700 ring-emerald-200' }
}

const keyOf = (i: IocLibraryItem) => `${i.iocType}:${i.iocValue}`
const open = ref<Set<string>>(new Set())
const toggle = (i: IocLibraryItem) => {
  const next = new Set(open.value)
  if (!next.delete(keyOf(i))) next.add(keyOf(i))
  open.value = next
}
const CASES_SHOWN = 10
</script>

<template>
  <div>
    <div class="mb-3 flex flex-wrap gap-1.5" role="group" :aria-label="t('ti.filterAria')">
      <button
        v-for="g in GROUPS"
        :key="g"
        type="button"
        class="rounded-full px-3 py-1 text-xs font-medium ring-1 ring-inset transition"
        :class="group === g ? 'bg-accent-50 text-accent-700 ring-accent-300' : 'bg-white text-slate-600 ring-slate-200 hover:bg-slate-50'"
        :aria-pressed="group === g"
        @click="group = g"
      >{{ t(`ti.group.${g}`) }} <span class="text-slate-400">{{ counts[g] }}</span></button>
    </div>

    <EmptyState v-if="!visible.length" :title="t('kb.noMatch')" />
    <template v-else>
      <div class="hidden grid-cols-[116px_minmax(0,1fr)_120px_80px_96px] gap-3 px-2 pb-2 text-[11px] font-medium text-slate-400 md:grid">
        <span>{{ t('ti.col.type') }}</span><span>{{ t('ti.col.ioc') }}</span><span>{{ t('ti.col.reputation') }}</span><span>{{ t('ti.col.cases') }}</span><span>{{ t('ti.col.lastSeen') }}</span>
      </div>
      <ul class="divide-y divide-slate-100 border-t border-slate-100">
        <li v-for="i in visible" :key="keyOf(i)">
          <button
            type="button"
            class="-mx-2 grid w-[calc(100%+1rem)] grid-cols-[116px_minmax(0,1fr)] items-center gap-x-3 gap-y-1 rounded-lg px-2 py-3 text-left hover:bg-slate-50 md:grid-cols-[116px_minmax(0,1fr)_120px_80px_96px]"
            :aria-expanded="open.has(keyOf(i))"
            :aria-label="t('ti.rowAria', { value: i.iocValue })"
            @click="toggle(i)"
          >
            <span class="flex items-center gap-1">
              <component :is="open.has(keyOf(i)) ? ChevronDown : ChevronRight" class="size-3.5 shrink-0 text-slate-400" />
              <span class="truncate rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="GROUP_TONE[groupOf(i.iocType)]">{{ i.iocType }}</span>
            </span>
            <span class="min-w-0">
              <span class="block truncate font-mono text-xs font-semibold text-slate-800" :title="i.iocValue">{{ i.iocValue }}</span>
              <span class="block truncate text-[11px] text-slate-400">{{ i.sources.join(' · ') }}</span>
            </span>
            <span class="col-start-2 flex flex-wrap items-center gap-2 md:col-start-auto md:contents">
              <span><span class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="reputation(i.reputationScore).tone">{{ reputation(i.reputationScore).label }}</span></span>
              <span class="text-xs font-semibold text-slate-700">{{ t('ti.cases', { n: i.caseCount }) }}</span>
              <span class="text-xs text-slate-500" :title="i.lastSeen ? formatDateTime(i.lastSeen) : undefined">{{ i.lastSeen ? timeAgo(i.lastSeen) : '—' }}</span>
            </span>
          </button>
          <div v-if="open.has(keyOf(i))" class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs md:ml-[124px]">
            <p class="text-slate-500">
              {{ t('ti.seen', { first: i.firstSeen ? formatDateTime(i.firstSeen) : '—', last: i.lastSeen ? formatDateTime(i.lastSeen) : '—' }) }}
              <template v-if="i.confidence != null"> · {{ t('ti.confidence', { n: i.confidence }) }}</template>
            </p>
            <ul class="mt-2 space-y-1.5">
              <li v-for="c in i.cases.slice(0, CASES_SHOWN)" :key="c.id" class="flex flex-wrap items-center gap-2">
                <RouterLink :to="{ name: 'incident-detail', params: { id: c.id } }" class="font-mono font-semibold text-accent-700 hover:underline">{{ incidentLabel(c.id) }}</RouterLink>
                <span class="min-w-0 flex-1 truncate text-slate-700" :title="c.title">{{ c.title }}</span>
                <StatusPill :status="c.status" />
              </li>
            </ul>
            <p v-if="i.cases.length > CASES_SHOWN" class="mt-1.5 text-slate-400">{{ t('ti.moreCases', { n: i.cases.length - CASES_SHOWN }) }}</p>
          </div>
        </li>
      </ul>
    </template>
  </div>
</template>
