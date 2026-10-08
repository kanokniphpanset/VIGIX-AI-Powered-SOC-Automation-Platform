<script setup lang="ts">
// Similar past cases: closed incidents that share an IOC / Wazuh rule / MITRE technique / host with this one, ranked
// deterministically on the backend (domain/incident/similarCases). Read-only reference for the analyst: why each case
// matched and how it was handled. Shown as compact knowledge cases (title, outcome, kind of response); the case page has the details.
import { onMounted, ref, watch } from 'vue'
import { BookOpen, Loader2 } from 'lucide-vue-next'
import { workApi, type SimilarCase } from '@/api/work'
import { statusLabel } from '@/utils/vigix'
import { useI18n } from '@/i18n'

const props = defineProps<{ incidentId: string }>()
const { t } = useI18n()

const items = ref<SimilarCase[] | null>(null)
const failed = ref(false)
async function load() {
  items.value = null
  failed.value = false
  try {
    items.value = (await workApi.similarCases(props.incidentId)).items
  } catch {
    failed.value = true
    items.value = []
  }
}
onMounted(load)
watch(() => props.incidentId, load)

/** Only the kinds of response used (names, no targets), each once - the case page has the details. */
const responseOf = (c: SimilarCase) => [...new Set(c.actions.map((a) => a.name ?? a.code).filter((x): x is string => !!x))].join(', ')
</script>

<template>
  <section :aria-label="t('sim.title')" data-testid="similar-cases">
    <div class="flex items-center justify-between gap-2">
      <h2 class="flex items-center gap-1.5 text-sm font-semibold text-slate-800"><BookOpen class="size-4 text-slate-400" />{{ t('sim.title') }}</h2>
      <RouterLink :to="{ name: 'knowledge', query: { section: 'history' } }" class="text-[11px] text-accent-700 hover:underline">{{ t('sim.all') }}</RouterLink>
    </div>

    <p v-if="items === null" class="mt-3 flex items-center gap-1.5 text-xs text-slate-500"><Loader2 class="size-3.5 animate-spin" /></p>
    <p v-else-if="failed" class="mt-3 text-xs text-rose-600">{{ t('sim.loadFailed') }}</p>
    <p v-else-if="!items.length" class="mt-3 text-xs text-slate-500">{{ t('sim.none') }}</p>

    <!-- compact knowledge cases: title, outcome and the kind of response only -->
    <ul v-else class="mt-2 divide-y divide-slate-100">
      <li v-for="c in items" :key="c.id">
        <RouterLink :to="{ name: 'incident-detail', params: { id: c.id } }" class="block py-2 hover:bg-slate-50">
          <span class="block text-xs font-medium text-slate-800">{{ c.title }}</span>
          <span class="mt-0.5 flex items-center gap-1.5 text-[11px] text-slate-500">
            <span class="size-1.5 shrink-0 rounded-full" :class="c.status === 'resolved' ? 'bg-emerald-500' : 'bg-slate-400'" />
            <span>{{ statusLabel(c.status) }}</span>
            <template v-if="c.actions.length"><span>·</span><span class="truncate">{{ responseOf(c) }}</span></template>
          </span>
        </RouterLink>
      </li>
    </ul>
  </section>
</template>
