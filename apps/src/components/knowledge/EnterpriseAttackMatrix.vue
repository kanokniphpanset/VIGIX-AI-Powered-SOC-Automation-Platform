<script setup lang="ts">
import { computed, ref } from 'vue'
import { ExternalLink, Search } from 'lucide-vue-next'
import matrix from '@/data/enterpriseAttackMatrix.json'
import { useI18n } from '@/i18n'

const { t } = useI18n()
const search = ref('')
const showSubtechniques = ref(false)
const matches = (technique: typeof matrix.techniques[number]) =>
  `${technique.id} ${technique.name}`.toLowerCase().includes(search.value.trim().toLowerCase())
const columns = computed(() => matrix.tactics.map(tactic => {
  const entries = matrix.techniques.filter(technique => technique.tactics.includes(tactic.slug))
  return {
    ...tactic,
    techniques: entries.filter(technique => !technique.subtechnique).map(technique => {
      const children = entries.filter(child => child.subtechnique && child.id.startsWith(`${technique.id}.`))
      return { ...technique, children: children.filter(matches), childCount: children.length,
        visible: matches(technique) || (showSubtechniques.value && children.some(matches)) }
    }).filter(technique => technique.visible),
  }
}))
const hasMatches = computed(() => columns.value.some(column => column.techniques.length))
</script>

<template>
  <section class="mb-6 rounded-xl border border-slate-200 bg-slate-50/60 p-4" aria-labelledby="enterprise-matrix-title">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h3 id="enterprise-matrix-title" class="text-base font-semibold text-slate-900">ATT&amp;CK Matrix for Enterprise</h3>
        <p class="mt-1 text-xs text-slate-500">{{ t('kb.matrix.description') }}</p>
      </div>
      <a :href="matrix.matrixUrl" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1.5 text-xs font-semibold text-accent-700 hover:underline">
        {{ t('kb.matrix.open') }} <ExternalLink class="size-3.5" aria-hidden="true" />
      </a>
    </div>
    <div class="my-4 flex flex-wrap items-center gap-4">
      <label class="relative block min-w-0 flex-1 sm:max-w-sm">
        <span class="sr-only">{{ t('kb.matrix.search') }}</span>
        <Search class="pointer-events-none absolute left-3 top-2.5 size-4 text-slate-400" aria-hidden="true" />
        <input v-model="search" type="search" :placeholder="t('kb.matrix.search')" class="w-full rounded-lg border border-slate-300 bg-white py-2 pl-9 pr-3 text-sm focus:outline-none focus:ring-2 focus:ring-accent-500" />
      </label>
      <label class="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-700">
        <input v-model="showSubtechniques" type="checkbox" class="accent-accent-600" />
        {{ t('kb.matrix.subtechniques') }}
      </label>
    </div>
    <p v-if="!hasMatches" role="status" class="py-6 text-center text-sm text-slate-500">{{ t('kb.noMatch') }}</p>
    <div v-else tabindex="0" role="region" :aria-label="t('kb.matrix.scroll')" class="max-h-[34rem] overflow-auto rounded-lg border border-slate-200 bg-white focus:outline-none focus:ring-2 focus:ring-accent-500">
      <div class="flex min-w-max items-start">
        <section v-for="column in columns" :key="column.id" class="w-56 shrink-0 border-r border-slate-200 last:border-r-0" :aria-label="column.name">
          <div class="sticky top-0 z-10 min-h-20 border-b border-slate-200 bg-slate-100 px-3 py-3">
            <a :href="column.url" target="_blank" rel="noopener noreferrer" class="text-sm font-semibold text-slate-900 hover:text-accent-700 hover:underline">{{ column.name }}</a>
            <p class="mt-1 text-[11px] text-slate-500">{{ column.id }} · {{ t('kb.matrix.count', { n: column.techniques.length }) }}</p>
          </div>
          <ul class="space-y-2 p-2">
            <li v-for="technique in column.techniques" :key="technique.id" class="rounded-md border border-slate-200 bg-white p-2 text-xs hover:border-accent-300">
              <a :href="technique.url" target="_blank" rel="noopener noreferrer" class="block font-medium text-slate-800 hover:text-accent-700 hover:underline">
                <span class="mb-0.5 block font-mono text-[10px] text-slate-500">{{ technique.id }}</span>
                {{ technique.name }}<span v-if="!showSubtechniques && technique.childCount" class="ml-1 text-slate-400">({{ technique.childCount }})</span>
              </a>
              <ul v-if="showSubtechniques && technique.children.length" class="mt-2 space-y-2 border-l-2 border-slate-100 pl-2">
                <li v-for="child in technique.children" :key="child.id">
                  <a :href="child.url" target="_blank" rel="noopener noreferrer" class="block text-slate-600 hover:text-accent-700 hover:underline"><span class="block font-mono text-[10px] text-slate-400">{{ child.id }}</span>{{ child.name }}</a>
                </li>
              </ul>
            </li>
          </ul>
        </section>
      </div>
    </div>
    <p class="mt-3 text-[11px] text-slate-500">{{ t('kb.matrix.source', { date: matrix.retrievedAt }) }} · <a :href="matrix.source" target="_blank" rel="noopener noreferrer" class="underline">MITRE ATT&amp;CK®</a></p>
  </section>
</template>
