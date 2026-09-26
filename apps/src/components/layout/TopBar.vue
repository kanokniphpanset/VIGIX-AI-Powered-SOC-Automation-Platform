<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Search, CircleHelp, Compass } from 'lucide-vue-next'
import UserMenu from './UserMenu.vue'
import IncidentNotifications from './IncidentNotifications.vue'
import { useUiStore } from '@/stores/ui'
import { useI18n } from '@/i18n'
import { LANGS } from '@/i18n/messages'

const router = useRouter()
const ui = useUiStore()
const { locale, setLocale, t } = useI18n()
const search = ref('')
const showHelp = ref(false)
const helpRoot = ref<HTMLElement | null>(null)

/** Global search = the Alert Inbox search (IOC, rule, host, user, alert id). */
function runSearch() {
  const q = search.value.trim()
  if (!q) return
  router.push({ path: '/alerts', query: { search: q } })
}

function startTour() {
  showHelp.value = false
  ui.startTour()
}

function onClickOutside(e: MouseEvent) {
  if (helpRoot.value && !helpRoot.value.contains(e.target as Node)) showHelp.value = false
}
onMounted(() => document.addEventListener('mousedown', onClickOutside))
onUnmounted(() => document.removeEventListener('mousedown', onClickOutside))
</script>

<template>
  <header class="flex h-20 shrink-0 items-center justify-between gap-2 border-b border-surface-border bg-white px-4 md:gap-4 md:px-8">
    <div class="relative w-full max-w-md">
      <Search class="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
      <input
        v-model="search"
        type="search"
        :aria-label="t('top.searchLabel')"
        :placeholder="t('top.search')"
        class="w-full rounded-lg border border-slate-200 bg-slate-50 py-2 pl-9 pr-3 text-sm text-slate-700 placeholder:text-slate-400 focus:border-accent-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-accent-100"
        @keyup.enter="runSearch"
      />
    </div>

    <div class="flex shrink-0 items-center gap-1.5">
      <!-- TH / EN -->
      <div role="group" :aria-label="t('lang.label')" data-tour="lang" class="flex overflow-hidden rounded-lg border border-slate-200 text-xs font-semibold">
        <button
          v-for="l in LANGS"
          :key="l"
          type="button"
          :aria-pressed="locale === l"
          class="px-2.5 py-1.5"
          :class="locale === l ? 'bg-navy-800 text-white' : 'bg-white text-slate-600 hover:bg-slate-50'"
          @click="setLocale(l)"
        >
          {{ l === 'th' ? t('lang.th') : t('lang.en') }}
        </button>
      </div>

      <div ref="helpRoot" class="relative">
        <button type="button" :aria-label="t('top.help')" :aria-expanded="showHelp" data-tour="help" class="rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-700" @click="showHelp = !showHelp">
          <CircleHelp class="size-4.5" />
        </button>
        <div v-if="showHelp" class="absolute right-0 z-40 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-xl border border-slate-200 bg-white p-3.5 shadow-lg">
          <p class="text-xs font-semibold text-slate-700">{{ t('top.helpTitle') }}</p>
          <p class="mt-1 text-xs leading-relaxed text-slate-500">{{ t('top.helpBody') }}</p>
          <div class="mt-3 flex items-center justify-between gap-2">
            <button type="button" class="inline-flex items-center gap-1.5 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700" @click="startTour">
              <Compass class="size-3.5" /> {{ t('top.startTour') }}
            </button>
            <button type="button" class="text-xs font-semibold text-slate-500 hover:text-slate-700" @click="showHelp = false">{{ t('top.close') }}</button>
          </div>
        </div>
      </div>
      <IncidentNotifications />
      <div class="mx-1 hidden h-6 w-px bg-slate-200 sm:block" />
      <UserMenu />
    </div>
  </header>
</template>
