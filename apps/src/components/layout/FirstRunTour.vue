<script setup lang="ts">
// First-use tour. Opens by itself the first time a user reaches the dashboard, and again from the (?) menu.
// Each step highlights one real element (data-tour="…") with a short explanation; a step whose element is not on
// screen is shown as a centred card. Esc / Skip closes it; either way it is marked as seen for this user.
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { X } from 'lucide-vue-next'
import { useUiStore } from '@/stores/ui'
import { useSessionStore } from '@/stores/session'
import { useI18n, type MsgKey } from '@/i18n'
import { cardPosition, tourSeenKey, tourSteps } from '@/utils/tour'

const ui = useUiStore()
const session = useSessionStore()
const route = useRoute()
const router = useRouter()
const { t } = useI18n()

const steps = computed(() => tourSteps(session.role))
const index = ref(0)
const step = computed(() => steps.value[index.value] ?? null)
const last = computed(() => index.value === steps.value.length - 1)
const card = ref<HTMLElement | null>(null)
const rect = ref<{ top: number; left: number; right: number; bottom: number; width: number; height: number } | null>(null)
const pos = ref<{ top: number; left: number } | null>(null)

function seen(): boolean {
  try {
    return localStorage.getItem(tourSeenKey(session.session?.email)) === 'done'
  } catch {
    return true // storage unavailable: never nag; the (?) menu still opens the tour
  }
}
function markSeen() {
  try {
    localStorage.setItem(tourSeenKey(session.session?.email), 'done')
  } catch {
    /* storage unavailable */
  }
}

/** Measure the highlighted element and place the card next to it (or centred). */
async function place() {
  await nextTick()
  const sel = step.value?.target
  const el = sel ? (document.querySelector(sel) as HTMLElement | null) : null
  const r = el?.getBoundingClientRect()
  if (el && r && r.width > 0 && r.height > 0) {
    el.scrollIntoView({ block: 'nearest', inline: 'nearest' })
    const r2 = el.getBoundingClientRect()
    rect.value = { top: r2.top, left: r2.left, right: r2.right, bottom: r2.bottom, width: r2.width, height: r2.height }
  } else rect.value = null
  const c = card.value?.getBoundingClientRect()
  pos.value = cardPosition(rect.value, { width: window.innerWidth, height: window.innerHeight }, { width: c?.width ?? 340, height: c?.height ?? 220 })
  card.value?.focus()
}

async function open() {
  index.value = 0
  if (route.path !== '/dashboard') await router.push('/dashboard') // most steps point at the dashboard and the shell
  await place()
}
function close() {
  markSeen()
  ui.tourOpen = false
}
function go(delta: number) {
  const next = index.value + delta
  if (next < 0) return
  if (next >= steps.value.length) return close()
  index.value = next
  void place()
}

function onKey(e: KeyboardEvent) {
  if (!ui.tourOpen) return
  if (e.key === 'Escape') close()
  else if (e.key === 'ArrowRight') go(1)
  else if (e.key === 'ArrowLeft') go(-1)
}
const onResize = () => ui.tourOpen && void place()

watch(() => ui.tourOpen, (v) => v && void open())
// First visit: open once the dashboard has rendered its "my work" cards.
watch(
  () => [route.path, session.session?.email] as const,
  ([path, email]) => {
    if (path === '/dashboard' && email && !ui.tourOpen && !seen()) setTimeout(() => { if (!seen()) ui.tourOpen = true }, 1200)
  },
  { immediate: true },
)
onMounted(() => {
  window.addEventListener('keydown', onKey)
  window.addEventListener('resize', onResize)
})
onUnmounted(() => {
  window.removeEventListener('keydown', onKey)
  window.removeEventListener('resize', onResize)
})

const title = computed(() => (step.value ? t(`tour.${step.value.key}.title` as MsgKey) : ''))
const body = computed(() => (step.value ? t(`tour.${step.value.key}.body` as MsgKey) : ''))
const PAD = 6
</script>

<template>
  <Teleport to="body">
    <div v-if="ui.tourOpen && step" class="fixed inset-0 z-[70]" role="dialog" aria-modal="true" :aria-label="t('tour.label')">
      <!-- Dim everything except the highlighted element -->
      <div v-if="rect" class="pointer-events-none fixed rounded-xl ring-2 ring-accent-400 transition-all duration-200" :style="{ top: `${rect.top - PAD}px`, left: `${rect.left - PAD}px`, width: `${rect.width + PAD * 2}px`, height: `${rect.height + PAD * 2}px`, boxShadow: '0 0 0 9999px rgba(15, 23, 42, 0.55)' }" />
      <div v-else class="fixed inset-0 bg-slate-900/55" />
      <div class="fixed inset-0" @click="close" />

      <div
        ref="card"
        tabindex="-1"
        class="fixed w-[340px] max-w-[calc(100vw-2rem)] rounded-2xl bg-white p-5 shadow-2xl outline-none"
        :class="pos ? '' : rect ? 'bottom-4 left-1/2 -translate-x-1/2' : 'left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2'"
        :style="pos ? { top: `${pos.top}px`, left: `${pos.left}px` } : {}"
      >
        <div class="flex items-start justify-between gap-3">
          <p class="text-[11px] font-semibold uppercase tracking-wide text-accent-700">{{ t('tour.label') }} · {{ t('tour.stepOf', { n: index + 1, total: steps.length }) }}</p>
          <button type="button" class="-m-1 rounded p-1 text-slate-400 hover:text-slate-700" :aria-label="t('tour.skip')" @click="close"><X class="size-4" /></button>
        </div>
        <h2 class="mt-1.5 text-base font-bold text-slate-900">{{ title }}</h2>
        <p class="mt-1.5 text-sm leading-relaxed text-slate-600">{{ body }}</p>
        <div class="mt-4 flex items-center gap-1.5" aria-hidden="true">
          <span v-for="(s, i) in steps" :key="s.key" class="h-1.5 rounded-full transition-all" :class="i === index ? 'w-5 bg-navy-800' : 'w-1.5 bg-slate-200'" />
        </div>
        <div class="mt-4 flex items-center justify-between gap-2">
          <button type="button" class="text-sm font-medium text-slate-500 hover:text-slate-800" @click="close">{{ t('tour.skip') }}</button>
          <div class="flex gap-2">
            <button v-if="index > 0" type="button" class="rounded-lg border border-slate-200 px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50" @click="go(-1)">{{ t('tour.back') }}</button>
            <button type="button" class="rounded-lg bg-navy-800 px-4 py-2 text-sm font-semibold text-white hover:bg-navy-700" @click="go(1)">{{ last ? t('tour.done') : t('tour.next') }}</button>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>
