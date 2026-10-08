<script setup lang="ts">
// Recommendation Preview (subtype knowledge). Read-only GETs: nothing here creates a recommendation, ticket or action, and there
// is no send / execute control. Two SEPARATE blocks:
//  1. the incident preview - computed from THIS incident's real alerts/evidence (never filled from fixtures);
//  2. simulated examples - only when the backend enables fixtures; labelled as simulated data, unrelated to this incident.
import { onMounted, ref } from 'vue'
import { Eye, FlaskConical, Loader2, RotateCw } from 'lucide-vue-next'
import { incidentsApi, workflowApi, type RecommendationPreview } from '@/api/vigix'
import RecommendationPreviewBody from '@/components/incidents/RecommendationPreviewBody.vue'
import { useI18n } from '@/i18n'

const props = defineProps<{ incidentId: string }>()
const { t } = useI18n()

const preview = ref<RecommendationPreview | null>(null)
const open = ref(false)
const loading = ref(false)
const error = ref<string | null>(null)

async function load() {
  open.value = true
  loading.value = true
  error.value = null
  try {
    preview.value = await incidentsApi.recommendationPreview(props.incidentId)
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

const fixtures = ref<{ id: string; title: string; note: string }[]>([])
const fixtureId = ref('')
const fixture = ref<RecommendationPreview | null>(null)
const fixtureLoading = ref(false)
const fixtureError = ref<string | null>(null)

onMounted(async () => {
  try {
    const res = await workflowApi.previewFixtures()
    fixtures.value = res.enabled ? res.items : []
    fixtureId.value = fixtures.value[0]?.id ?? ''
  } catch {
    fixtures.value = []
  }
})

async function loadFixture() {
  if (!fixtureId.value) return
  fixtureLoading.value = true
  fixtureError.value = null
  try {
    fixture.value = await workflowApi.previewFixture(fixtureId.value)
  } catch (e) {
    fixtureError.value = e instanceof Error ? e.message : String(e)
  } finally {
    fixtureLoading.value = false
  }
}
</script>

<template>
  <div class="mb-5 space-y-3">
    <!-- 1. Incident preview (real evidence of this incident) -->
    <section class="rounded-xl border-2 border-dashed border-amber-300 bg-amber-50/30 p-4" aria-labelledby="rec-preview-title">
      <div class="flex flex-wrap items-center gap-2">
        <h3 id="rec-preview-title" class="text-sm font-semibold text-slate-800">{{ t('inc.pv.title') }}</h3>
        <div class="ml-auto flex gap-2">
          <button
            type="button"
            class="inline-flex items-center gap-1 rounded-lg border border-amber-400 bg-white px-3 py-1.5 text-xs font-semibold text-amber-900 hover:bg-amber-50 disabled:opacity-50"
            :disabled="loading"
            :aria-busy="loading"
            @click="load"
          >
            <Loader2 v-if="loading" class="size-3.5 animate-spin" /><RotateCw v-else-if="preview && open" class="size-3.5" /><Eye v-else class="size-3.5" />
            {{ preview && open ? t('inc.pv.reload') : t('inc.pv.show') }}
          </button>
        </div>
      </div>
      <p class="mt-1 text-xs text-slate-600">{{ t('inc.pv.intro') }}</p>
      <p class="mt-0.5 text-[11px] font-medium text-amber-900">{{ t('inc.pv.notGenerate') }}</p>

      <template v-if="open">
        <p v-if="loading" class="mt-3 text-xs text-slate-500" role="status">{{ t('inc.pv.loading') }}</p>
        <p v-else-if="error" class="mt-3 rounded bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ t('inc.pv.error', { msg: error }) }}</p>
        <template v-if="preview && !loading">
          <p v-if="!preview.available" class="mt-3 rounded bg-slate-100 px-3 py-2 text-xs text-slate-700">{{ t('inc.pv.unavailable', { reason: preview.unavailableReason ?? '' }) }}</p>
          <RecommendationPreviewBody v-else :preview="preview" />
        </template>
      </template>
    </section>

    <!-- 2. Simulated examples: a separate block, never mixed into the incident preview -->
    <section v-if="fixtures.length" class="rounded-xl border-2 border-violet-300 bg-violet-50/40 p-4">
      <h3 class="flex items-center gap-1.5 text-sm font-semibold text-violet-800"><FlaskConical class="size-4" /> {{ t('inc.pv.fixtureSection') }}</h3>
      <p class="mt-2 text-xs text-slate-600">{{ t('inc.pv.fixturesHint') }}</p>
      <div class="mt-2 flex flex-wrap items-center gap-2">
        <label class="sr-only" for="rec-preview-fixture">{{ t('inc.pv.fixturePick') }}</label>
        <select id="rec-preview-fixture" v-model="fixtureId" class="min-w-0 max-w-full flex-1 rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-xs">
          <option v-for="f in fixtures" :key="f.id" :value="f.id">{{ f.title }}</option>
        </select>
        <button type="button" class="inline-flex items-center gap-1 rounded-lg border border-violet-300 bg-white px-3 py-1.5 text-xs text-violet-800 hover:bg-violet-50 disabled:opacity-50" :disabled="fixtureLoading || !fixtureId" :aria-busy="fixtureLoading" @click="loadFixture">
          <Loader2 v-if="fixtureLoading" class="size-3.5 animate-spin" /><Eye v-else class="size-3.5" /> {{ t('inc.pv.fixtures') }}
        </button>
      </div>
      <p v-if="fixtureError" class="mt-3 rounded bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ t('inc.pv.error', { msg: fixtureError }) }}</p>
      <RecommendationPreviewBody v-if="fixture && !fixtureLoading" :preview="fixture" />
    </section>
  </div>
</template>
