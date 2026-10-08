<script setup lang="ts">
import { computed, onBeforeUnmount, watch } from 'vue'
import { ref } from 'vue'
import { Loader2, RotateCw } from 'lucide-vue-next'
import { incidentsApi, type RecommendationPreview } from '@/api/vigix'
import RecommendationPreviewBody from './RecommendationPreviewBody.vue'

const props = defineProps<{ incidentId: string; revision?: string }>()
/** The loaded preview, so the page can show its evidence basis in its own place (null while reloading for another incident). */
const emit = defineEmits<{ preview: [value: RecommendationPreview | null] }>()
const result = ref<RecommendationPreview | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)
let request = 0
let disposed = false
async function load(silent = false) {
  const token = ++request
  const incidentId = props.incidentId
  if (!silent) loading.value = true
  error.value = null
  try {
    const data = await incidentsApi.recommendationPreview(incidentId)
    if (!disposed && token === request && incidentId === props.incidentId) { result.value = data; emit('preview', data) }
  } catch (e) {
    if (!disposed && token === request) error.value = e instanceof Error ? e.message : String(e)
  } finally {
    if (!disposed && token === request) loading.value = false
  }
}
watch(() => [props.incidentId, props.revision], () => {
  result.value = null
  emit('preview', null)
  void load()
}, { immediate: true })
// Read-only refresh binds the displayed draft to newly associated alerts and Re-hunt state.
const refresh = setInterval(() => { if (!loading.value) void load(true) }, 30000)
onBeforeUnmount(() => { disposed = true; ++request; clearInterval(refresh) })
const displayed = computed(() => result.value ? {
  ...result.value,
  label: result.value.reviewed
    ? 'คำแนะนำฉบับร่าง — รอ SOC ตรวจรับก่อนส่งให้ IR'
    : 'คำแนะนำฉบับร่าง — ฐานความรู้ยังรอ IR review ห้ามใช้เป็นคำสั่งดำเนินการ',
} : null)
</script>

<template>
  <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="incident-recommendation-title">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="incident-recommendation-title" class="text-lg font-semibold text-slate-900">คำแนะนำเพื่อยับยั้ง Incident</h2>
        <p class="mt-1 text-sm text-slate-500">ประเมินจาก Alert และหลักฐานที่ผูกกับเคสนี้ อัปเดตเมื่อมีข้อมูลใหม่</p>
      </div>
      <button type="button" class="inline-flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-700 disabled:opacity-50" :disabled="loading" @click="load()">
        <Loader2 v-if="loading" class="size-4 animate-spin" /><RotateCw v-else class="size-4" /> อัปเดตคำแนะนำ
      </button>
    </div>
    <p v-if="loading" class="mt-4 text-sm text-slate-500" role="status">กำลังประเมินหลักฐานของเคส…</p>
    <p v-if="error" class="mt-4 rounded-lg bg-rose-50 p-3 text-sm text-rose-800" role="alert">โหลดคำแนะนำล่าสุดไม่ได้: {{ error }}<span v-if="result" class="block">ข้อมูลด้านล่างเป็นผลก่อนหน้า กรุณาอัปเดตก่อนใช้อ้างอิง</span></p>
    <template v-if="displayed && !loading">
      <RecommendationPreviewBody v-if="displayed.available" :preview="displayed" incident-presentation hide-basis />
      <p v-else class="mt-4 rounded-lg bg-slate-50 p-3 text-sm text-slate-700">ยังสร้างคำแนะนำไม่ได้: {{ displayed.unavailableReason }}</p>
    </template>
    <p class="mt-4 border-t border-slate-100 pt-3 text-xs text-slate-500">ไม่มีการส่ง Ticket หรือดำเนินมาตรการอัตโนมัติจากหน้านี้</p>
  </section>
</template>
