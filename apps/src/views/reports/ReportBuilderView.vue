<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowLeft, Eye, EyeOff, FileText, Plus, Printer, RotateCw, X } from 'lucide-vue-next'
import { dashboardApi } from '@/api/vigix'
import ReportTableEditor from '@/components/reports/ReportTableEditor.vue'
import logoUrl from '@/assets/report/tnet-logo.png'
import { COMPANY, buildSocReport, isSocReport, periodOf, setReportPeriod, type ReportSection, type SocReport } from '@/utils/socReport'
import { socReportDocx } from '@/utils/socReportDocx'
import { socReportHtml } from '@/utils/socReportHtml'
import { useI18n } from '@/i18n'

/**
 * Monthly SOC Operations Report on the T-NET company template (header, logo, section layout and table styling are
 * the template; see utils/socReport.ts). Values are pre-filled from the live VIGIX summary and every text/number is
 * editable before export. Export = Word (.docx) or Print / Save as PDF. The draft stays in this browser only
 * (localStorage) so an unfinished edit survives a reload.
 */
const router = useRouter()
const { t } = useI18n()
const DRAFT_KEY = 'vigix.report.soc.v2'

const loading = ref(false)
const exporting = ref(false)
const error = ref('')
const report = ref<SocReport | null>(null)
const period = ref(periodOf(new Date()))

async function fill(confirmOverwrite: boolean) {
  if (confirmOverwrite && report.value && !window.confirm(t('rp.refillConfirm'))) return
  loading.value = true
  error.value = ''
  try {
    const summary = await dashboardApi.summary(30)
    report.value = buildSocReport(summary, { period: period.value, preparedAt: new Date() })
  } catch {
    error.value = t('rp.loadFailed')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  try {
    const raw = localStorage.getItem(DRAFT_KEY)
    const draft: unknown = raw ? JSON.parse(raw) : null
    if (isSocReport(draft)) {
      report.value = draft
      period.value = draft.period
      return
    }
  } catch {
    /* no usable draft */
  }
  void fill(false)
})

watch(
  report,
  (r) => {
    if (!r) return
    try {
      localStorage.setItem(DRAFT_KEY, JSON.stringify(r))
    } catch {
      /* storage unavailable — edits are simply not kept across reloads */
    }
  },
  { deep: true },
)

watch(period, (p) => {
  if (report.value && p && p !== report.value.period) setReportPeriod(report.value, p)
})

function addText(sec: ReportSection) {
  sec.blocks.push({ kind: 'text', text: '' })
}

async function logoBytes(): Promise<Blob> {
  return (await fetch(logoUrl)).blob()
}
const dataUrl = (b: Blob) =>
  new Promise<string>((resolve, reject) => {
    const fr = new FileReader()
    fr.onload = () => resolve(String(fr.result))
    fr.onerror = () => reject(fr.error)
    fr.readAsDataURL(b)
  })

async function exportDocx() {
  if (!report.value) return
  exporting.value = true
  error.value = ''
  try {
    const blob = await socReportDocx(report.value, await (await logoBytes()).arrayBuffer())
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `VIGIX_Monthly_SOC_Report_${report.value.period}.docx`
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 1000)
  } catch {
    error.value = t('rp.docxFailed')
  } finally {
    exporting.value = false
  }
}

async function printPdf() {
  if (!report.value) return
  const w = window.open('', '_blank')
  if (!w) {
    error.value = t('rp.popupBlocked')
    return
  }
  w.document.write(socReportHtml(report.value, await dataUrl(await logoBytes())))
  w.document.close()
  w.focus()
  // Let the logo decode before the print dialog snapshots the page.
  setTimeout(() => w.print(), 300)
}
</script>

<template>
  <div>
    <button type="button" class="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800" @click="router.push('/dashboard')">
      <ArrowLeft class="size-4" /> {{ t('rp.back') }}
    </button>

    <div class="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <p class="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">{{ t('rp.kind') }}</p>
        <h1 class="mt-1 text-2xl font-bold tracking-tight text-slate-900">{{ t('rp.title') }}</h1>
        <p class="mt-1 text-sm text-slate-500">{{ t('rp.hint') }}</p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <label class="flex items-center gap-2 text-xs text-slate-600">
          {{ t('rp.period') }}
          <input v-model="period" type="month" class="rounded-lg border border-slate-300 px-2 py-1.5 text-sm" />
        </label>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50" :disabled="loading" @click="fill(true)">
          <RotateCw class="size-4" :class="loading ? 'animate-spin' : ''" /> {{ t('rp.refill') }}
        </button>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50" :disabled="!report" @click="printPdf">
          <Printer class="size-4" /> Print / PDF
        </button>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg bg-[#24557F] px-3 py-2 text-sm font-semibold text-white hover:bg-[#1c4466] disabled:opacity-50" :disabled="!report || exporting" @click="exportDocx">
          <FileText class="size-4" /> {{ exporting ? t('rp.exporting') : t('rp.export') }}
        </button>
      </div>
    </div>

    <p v-if="error" class="mb-4 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ error }}</p>
    <p v-if="loading && !report" class="text-sm text-slate-500">{{ t('rp.loading') }}</p>

    <!-- The page: laid out like the Word template (Letter width). -->
    <article v-if="report" class="mx-auto max-w-[850px] bg-white px-8 py-8 shadow-sm ring-1 ring-slate-200 md:px-12">
      <header class="flex items-center justify-between gap-4">
        <img :src="logoUrl" alt="T-NET IT Solution" class="h-auto w-20 shrink-0" />
        <div class="text-right text-[13px] leading-snug text-slate-900">
          <p class="text-[15px] font-bold">{{ COMPANY.name }}</p>
          <p v-for="l in COMPANY.address" :key="l">{{ l }}</p>
          <p>{{ COMPANY.contact }}</p>
        </div>
      </header>

      <textarea v-model="report.title" rows="1" aria-label="Report title" class="mt-4 block w-full resize-none bg-transparent text-center text-lg font-bold text-slate-900 [field-sizing:content] focus:bg-amber-50 focus:outline-none" />
      <textarea v-model="report.subtitle" rows="1" aria-label="Report subtitle" class="mb-3 block w-full resize-none bg-transparent text-center text-sm font-semibold text-slate-800 [field-sizing:content] focus:bg-amber-50 focus:outline-none" />

      <table class="w-full table-fixed border-collapse text-[13px]">
        <tbody>
          <tr v-for="r in Math.ceil(report.meta.length / 2)" :key="r">
            <template v-for="(m, mi) in report.meta.slice((r - 1) * 2, (r - 1) * 2 + 2)" :key="mi">
              <th class="w-[21%] border border-[#B7B7B7] bg-[#24557F] p-0">
                <textarea v-model="m.label" rows="1" aria-label="Cover label" class="block w-full resize-none bg-transparent px-2 py-1.5 text-center font-semibold text-white [field-sizing:content] focus:outline-none" />
              </th>
              <td class="border border-[#B7B7B7] p-0">
                <textarea v-model="m.value" rows="1" :aria-label="m.label" class="block w-full resize-none bg-transparent px-2 py-1.5 [field-sizing:content] focus:bg-amber-50 focus:outline-none" />
              </td>
            </template>
          </tr>
        </tbody>
      </table>

      <section v-for="sec in report.sections" :key="sec.id" class="group/sec mt-6" :class="sec.include ? '' : 'opacity-40'">
        <div v-if="sec.pageBreakBefore" class="mb-4 border-t border-dashed border-slate-300 text-center text-[10px] uppercase tracking-widest text-slate-300">{{ t('rp.pageBreak') }}</div>
        <div class="mb-2 flex items-start gap-2">
          <textarea v-model="sec.title" rows="1" :aria-label="`Section title ${sec.title}`" class="block w-full resize-none bg-transparent text-base font-bold text-slate-900 [field-sizing:content] focus:bg-amber-50 focus:outline-none" />
          <button
            type="button"
            class="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
            :title="sec.include ? t('rp.exclude') : t('rp.include')"
            :aria-label="sec.include ? `Exclude ${sec.title}` : `Include ${sec.title}`"
            @click="sec.include = !sec.include"
          >
            <Eye v-if="sec.include" class="size-4" /><EyeOff v-else class="size-4" />
          </button>
        </div>

        <template v-for="(b, bi) in sec.blocks" :key="bi">
          <table v-if="b.kind === 'kpis'" class="mb-3 w-full table-fixed border-collapse">
            <tbody>
              <tr>
                <th v-for="(k, ki) in b.items" :key="ki" class="border border-[#B7B7B7] bg-[#24557F] p-0">
                  <textarea v-model="k.label" rows="1" aria-label="KPI label" class="block w-full resize-none bg-transparent px-1 py-1.5 text-center text-xs font-semibold text-white [field-sizing:content] focus:outline-none" />
                </th>
              </tr>
              <tr>
                <td v-for="(k, ki) in b.items" :key="ki" class="border border-[#B7B7B7] bg-[#F7F7F7] p-0">
                  <input v-model="k.value" :aria-label="k.label" class="block w-full bg-transparent py-2 text-center text-2xl font-bold text-slate-900 focus:bg-amber-50 focus:outline-none" />
                </td>
              </tr>
            </tbody>
          </table>

          <ReportTableEditor v-else-if="b.kind === 'table'" :block="b" />

          <div v-else class="group/blk relative mb-2">
            <textarea
              v-model="b.text"
              rows="2"
              :aria-label="b.kind === 'note' ? 'Remark' : b.kind === 'heading' ? 'Sub-heading' : 'Paragraph'"
              :placeholder="t('rp.typeText')"
              class="block w-full resize-none px-2 py-1.5 text-[13px] leading-relaxed [field-sizing:content] focus:outline-none"
              :class="
                b.kind === 'note'
                  ? 'border border-[#D9A441] bg-[#FFF2CC] text-[#444444]'
                  : ['rounded bg-transparent text-slate-800 hover:bg-slate-50 focus:bg-amber-50', b.kind === 'heading' ? 'mt-2 font-semibold text-slate-900' : '']
              "
            />
            <button
              type="button"
              :title="t('rp.removeText')"
              aria-label="Remove paragraph"
              class="absolute -right-7 top-1 hidden rounded p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600 group-hover/blk:block"
              @click="sec.blocks.splice(bi, 1)"
            >
              <X class="size-3.5" />
            </button>
          </div>
        </template>

        <button type="button" class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-slate-400 opacity-0 transition hover:bg-slate-100 hover:text-slate-700 focus:opacity-100 group-hover/sec:opacity-100" @click="addText(sec)">
          <Plus class="size-3.5" /> {{ t('rp.addText') }}
        </button>
      </section>

      <footer class="mt-8 border-t border-slate-200 pt-2 text-center text-xs text-slate-500">
        <input v-model="report.footer" aria-label="Footer text" class="w-full bg-transparent text-center focus:bg-amber-50 focus:outline-none" />
      </footer>
    </article>
  </div>
</template>
