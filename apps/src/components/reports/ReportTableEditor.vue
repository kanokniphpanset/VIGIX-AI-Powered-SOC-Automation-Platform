<script setup lang="ts">
import { Plus, X } from 'lucide-vue-next'
import { severityFill, type TableBlock } from '@/utils/socReport'
import { useI18n } from '@/i18n'

/** Editable template table: header cells, body cells, add/remove rows. Edits the block in place (it lives in the reactive report). */
const props = defineProps<{ block: TableBlock }>()
const { t } = useI18n()

function addRow() {
  props.block.rows.push(props.block.columns.map(() => ''))
}
function removeRow(i: number) {
  props.block.rows.splice(i, 1)
}
const tone = (row: string[], i: number) => {
  const f = props.block.severityTone && i === 0 ? severityFill(row[0] ?? '') : null
  return f ? { background: `#${f}`, fontWeight: 700 } : undefined
}
</script>

<template>
  <div class="group/table mb-3">
    <table class="w-full table-fixed border-collapse text-[13px]">
      <colgroup>
        <col v-for="(w, i) in block.widths" :key="i" :style="{ width: `${(w / block.widths.reduce((a, b) => a + b, 0)) * 100}%` }" />
      </colgroup>
      <thead>
        <tr>
          <th v-for="(_, i) in block.columns" :key="i" class="border border-[#B7B7B7] bg-[#24557F] p-0">
            <textarea
              v-model="block.columns[i]"
              rows="1"
              :aria-label="`Column ${i + 1} heading`"
              class="block w-full resize-none bg-transparent px-2 py-1.5 text-center font-semibold text-white [field-sizing:content] focus:bg-[#1c4466] focus:outline-none"
            />
          </th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(row, r) in block.rows" :key="r" class="group/row relative">
          <td v-for="(_, i) in block.columns" :key="i" class="relative border border-[#B7B7B7] p-0" :style="tone(row, i)">
            <textarea
              v-model="row[i]"
              rows="1"
              :aria-label="`Row ${r + 1}, ${block.columns[i]}`"
              class="block w-full resize-none bg-transparent px-2 py-1.5 text-slate-900 [field-sizing:content] focus:bg-amber-50 focus:outline-none"
              :class="block.align[i] === 'center' ? 'text-center' : ''"
            />
            <button
              v-if="i === block.columns.length - 1"
              type="button"
              :title="t('rp.removeRow')"
              :aria-label="`Remove row ${r + 1}`"
              class="absolute -right-7 top-1/2 hidden -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600 group-hover/row:block print:hidden"
              @click="removeRow(r)"
            >
              <X class="size-3.5" />
            </button>
          </td>
        </tr>
      </tbody>
    </table>
    <button
      type="button"
      class="mt-1 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-slate-400 opacity-0 transition hover:bg-slate-100 hover:text-slate-700 focus:opacity-100 group-hover/table:opacity-100"
      @click="addRow"
    >
      <Plus class="size-3.5" /> {{ t('rp.addRow') }}
    </button>
  </div>
</template>
