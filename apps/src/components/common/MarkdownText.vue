<script setup lang="ts">
// Renders LLM Markdown (utils/markdown.ts) with plain template nodes — no v-html, so model output cannot inject HTML.
import { computed } from 'vue'
import { parseMarkdown, type Inline } from '@/utils/markdown'

const props = defineProps<{ text: string | null | undefined }>()
const blocks = computed(() => parseMarkdown(props.text))
const HEADING: Record<number, string> = { 1: 'text-base', 2: 'text-base', 3: 'text-sm', 4: 'text-sm', 5: 'text-sm', 6: 'text-sm' }
const inlineClass = (i: Inline) =>
  i.kind === 'strong' ? 'font-semibold text-slate-900' : i.kind === 'em' ? 'italic' : i.kind === 'code' ? 'break-all rounded bg-slate-100 px-1 font-mono text-[0.85em] text-slate-800' : ''
</script>

<template>
  <div class="space-y-2 text-sm leading-relaxed text-slate-800">
    <template v-for="(b, bi) in blocks" :key="bi">
      <p v-if="b.kind === 'heading'" class="pt-1 font-semibold text-slate-900" :class="HEADING[b.level]" role="heading" :aria-level="b.level">
        <span v-for="(i, ii) in b.inlines" :key="ii" :class="inlineClass(i)">{{ i.text }}</span>
      </p>
      <p v-else-if="b.kind === 'paragraph'"><span v-for="(i, ii) in b.inlines" :key="ii" :class="inlineClass(i)">{{ i.text }}</span></p>
      <component :is="b.ordered ? 'ol' : 'ul'" v-else-if="b.kind === 'list'" class="space-y-1 pl-5" :class="b.ordered ? 'list-decimal' : 'list-disc'">
        <li v-for="(item, li) in b.items" :key="li" :style="item.depth ? { marginLeft: `${item.depth * 1}rem` } : undefined">
          <span v-for="(i, ii) in item.inlines" :key="ii" :class="inlineClass(i)">{{ i.text }}</span>
        </li>
      </component>
      <pre v-else-if="b.kind === 'code'" class="overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100">{{ b.text }}</pre>
      <hr v-else-if="b.kind === 'hr'" class="border-slate-200" />
    </template>
  </div>
</template>
