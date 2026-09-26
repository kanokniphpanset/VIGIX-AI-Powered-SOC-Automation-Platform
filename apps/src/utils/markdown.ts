// Minimal Markdown -> block/inline tree for LLM analysis text (pure; runs under `node --test`).
// Rendered by components/common/MarkdownText.vue with plain Vue template nodes — never v-html — so model output can
// never inject HTML/script. Supported: headings (#..######), paragraphs, bullet / numbered lists (with indentation),
// fenced code blocks, horizontal rules, **bold**, *italic* / _italic_, `code`. Anything else is shown as text.

export type Inline = { kind: 'text' | 'strong' | 'em' | 'code'; text: string }
export type Block =
  | { kind: 'heading'; level: number; inlines: Inline[] }
  | { kind: 'paragraph'; inlines: Inline[] }
  | { kind: 'list'; ordered: boolean; items: { depth: number; inlines: Inline[] }[] }
  | { kind: 'code'; text: string }
  | { kind: 'hr' }

const INLINE = /(\*\*[^*\n]+?\*\*|__[^_\n]+?__|`[^`\n]+`|\*[^*\s][^*\n]*?\*|(?<![\w])_[^_\s][^_\n]*?_(?![\w]))/g

export function parseInline(text: string): Inline[] {
  const out: Inline[] = []
  let last = 0
  for (const m of text.matchAll(INLINE)) {
    const tok = m[0]
    const at = m.index ?? 0
    if (at > last) out.push({ kind: 'text', text: text.slice(last, at) })
    if (tok.startsWith('**') || tok.startsWith('__')) out.push({ kind: 'strong', text: tok.slice(2, -2) })
    else if (tok.startsWith('`')) out.push({ kind: 'code', text: tok.slice(1, -1) })
    else out.push({ kind: 'em', text: tok.slice(1, -1) })
    last = at + tok.length
  }
  if (last < text.length) out.push({ kind: 'text', text: text.slice(last) })
  return out.filter((i) => i.text.length > 0)
}

const LIST_ITEM = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/

export function parseMarkdown(src: string | null | undefined): Block[] {
  const lines = (src ?? '').replace(/\r\n?/g, '\n').split('\n')
  const blocks: Block[] = []
  let para: string[] = []
  const flush = () => {
    if (para.length) blocks.push({ kind: 'paragraph', inlines: parseInline(para.join(' ').trim()) })
    para = []
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trim()
    if (!trimmed) { flush(); continue }
    if (trimmed.startsWith('```')) {
      flush()
      const code: string[] = []
      for (i++; i < lines.length && !lines[i].trim().startsWith('```'); i++) code.push(lines[i])
      blocks.push({ kind: 'code', text: code.join('\n') })
      continue
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(trimmed)
    if (heading) { flush(); blocks.push({ kind: 'heading', level: heading[1].length, inlines: parseInline(heading[2].replace(/\s*#+\s*$/, '')) }); continue }
    if (/^([-*_])(\s*\1){2,}$/.test(trimmed)) { flush(); blocks.push({ kind: 'hr' }); continue }
    const item = LIST_ITEM.exec(line)
    if (item) {
      flush()
      const ordered = /\d/.test(item[2])
      const depth = Math.floor(item[1].replace(/\t/g, '    ').length / 2)
      const prev = blocks[blocks.length - 1]
      const entry = { depth, inlines: parseInline(item[3].trim()) }
      if (prev && prev.kind === 'list' && (prev.ordered === ordered || depth > 0)) prev.items.push(entry)
      else blocks.push({ kind: 'list', ordered, items: [entry] })
      continue
    }
    // A continuation line directly under a list item belongs to that item.
    const prev = blocks[blocks.length - 1]
    if (!para.length && prev && prev.kind === 'list' && /^\s+/.test(line)) {
      prev.items[prev.items.length - 1].inlines.push({ kind: 'text', text: ' ' }, ...parseInline(trimmed))
      continue
    }
    para.push(trimmed)
  }
  flush()
  return blocks
}
