import { COMPANY, REPORT_COLORS as C, severityFill, type ReportBlock, type SocReport } from './socReport'

/**
 * Standalone HTML of the report for Print / Save as PDF — same layout as the Word export (utils/socReportDocx.ts).
 * `logoSrc` should be a data: URL so the printed window needs no network access.
 */

const esc = (t: string) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
const lines = (t: string) => esc(t).replace(/\n/g, '<br>')

function block(b: ReportBlock): string {
  switch (b.kind) {
    case 'text':
      return b.text
        .split('\n')
        .filter((t) => t.trim())
        .map((t) => `<p>${esc(t)}</p>`)
        .join('')
    case 'heading':
      return `<h3>${esc(b.text)}</h3>`
    case 'note':
      return `<table class="note"><tr><td>${lines(b.text)}</td></tr></table>`
    case 'kpis':
      return `<table class="kpi"><tr>${b.items.map((k) => `<th>${lines(k.label)}</th>`).join('')}</tr><tr>${b.items.map((k) => `<td>${lines(k.value)}</td>`).join('')}</tr></table>`
    case 'table': {
      const all = b.widths.reduce((a, c) => a + c, 0) || 1
      const cols = b.columns.map((_, i) => `<col style="width:${(((b.widths[i] ?? 1) / all) * 100).toFixed(2)}%">`).join('')
      const head = `<thead><tr>${b.columns.map((c) => `<th>${lines(c)}</th>`).join('')}</tr></thead>`
      const body = b.rows
        .map(
          (r) =>
            `<tr>${b.columns
              .map((_, i) => {
                const tone = b.severityTone && i === 0 ? severityFill(r[0] ?? '') : null
                const style = [b.align[i] === 'center' ? 'text-align:center' : '', tone ? `background:#${tone};font-weight:700` : ''].filter(Boolean).join(';')
                return `<td${style ? ` style="${style}"` : ''}>${lines(r[i] ?? '')}</td>`
              })
              .join('')}</tr>`,
        )
        .join('')
      return `<table class="grid"><colgroup>${cols}</colgroup>${head}<tbody>${body}</tbody></table>`
    }
  }
}

export function socReportHtml(r: SocReport, logoSrc: string): string {
  const meta: string[] = []
  for (let i = 0; i < r.meta.length; i += 2) {
    const pair = r.meta.slice(i, i + 2)
    meta.push(
      `<tr>${pair.map((m) => `<th>${lines(m.label)}</th><td${pair.length === 1 ? ' colspan="3"' : ''}>${lines(m.value)}</td>`).join('')}</tr>`,
    )
  }
  const sections = r.sections
    .filter((s) => s.include)
    .map((s) => `<section${s.pageBreakBefore ? ' class="break"' : ''}><h2>${esc(s.title)}</h2>${s.blocks.map(block).join('')}</section>`)
    .join('\n')

  return `<!doctype html><html lang="th"><head><meta charset="utf-8"><title>${esc(r.title)}</title>
<style>
@page{size:letter;margin:12mm 14mm 14mm;@bottom-center{content:"${esc(r.footer)}  |  หน้า " counter(page);font:10pt 'TH Sarabun New','Sarabun',Tahoma,sans-serif;color:#666}}
*{box-sizing:border-box}
body{font:15px/1.45 'TH Sarabun New','Sarabun','Angsana New',Tahoma,sans-serif;color:#000;max-width:800px;margin:24px auto;padding:0 16px;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.head{display:flex;align-items:center;justify-content:space-between;gap:16px}
.head img{width:84px;height:auto}
.head .co{text-align:right;font-size:14px;line-height:1.35}
.head .co b{font-size:17px}
h1{text-align:center;font-size:21px;margin:14px 0 0}
.sub{text-align:center;font-weight:700;font-size:16px;margin:2px 0 12px}
h2{font-size:18px;margin:18px 0 8px;break-after:avoid}
h3{font-size:16px;margin:14px 0 6px;break-after:avoid}
p{margin:6px 0}
table{width:100%;border-collapse:collapse;margin:0 0 10px;break-inside:auto}
tr{break-inside:avoid}
th,td{border:1px solid #${C.border};padding:4px 7px;vertical-align:middle}
th{background:#${C.header};color:#fff;font-weight:700;text-align:center}
table.meta th{width:20.8%}
table.kpi{table-layout:fixed}
table.kpi th{font-size:14px}
table.kpi td{background:#${C.kpiFill};text-align:center;font-weight:700;font-size:24px}
table.note td{border-color:#${C.noteBorder};background:#${C.noteFill};color:#${C.noteText};font-size:14px}
section.break{break-before:page}
</style></head><body>
<div class="head"><img src="${esc(logoSrc)}" alt="T-NET IT Solution"><div class="co"><b>${esc(COMPANY.name)}</b><br>${COMPANY.address.map(esc).join('<br>')}<br>${esc(COMPANY.contact)}</div></div>
<h1>${esc(r.title)}</h1>
<p class="sub">${esc(r.subtitle)}</p>
<table class="meta">${meta.join('')}</table>
${sections}
</body></html>`
}
