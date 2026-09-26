import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  ImageRun,
  Packer,
  PageNumber,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  VerticalAlign,
  WidthType,
  type ITableCellBorders,
} from 'docx'
import { COMPANY, REPORT_COLORS as C, severityFill, type Align, type ReportBlock, type SocReport, type TableBlock } from './socReport'

/**
 * Word export of the Monthly SOC Operations Report, laid out like the company template:
 * US Letter, template margins, T-NET logo + address header, #24557F table headers, B7B7B7 grid, footer with page number.
 * Font is the template's Normal font (Angsana New); sizes are in half-points and apply to Thai (complex script) too.
 */

const FONT = { ascii: 'Angsana New', hAnsi: 'Angsana New', cs: 'Angsana New', eastAsia: 'Angsana New' }
const PAGE_W = 12240
const MARGIN = { top: 680, right: 794, bottom: 737, left: 794, header: 720, footer: 360 }
const TABLE_W = 10080
const SIZE = { company: 36, subheading: 32, address: 28, title: 40, subtitle: 32, heading: 36, body: 30, cell: 30, kpiLabel: 28, kpiValue: 48, note: 28, footer: 24 }

const line = (color: string) => ({ style: BorderStyle.SINGLE, size: 6, color })
const grid = (color: string): ITableCellBorders => ({ top: line(color), bottom: line(color), left: line(color), right: line(color) })
const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' }
const noBorders = { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE }
const tableBorders = (color: string) => ({ ...grid(color), insideHorizontal: line(color), insideVertical: line(color) })
const fill = (hex: string) => ({ type: ShadingType.CLEAR, color: 'auto', fill: hex })
const jc = (a: Align) => (a === 'center' ? AlignmentType.CENTER : AlignmentType.LEFT)

/** Multi-line cell/paragraph text: one run per line with breaks between. */
function runs(text: string, opts: { size: number; bold?: boolean; color?: string }): TextRun[] {
  return text.split('\n').map((t, i) => new TextRun({ text: t, break: i ? 1 : 0, font: FONT, ...opts }))
}

/** Integer widths that sum exactly to `total`. */
function scale(widths: number[], total: number): number[] {
  const all = widths.reduce((a, b) => a + b, 0) || 1
  const out = widths.map((w) => Math.floor((w / all) * total))
  out[out.length - 1] += total - out.reduce((a, b) => a + b, 0)
  return out
}

function cell(text: string, width: number, o: { head?: boolean; align?: Align; shade?: string | null; size?: number; bold?: boolean; color?: string; span?: number; borders?: ITableCellBorders }) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    columnSpan: o.span,
    verticalAlign: VerticalAlign.CENTER,
    shading: o.head ? fill(C.header) : o.shade ? fill(o.shade) : undefined,
    borders: o.borders,
    margins: { top: 50, bottom: 50, left: 100, right: 100 },
    children: [
      new Paragraph({
        alignment: o.head ? AlignmentType.CENTER : jc(o.align ?? 'left'),
        children: runs(text, { size: o.size ?? SIZE.cell, bold: o.head || o.bold, color: o.head ? 'FFFFFF' : (o.color ?? '000000') }),
      }),
    ],
  })
}

function dataTable(b: TableBlock): Table {
  const w = scale(b.widths.length === b.columns.length ? b.widths : b.columns.map(() => 1), TABLE_W)
  return new Table({
    width: { size: TABLE_W, type: WidthType.DXA },
    columnWidths: w,
    alignment: AlignmentType.CENTER,
    borders: tableBorders(C.border),
    rows: [
      new TableRow({ tableHeader: true, children: b.columns.map((c, i) => cell(c, w[i], { head: true })) }),
      ...b.rows.map(
        (r) =>
          new TableRow({
            cantSplit: true,
            children: b.columns.map((_, i) =>
              cell(r[i] ?? '', w[i], { align: b.align[i] ?? 'left', shade: b.severityTone && i === 0 ? severityFill(r[0] ?? '') : null, bold: b.severityTone && i === 0 }),
            ),
          }),
      ),
    ],
  })
}

function block(b: ReportBlock): (Paragraph | Table)[] {
  switch (b.kind) {
    case 'text':
      return b.text
        .split('\n')
        .filter((t, i, all) => t.trim() || all.length === 1)
        .map((t) => new Paragraph({ spacing: { before: 80, after: 80, line: 240 }, children: [new TextRun({ text: t, font: FONT, size: SIZE.body })] }))
    case 'heading':
      return [new Paragraph({ keepNext: true, spacing: { before: 160, after: 80, line: 240 }, children: [new TextRun({ text: b.text, bold: true, font: FONT, size: SIZE.subheading })] })]
    case 'note':
      return [
        new Table({
          width: { size: TABLE_W, type: WidthType.DXA },
          columnWidths: [TABLE_W],
          alignment: AlignmentType.CENTER,
          borders: tableBorders(C.noteBorder),
          rows: [new TableRow({ children: [cell(b.text, TABLE_W, { shade: C.noteFill, color: C.noteText, size: SIZE.note })] })],
        }),
      ]
    case 'kpis': {
      const w = scale(b.items.map(() => 1), TABLE_W)
      return [
        new Table({
          width: { size: TABLE_W, type: WidthType.DXA },
          columnWidths: w,
          alignment: AlignmentType.CENTER,
          borders: tableBorders(C.border),
          rows: [
            new TableRow({ children: b.items.map((k, i) => cell(k.label, w[i], { head: true, size: SIZE.kpiLabel })) }),
            new TableRow({ children: b.items.map((k, i) => cell(k.value, w[i], { align: 'center', shade: C.kpiFill, bold: true, size: SIZE.kpiValue })) }),
          ],
        }),
      ]
    }
    case 'table':
      return [dataTable(b)]
  }
}

/** A thin gap after each table so consecutive tables/paragraphs don't touch. */
const gap = () => new Paragraph({ spacing: { before: 0, after: 60, line: 240 }, children: [] })

export async function socReportDocx(r: SocReport, logo: ArrayBuffer): Promise<Blob> {
  const logoW = 1700
  const header = new Table({
    width: { size: TABLE_W, type: WidthType.DXA },
    columnWidths: [logoW, TABLE_W - logoW],
    borders: noBorders,
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: logoW, type: WidthType.DXA },
            verticalAlign: VerticalAlign.CENTER,
            children: [new Paragraph({ children: [new ImageRun({ type: 'png', data: logo, transformation: { width: 84, height: 76 } })] })],
          }),
          new TableCell({
            width: { size: TABLE_W - logoW, type: WidthType.DXA },
            verticalAlign: VerticalAlign.CENTER,
            children: [
              new Paragraph({
                alignment: AlignmentType.RIGHT,
                spacing: { line: 240 },
                children: [
                  new TextRun({ text: COMPANY.name, bold: true, font: FONT, size: SIZE.company }),
                  ...[...COMPANY.address, COMPANY.contact].map((t) => new TextRun({ text: t, break: 1, font: FONT, size: SIZE.address })),
                ],
              }),
            ],
          }),
        ],
      }),
    ],
  })

  // Cover table: label/value pairs, two per row (template layout 2098/2948/2098/2948).
  const metaW = scale([2098, 2948, 2098, 2948], TABLE_W)
  const metaRows: TableRow[] = []
  for (let i = 0; i < r.meta.length; i += 2) {
    const pair = r.meta.slice(i, i + 2)
    metaRows.push(
      new TableRow({
        children: pair.flatMap((m, j) =>
          pair.length === 1
            ? [cell(m.label, metaW[0], { head: true }), cell(m.value, metaW[1] + metaW[2] + metaW[3], { span: 3 })]
            : [cell(m.label, metaW[j * 2], { head: true }), cell(m.value, metaW[j * 2 + 1], {})],
        ),
      }),
    )
  }

  const children: (Paragraph | Table)[] = [
    header,
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 160, after: 0, line: 240 },
      children: [new TextRun({ text: r.title, bold: true, font: FONT, size: SIZE.title })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 140, line: 240 },
      children: [new TextRun({ text: r.subtitle, bold: true, font: FONT, size: SIZE.subtitle })],
    }),
    new Table({ width: { size: TABLE_W, type: WidthType.DXA }, columnWidths: metaW, alignment: AlignmentType.CENTER, borders: tableBorders(C.border), rows: metaRows }),
  ]

  for (const sec of r.sections.filter((x) => x.include)) {
    children.push(
      new Paragraph({
        pageBreakBefore: !!sec.pageBreakBefore,
        keepNext: true,
        spacing: { before: 200, after: 100, line: 240 },
        children: [new TextRun({ text: sec.title, bold: true, font: FONT, size: SIZE.heading })],
      }),
    )
    for (const b of sec.blocks) {
      children.push(...block(b))
      if (b.kind !== 'text' && b.kind !== 'heading') children.push(gap())
    }
  }

  const doc = new Document({
    creator: 'VIGIX',
    title: r.title,
    styles: { default: { document: { run: { font: FONT, size: SIZE.body } } } },
    sections: [
      {
        properties: { page: { size: { width: PAGE_W, height: 15840 }, margin: MARGIN } },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({ text: `${r.footer}  |  หน้า `, font: FONT, size: SIZE.footer, color: '666666' }),
                  new TextRun({ children: [PageNumber.CURRENT], font: FONT, size: SIZE.footer, color: '666666' }),
                ],
              }),
            ],
          }),
        },
        children,
      },
    ],
  })
  return Packer.toBlob(doc)
}
