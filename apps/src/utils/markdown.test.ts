import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseInline, parseMarkdown } from './markdown.ts'

// Shape of the real LLM analysis seen in the E2E (gemma4 via vLLM).
const LLM = `### Analyst Assessment
**1. Classification**
*   **Type:** Brute Force Attack (Credential Access)
*   **Source IP:** \`185.220.101.45\`

**2. Hypotheses**
1. An external actor is attempting to guess the *root* password.
2. No successful login is observed.

---
Plain closing paragraph
continued on a second line.`

test('headings, bold labels, bullet and numbered lists, rule and paragraphs are recognised', () => {
  const blocks = parseMarkdown(LLM)
  assert.deepEqual(blocks.map((b) => b.kind), ['heading', 'paragraph', 'list', 'paragraph', 'list', 'hr', 'paragraph'])
  assert.deepEqual(blocks[0], { kind: 'heading', level: 3, inlines: [{ kind: 'text', text: 'Analyst Assessment' }] })
  const bullets = blocks[2]
  assert.ok(bullets.kind === 'list' && !bullets.ordered && bullets.items.length === 2)
  assert.deepEqual(bullets.kind === 'list' && bullets.items[1].inlines, [{ kind: 'strong', text: 'Source IP:' }, { kind: 'text', text: ' ' }, { kind: 'code', text: '185.220.101.45' }])
  assert.ok(blocks[4].kind === 'list' && blocks[4].ordered)
  assert.deepEqual(blocks[6], { kind: 'paragraph', inlines: [{ kind: 'text', text: 'Plain closing paragraph continued on a second line.' }] })
})

test('no ** or ` markers are left in the rendered text', () => {
  const texts = JSON.stringify(parseMarkdown(LLM))
  assert.ok(!texts.includes('**'), texts)
  assert.ok(!texts.includes('`'), texts)
})

test('HTML in model output stays plain text (it is never interpreted)', () => {
  const blocks = parseMarkdown('<script>alert(1)</script> **x**')
  assert.deepEqual(blocks, [{ kind: 'paragraph', inlines: [{ kind: 'text', text: '<script>alert(1)</script> ' }, { kind: 'strong', text: 'x' }] }])
})

test('inline: identifiers with underscores and file paths are not turned into italics', () => {
  assert.deepEqual(parseInline('ssh_brute_force at c:\\users\\fin_analyst'), [{ kind: 'text', text: 'ssh_brute_force at c:\\users\\fin_analyst' }])
  assert.deepEqual(parseInline('a *b* c'), [{ kind: 'text', text: 'a ' }, { kind: 'em', text: 'b' }, { kind: 'text', text: ' c' }])
})

test('fenced code keeps its content verbatim; empty input gives nothing', () => {
  assert.deepEqual(parseMarkdown('```\nnetstat -an | grep 22\n```'), [{ kind: 'code', text: 'netstat -an | grep 22' }])
  assert.deepEqual(parseMarkdown(''), [])
  assert.deepEqual(parseMarkdown(null), [])
})
