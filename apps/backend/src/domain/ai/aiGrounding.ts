import { isIP } from "node:net";
/**
 * Post-generation grounding check for free-text AI analysis (LlmAnalystAgent summary / key findings). Pure and
 * deterministic — it does not trust the prompt. Every concrete indicator the text names (IPv4/IPv6 address, MD5 / SHA-1 /
 * SHA-256 hash, URL, domain, upper-case host name like WKS-DEV-12) must literally appear in the incident's source data
 * (alert payloads, evidence, IOCs). Anything else is reported as UNGROUNDED — never silently removed: the original text
 * is kept, and callers must stop treating the analysis as trusted.
 */

export type IndicatorKind = "ip" | "hash" | "url" | "domain" | "host" | "command" | "email" | "mac";
export interface GroundingResult {
  status: "GROUNDED" | "UNGROUNDED";
  ungrounded: { kind: IndicatorKind; value: string }[];
}

const IPV4 = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)/g;
const IPV6 = /(?<![0-9a-f:])[0-9a-f:]*:[0-9a-f:.]+(?![0-9a-f:])/gi;
const HASH = /(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])/gi;
const URL = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)\]]+/gi;
const EMAIL = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b/gi;
const MAC = /\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi;
// Ambiguous dotted names are checked conservatively against source evidence.
const DOMAIN = /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-]|\.[a-z0-9])/gi;
const HOST = /(?<![\w-])(?:[a-z][a-z0-9]*-)+(?:[a-z0-9]*\d[a-z0-9]*)(?![\w-])/gi;
const UPPER_HOST = /(?<![\w-])[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+(?![\w-])/g;
const NAMED_HOST = /\b(?:host(?:name)?|server|endpoint|workstation|agent)\b(?:\s*[:=]\s*|\s+(?:named\s+|is\s+)?)["'`]?([a-z0-9][a-z0-9_.-]*)/gi;
const COMMAND = /(?:\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|curl|wget|certutil|netsh|iptables|whoami|rm|chmod)\s+[^\n;]+|`[^`\n]+`)/gi;
/**
 * A backtick span is a command only when it reads like one — arguments (whitespace), a pipe / redirect / chaining, or a
 * bare known binary. LLM Markdown also backticks single field names and values (`frequency`, `previous_output`,
 * `UNKNOWN` — Wazuh fields / a threat-intel verdict it was given); those are not commands, and any IP / hash / host /
 * domain / URL inside backticks is still checked by its own detector above.
 */
const KNOWN_BINARY = /^(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh|curl|wget|certutil|netsh|iptables|whoami|rm|chmod|net(?:\.exe)?|reg(?:\.exe)?|sc(?:\.exe)?|schtasks(?:\.exe)?|mshta|rundll32(?:\.exe)?)$/i;
function looksLikeCommand(match: string): boolean {
  if (!match.startsWith("`")) return true; // the explicit "<binary> <args>" alternative
  const inner = match.replace(/^`|`$/g, "").trim();
  return /\s|[|;&<>]/.test(inner) || KNOWN_BINARY.test(inner);
}
// Catalog / taxonomy codes that look like host names but are not infrastructure.
const NOT_A_HOST = /^(?:T\d{4}|CVE-|RULE-|POL-|STC-|ATK-|PB-|RB-|ACT-|INC-|MITRE|SHA-|MD5|UTF-|ISO-|RFC-|TLS-|SSL-|HTTP-|IR-|SOC-|NIST-|OWASP-|X-)/;

function unique<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** True when `token` occurs in the source text as a whole indicator (10.0.0.1 is not found inside 10.0.0.10). */
function present(token: string, source: string, kind: IndicatorKind): boolean {
  const sourceLower = source.toLowerCase();
  const t = token.toLowerCase();
  if (kind === "url") {
    const normalize = (v: string) => { try { const url = new globalThis.URL(v.replace(/[.,;:]+$/, "")); return url.href; } catch { return v; } };
    return (source.match(URL) ?? []).some(v => normalize(v) === normalize(token));
  }
  if (kind === "command") return source.includes(token);
  const edge = kind === "ip" ? "[\\d.:a-f]" : kind === "hash" ? "[0-9a-f]" : "[\\w.-]";
  return new RegExp(`(?<!${edge})${escape(t)}(?!${edge})`).test(sourceLower);
}

export function checkGrounding(text: string, sources: string[]): GroundingResult {
  const source = sources.join("\n");
  const found: { kind: IndicatorKind; value: string }[] = [
    ...unique(text.match(URL) ?? []).map((value) => ({ kind: "url" as const, value: value.replace(/[.,;:]+$/, "") })),
    ...unique(text.match(IPV4) ?? []).map((value) => ({ kind: "ip" as const, value })),
    ...unique((text.match(IPV6) ?? []).map(v => v.replace(/[.,;]+$/, "")).filter(v => isIP(v) === 6)).map((value) => ({ kind: "ip" as const, value })),
    ...unique(text.match(HASH) ?? []).map((value) => ({ kind: "hash" as const, value })),
    ...unique(text.match(EMAIL) ?? []).map(value => ({ kind: "email" as const, value })),
    ...unique(text.match(MAC) ?? []).map(value => ({ kind: "mac" as const, value })),
    // A domain inside a URL is judged with its URL.
    ...unique((text.replace(URL, " ").match(DOMAIN) ?? []).map((d) => d.toLowerCase())).map((value) => ({ kind: "domain" as const, value })),
    ...unique([...(text.match(HOST) ?? []), ...(text.match(UPPER_HOST) ?? [])])
      .filter((h) => !NOT_A_HOST.test(h))
      .map((value) => ({ kind: "host" as const, value })),
    ...unique([...text.matchAll(NAMED_HOST)].map(m => m[1].replace(/[.,;:]+$/, "")).filter(v => !['the','a','an','was','with','and','or','is','has','at','on'].includes(v.toLowerCase())))
      .filter(v => !NOT_A_HOST.test(v)).map(value => ({ kind: "host" as const, value })),
    ...unique(text.match(COMMAND) ?? []).filter(looksLikeCommand).map(value => ({ kind: "command" as const, value: value.replace(/^`|`$/g, "").trim().replace(/[.,]+$/, "") })),
  ];
  const ungrounded = found.filter((f) => !present(f.value, source, f.kind));
  return { status: ungrounded.length ? "UNGROUNDED" : "GROUNDED", ungrounded };
}

/** Flattens any stored JSON (alert payload, evidence structured data) into its string / number leaves. */
export function stringLeaves(value: unknown, out: string[] = []): string[] {
  if (value == null) return out;
  if (typeof value === "string" || typeof value === "number") out.push(String(value));
  else if (Array.isArray(value)) value.forEach((v) => stringLeaves(v, out));
  else if (typeof value === "object") Object.values(value as Record<string, unknown>).forEach((v) => stringLeaves(v, out));
  return out;
}

/**
 * VIGIX has no AI severity. AI output stored BEFORE that change may still contain a model severity suggestion
 * ("ML severity suggestion: MEDIUM", "ML severity classification suggests HIGH ..."). Such sentences / findings are
 * removed when the analysis is READ (shown to analysts or used as recommendation context); the stored original is
 * never modified. Returns the cleaned text and whether anything was removed.
 */
const AI_SEVERITY_SENTENCE = /[^.!?\n]*\b(?:ML|AI|model)\s+severity\b[^.!?\n]*[.!?]?|[^.!?\n]*\bseverity\s+(?:suggestion|prediction|classification)\b[^.!?\n]*[.!?]?/gi;
/** Key=value clause written by the old AI pipeline into timeline text: "…(advisory), suggested severity=medium". */
const AI_SEVERITY_CLAUSE = /\s*[,;]?\s*\bsuggested[ _]severity\s*[=:]\s*[a-z]+/gi;
export function stripAiSeverity(text: string): { text: string; removed: boolean } {
  const cleaned = text.replace(AI_SEVERITY_CLAUSE, "").replace(AI_SEVERITY_SENTENCE, "").replace(/[ \t]{2,}/g, " ").trim();
  return { text: cleaned, removed: cleaned !== text.trim() };
}
