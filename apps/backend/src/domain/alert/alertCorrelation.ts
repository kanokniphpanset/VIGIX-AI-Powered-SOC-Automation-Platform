import { extractAlertIocs } from "../investigation/alertIocs";
import { summarizeAlert } from "./alertSummary";

/**
 * alertCorrelation — automatic alert correlation at ingestion (pure, deterministic, no AI).
 *
 * An alert that would open an incident instead JOINS an incident that is still open when it is evidently the same
 * activity. Without this, related alerts become separate incidents and the primary incident's re-hunt never looks
 * for the related alert's indicators (ATK-04: the C2 callback lives only in the related alert, so round 3 was a false
 * RESOLVED). Facts only — every reason below is read from the two payloads:
 *
 *   SHARED_IOC           both state the same specific indicator: a public IP, domain, URL or file hash on any host
 *                        (within 7 days), or a file / process path or private IP on the SAME host (within 24 h).
 *                        Values shorter than 7 characters, the alerts' own agent IPs and common system paths
 *                        (C:\Windows\..., /usr/bin/...) never count.
 *   SAME_SOURCE_IP       the same public attacker source IP (data.srcip), within 24 h.
 *   SAME_HOST_TECHNIQUE  the same monitored host and a shared MITRE technique, within 24 h.
 *   SAME_HOST_RULE       the same monitored host and the same Wazuh rule, within 24 h.
 *
 * Same host alone (or the time window alone) never correlates two alerts. Indicators the incident already records
 * (analyst-added, AI threat intel, carried forward by a re-hunt) count like indicators of its alerts.
 */

export const CORRELATION_HOST_WINDOW_MS = 24 * 3600_000;
export const CORRELATION_IOC_WINDOW_MS = 7 * 24 * 3600_000;
/** Shorter values (a bare user name, "cmd.exe") would match unrelated activity. */
export const MIN_CORRELATION_VALUE_LENGTH = 7;

export type CorrelationReason = "SHARED_IOC" | "SAME_SOURCE_IP" | "SAME_HOST_TECHNIQUE" | "SAME_HOST_RULE";

export interface CorrelationAlert {
  rawPayload: unknown;
  receivedAt: Date;
}

/** An incident that is still open (open / investigating), with every alert it holds and the indicators it records. */
export interface CorrelationCandidate {
  incidentId: string;
  openedAt: Date;
  alerts: CorrelationAlert[];
  iocs: { iocType: string; value: string }[];
}

export interface CorrelationMatch {
  incidentId: string;
  reasons: CorrelationReason[];
  /** The indicator values both sides state (lower-cased). */
  sharedIocs: string[];
}

/** A correlating indicator. Host-scoped ones (paths, private IPs) only correlate alerts about the same host. */
export interface CorrelationIndicator {
  value: string;
  hostScoped: boolean;
}

const lc = (v: string) => v.trim().toLowerCase();

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/;

/** RFC 1918 / loopback / link-local / CGNAT IPv4 and ULA / link-local / loopback IPv6. */
export function isPrivateIp(ip: string): boolean {
  const v = lc(ip);
  const m = IPV4.exec(v);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 0;
  }
  return v === "::1" || v.startsWith("fc") || v.startsWith("fd") || v.startsWith("fe80");
}

/** Paths of the OS / installed software: a shared cmd.exe or /usr/bin/bash says nothing about two alerts. */
const COMMON_SYSTEM_PATH = /^(?:[a-z]:\\(?:windows|program files(?: \(x86\))?|programdata\\microsoft)\\|\/(?:usr|bin|sbin|lib|lib64|etc|opt|proc|sys|dev)\/)/i;

const NETWORK_OR_HASH = new Set(["DOMAIN", "URL", "MD5", "SHA1", "SHA256", "HASH"]);
const IP_TYPES = new Set(["IP", "IPV4", "IPV6"]);
const PATH_TYPES = new Set(["FILE_PATH", "PROCESS_NAME"]);

function toIndicator(iocType: string, raw: string, ownIps: Set<string>): CorrelationIndicator | null {
  const type = iocType.toUpperCase();
  const value = lc(raw);
  if (value.length < MIN_CORRELATION_VALUE_LENGTH) return null;
  if (IP_TYPES.has(type)) {
    if (ownIps.has(value)) return null;
    return { value, hostScoped: isPrivateIp(value) };
  }
  if (NETWORK_OR_HASH.has(type)) return { value, hostScoped: false };
  // A process "name" only counts as a full path (svchost32.exe alone is too generic).
  if (PATH_TYPES.has(type) && /[\\/]/.test(value) && !COMMON_SYSTEM_PATH.test(value)) return { value, hostScoped: true };
  return null;
}

function agentIps(rawPayload: unknown): string[] {
  const ip = summarizeAlert(rawPayload).agentIp;
  return ip ? [lc(ip)] : [];
}

/** The indicators of one alert payload that may correlate it with another alert. */
export function correlationIndicators(rawPayload: unknown, extraOwnIps: string[] = []): CorrelationIndicator[] {
  const own = new Set([...agentIps(rawPayload), ...extraOwnIps.map(lc)]);
  const out = new Map<string, CorrelationIndicator>();
  for (const i of extractAlertIocs(rawPayload)) {
    const ind = toIndicator(i.iocType, i.value, own);
    if (ind && !out.has(ind.value)) out.set(ind.value, ind);
  }
  return [...out.values()];
}

const within = (a: Date, b: Date, ms: number) => Math.abs(a.getTime() - b.getTime()) <= ms;

/** Why `alert` belongs to `candidate`, or null when it does not. */
export function correlationReasons(alert: CorrelationAlert, candidate: CorrelationCandidate): CorrelationMatch | null {
  const s = summarizeAlert(alert.rawPayload);
  const host = s.host ? lc(s.host) : null;
  const ownIps = [...agentIps(alert.rawPayload), ...candidate.alerts.flatMap((a) => agentIps(a.rawPayload))];
  const mine = correlationIndicators(alert.rawPayload, ownIps);
  const reasons = new Set<CorrelationReason>();
  const shared = new Set<string>();

  for (const other of candidate.alerts) {
    const o = summarizeAlert(other.rawPayload);
    const sameHost = !!host && !!o.host && lc(o.host) === host;
    const hostWindow = within(alert.receivedAt, other.receivedAt, CORRELATION_HOST_WINDOW_MS);
    const iocWindow = within(alert.receivedAt, other.receivedAt, CORRELATION_IOC_WINDOW_MS);

    if (iocWindow) {
      const theirs = new Set(correlationIndicators(other.rawPayload, ownIps).map((i) => i.value));
      for (const i of mine) {
        if (!theirs.has(i.value)) continue;
        if (i.hostScoped && !(sameHost && hostWindow)) continue;
        shared.add(i.value);
      }
    }
    if (!hostWindow) continue;
    if (s.sourceIp && o.sourceIp && lc(s.sourceIp) === lc(o.sourceIp) && !isPrivateIp(s.sourceIp)) reasons.add("SAME_SOURCE_IP");
    if (sameHost && s.mitreTechniques.some((t) => o.mitreTechniques.includes(t))) reasons.add("SAME_HOST_TECHNIQUE");
    if (sameHost && s.ruleId && s.ruleId === o.ruleId) reasons.add("SAME_HOST_RULE");
  }

  // Indicators the incident records itself (no alert of its own may state them). Only environment-wide ones:
  // a recorded path or private IP carries no host to compare.
  // Same 7-day window, measured against the incident's alerts (detection time, like every other rule here).
  const incidentTimes = candidate.alerts.length ? candidate.alerts.map((a) => a.receivedAt) : [candidate.openedAt];
  if (incidentTimes.some((t) => within(alert.receivedAt, t, CORRELATION_IOC_WINDOW_MS))) {
    const own = new Set(ownIps);
    const recorded = new Set(
      candidate.iocs.map((i) => toIndicator(i.iocType, i.value, own)).filter((i): i is CorrelationIndicator => !!i && !i.hostScoped).map((i) => i.value)
    );
    for (const i of mine) if (!i.hostScoped && recorded.has(i.value)) shared.add(i.value);
  }

  if (shared.size > 0) reasons.add("SHARED_IOC");
  if (reasons.size === 0) return null;
  const order: CorrelationReason[] = ["SHARED_IOC", "SAME_SOURCE_IP", "SAME_HOST_TECHNIQUE", "SAME_HOST_RULE"];
  return { incidentId: candidate.incidentId, reasons: order.filter((r) => reasons.has(r)), sharedIocs: [...shared].sort() };
}

/**
 * The open incident `alert` joins, or null (it opens its own). With several matches: the most shared indicators,
 * then the most reasons, then the most recently opened incident — one incident only; merging several existing
 * incidents stays an analyst decision (Set Group).
 */
export function findCorrelatedIncident(alert: CorrelationAlert, candidates: CorrelationCandidate[]): CorrelationMatch | null {
  const matches = candidates
    .map((c) => ({ c, m: correlationReasons(alert, c) }))
    .filter((x): x is { c: CorrelationCandidate; m: CorrelationMatch } => !!x.m)
    .sort((a, b) => b.m.sharedIocs.length - a.m.sharedIocs.length || b.m.reasons.length - a.m.reasons.length || b.c.openedAt.getTime() - a.c.openedAt.getTime());
  return matches[0]?.m ?? null;
}

/** What the candidate lookup must search for: the alert's host and the indicator values (plus JSON-escaped forms). */
export function correlationLookup(alert: CorrelationAlert): { host: string | null; indicatorValues: string[]; payloadNeedles: string[] } {
  const host = summarizeAlert(alert.rawPayload).host;
  const indicatorValues = correlationIndicators(alert.rawPayload).map((i) => i.value);
  // raw_payload::text escapes "\" as "\\": a Windows path must be searched for in that form too.
  const payloadNeedles = [...new Set(indicatorValues.flatMap((v) => [v, JSON.stringify(v).slice(1, -1)]))];
  return { host: host ? lc(host) : null, indicatorValues, payloadNeedles };
}
