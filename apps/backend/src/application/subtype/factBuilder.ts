import { processIdentity, resolveAll } from "../../domain/subtype/targets";
import { EvidenceFact, Facts, KnowledgeBase, OrganizationContext, TargetCandidate } from "../../domain/subtype/types";

/**
 * FactBuilder - Wazuh event / investigation results -> evidence_record -> subtype knowledge facts -> validated targets.
 *
 * Sources of a fact (and ONLY these):
 *   WAZUH_V2  structuredData.contractV2 of a SYSTEM evidence row (Evidence Contract v2: provenance, process GUID / start time, network
 *             src/dst + derived direction, authentication result, file / syscheck, IOC roles). A fact is derived only where the
 *             contract carries enough to be true; classification evidence that needs judgement stays UNKNOWN.
 *   ANALYST   a MANUAL evidence row of type ANALYST_ASSERTION (createdBy = the authenticated analyst; origin stamped server-side).
 *             The assertion row itself is the evidence reference. The LLM can never create one.
 *
 * Never: agent.ip as attacker, LLM text / confidence as evidence, missing data as ABSENT-or-false (it stays UNKNOWN),
 * authority or tool capability from anything but the organization context.
 */
export interface SubtypeEvidenceRow {
  id: string;
  /** stable citation id (E<n>), same numbering as RecommendationContextDto.evidence */
  ref: string;
  type: string;
  origin: "SYSTEM" | "MANUAL";
  createdBy: string | null;
  timestamp: Date;
  title: string;
  host: string | null;
  structured: Record<string, unknown> | null;
  /** The stored alert this SYSTEM row was derived from (alerts.id), when there is one. */
  alertId?: string | null;
}

export interface AssertionShape {
  evidence?: { id: string; status: "PRESENT" | "ABSENT" | "UNKNOWN"; authorization_status?: "AUTHORIZED" | "UNAUTHORIZED" | "UNKNOWN"; source_event_refs?: string[]; lineage?: string[]; note?: string; observed_at?: string }[];
  targets?: { type: string; fields: Record<string, unknown>; source_event_refs?: string[] }[];
  scope?: string[];
  context?: { active_damage_ongoing?: boolean };
}

export interface FactBuildResult {
  facts: Facts;
  audit: {
    evidence: EvidenceFact[];
    candidates: { type: string; origin: string; refs: string[]; validated: boolean; findings: string[]; display: string }[];
    ignored: string[];
    agentIps: string[];
    thresholds: typeof THRESHOLDS;
  };
}

/** Detection thresholds are VIGIX defaults (not from the reference) and are recorded in every audit. */
export const THRESHOLDS = { authFailureMinEvents: 5, authFailureWindowSeconds: 900, multiAccountMin: 5 } as const;

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : null);
const norm = (v: unknown) => String(v ?? "").trim().toLowerCase();

export function buildFacts(
  kb: KnowledgeBase,
  input: { rows: SubtypeEvidenceRow[]; assetCriticality: string; org: OrganizationContext; mode?: "platform_neutral" | "strict" }
): FactBuildResult {
  const evidence = new Map<string, EvidenceFact>();
  const ignored: string[] = [];
  const candidates: TargetCandidate[] = [];
  const scope = new Set<string>();
  const context: Record<string, unknown> = { "context.asset_criticality": input.assetCriticality };
  const agentIps = new Set<string>();
  const agentNames = new Set<string>();

  const put = (f: EvidenceFact) => {
    const def = kb.evidence.get(f.id);
    if (!def) { ignored.push(`unknown evidence id ${f.id}`); return; }
    if (!def.may_be_authorized) f.authorization = f.authorization === "AUTHORIZED" ? "AUTHORIZED" : "UNKNOWN";
    // PRESENT must rest on at least one reference; lineage is mandatory where the knowledge says so.
    if (f.status === "PRESENT" && !f.refs.length) { ignored.push(`${f.id}: PRESENT without evidence reference downgraded to UNKNOWN`); f = { ...f, status: "UNKNOWN" }; }
    if (f.status === "PRESENT" && def.requires_lineage && !f.lineage?.length) {
      ignored.push(`${f.id}: lineage required but not provided - kept UNKNOWN`); f = { ...f, status: "UNKNOWN" };
    }
    const prev = evidence.get(f.id);
    // never let a weaker fact overwrite a stronger one; PRESENT beats UNKNOWN, an explicit AUTHORIZED beats UNAUTHORIZED (fail safe).
    if (prev && prev.status === "PRESENT" && f.status !== "PRESENT") return;
    if (prev && prev.status === "PRESENT" && f.status === "PRESENT") {
      evidence.set(f.id, { ...prev, refs: [...new Set([...prev.refs, ...f.refs])], authorization: prev.authorization === "AUTHORIZED" || f.authorization === "AUTHORIZED" ? "AUTHORIZED" : prev.authorization === "UNAUTHORIZED" ? "UNAUTHORIZED" : f.authorization });
      return;
    }
    evidence.set(f.id, f);
  };

  // 1) Wazuh Evidence Contract v2 -----------------------------------------------------------------------------------------
  const authFailures: { ref: string; ip: string; host: string; account: string | null; at: number }[] = [];
  for (const row of input.rows) {
    const v2 = obj(obj(row.structured).contractV2);
    if (row.origin !== "SYSTEM" || !Object.keys(v2).length) continue;
    const prov = obj(v2.provenance);
    const agent = obj(prov.agent);
    const agentName = str(agent.name) ?? row.host;
    if (str(agent.ip)) agentIps.add(norm(agent.ip));
    if (agentName) agentNames.add(norm(agentName));
    const ev = obj(v2.evidence);
    const proc = obj(ev.process);
    const net = obj(ev.network);
    const auth = obj(ev.authentication);
    const file = obj(ev.file);
    const sys = obj(ev.syscheck);
    const ref = row.ref;

    const guid = str(proc.guid), pid = str(proc.pid), image = str(proc.image), startedAt = str(proc.startedAt);
    if (agentName && (guid || pid || image)) {   // PID-only is still recorded - the resolver rejects it as not an identity
      candidates.push({ type: "process", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { host_id: agentName, process_guid: guid, pid, start_time: startedAt, image_path: image, command_line: str(proc.commandLine) }, provenance: { process_guid: "evidence.process.guid", image_path: "evidence.process.image" } });
    }
    const filePath = str(file.path) ?? str(sys.path);
    if (agentName && filePath) {
      const h = obj(file.hashes);
      candidates.push({ type: "file_object", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { host_id: agentName, object_locator: filePath, sha256: str(h.sha256) } });
    }
    const dst = obj(net.dst);
    const direction = obj(net.direction);
    const url = str(net.url), dns = str(net.dnsQuery), dstIp = str(dst.ip);
    if (agentName && (url || dns || dstIp) && direction.value === "OUTBOUND") {
      const destination = url ?? dns ?? dstIp!;
      candidates.push({ type: "destination_endpoint", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { destination, granularity: url ? "URL" : dns ? "domain" : "IP", ip: dstIp } });
      // a flow's destination ROLE (C2 / exfil / ...) is a judgement Wazuh does not make: it stays unclassified until an analyst asserts it.
      if (dstIp) candidates.push({ type: "network_flow", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { source_host_id: agentName, destination: dstIp, destination_role: "unclassified_remote", protocol: "tcp", port: dst.port ?? null } });
    }
    const result = obj(auth.result).value;
    const remote = obj(auth.remote);
    const remoteIp = str(remote.ip);
    const account = str(auth.attemptedAccount) ?? str(auth.account);
    if (result === "FAILURE" && remoteIp && agentName && !agentIps.has(norm(remoteIp))) {
      const t = Date.parse(str(obj(prov.time).eventAt) ?? str(obj(prov.time).detectedAt) ?? "") || row.timestamp.getTime();
      authFailures.push({ ref, ip: remoteIp, host: agentName, account, at: t });
      const rule = obj(obj(v2.detection).rule);
      const groups = (Array.isArray(rule.groups) ? rule.groups : []).map(String);
      const freq = typeof rule.frequency === "number" ? rule.frequency : 0;
      if (groups.some((g) => /authentication_fail/i.test(g)) && freq >= THRESHOLDS.authFailureMinEvents) {
        put({ id: "bf_attempts_correlated", status: "PRESENT", authorization: "UNKNOWN", refs: [ref], source: "WAZUH_V2", observedAt: row.timestamp.toISOString(), note: `detection rule correlates >=${freq} failures` });
      }
      // an INBOUND authentication attempt's remote address is the attacker side - the only case where a role is derivable
      candidates.push({ type: "network_source", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { address: remoteIp, source_role: "attacker_source" }, provenance: { address: "evidence.authentication.remote.ip" } });
      candidates.push({ type: "service_endpoint", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { host_id: agentName, service: str(obj(auth.logon).process) ?? null, enforcement_point: null } });
    }
    if (account && agentName) candidates.push({ type: "account_identity", origin: "WAZUH_V2", evidenceRefs: [ref], fields: { account_id: account, provider: null, tenant_or_scope: str(auth.accountDomain) } });
    const ps = obj(ev.powershell);
    const cmd = `${str(proc.commandLine) ?? ""} ${str(ps.scriptBlockText) ?? ""}`;
    if (/powershell|pwsh/i.test(`${image ?? ""} ${cmd}`) && /\s-(?:enc|encodedcommand)\b/i.test(cmd)) {
      put({ id: "ps_encoded_or_binary_only", status: "PRESENT", authorization: "UNKNOWN", refs: [ref], source: "WAZUH_V2", observedAt: row.timestamp.toISOString(), note: "encoded command observed - an indicator only, never opens termination" });
    }
  }
  // clusters over several alerts (same remote address + host, inside the window)
  const byKey = new Map<string, typeof authFailures>();
  for (const f of authFailures) byKey.set(`${f.ip}|${f.host}`, [...(byKey.get(`${f.ip}|${f.host}`) ?? []), f]);
  for (const list of byKey.values()) {
    list.sort((a, b) => a.at - b.at);
    for (let i = 0; i < list.length; i++) {
      const w = list.filter((x) => x.at >= list[i].at && x.at - list[i].at <= THRESHOLDS.authFailureWindowSeconds * 1000);
      if (w.length >= THRESHOLDS.authFailureMinEvents) put({ id: "bf_attempts_correlated", status: "PRESENT", authorization: "UNKNOWN", refs: w.map((x) => x.ref), source: "DERIVED", note: `${w.length} failures from one source within ${THRESHOLDS.authFailureWindowSeconds}s` });
    }
  }
  const accounts = new Set(authFailures.map((f) => norm(f.account)).filter(Boolean));
  if (accounts.size >= THRESHOLDS.multiAccountMin) put({ id: "bf_multi_account_campaign", status: "PRESENT", authorization: "UNKNOWN", refs: authFailures.map((f) => f.ref), source: "DERIVED", note: `${accounts.size} distinct accounts attempted` });

  // 2) Analyst assertions (MANUAL rows) -------------------------------------------------------------------------------------
  for (const row of input.rows) {
    if (row.origin !== "MANUAL") continue;
    const a = obj(obj(row.structured).subtypeFacts) as AssertionShape;
    if (!Object.keys(a).length) continue;
    if (!row.createdBy || row.createdBy === "system") { ignored.push(`${row.ref}: assertion without an authenticated author ignored`); continue; }
    for (const e of a.evidence ?? []) {
      put({ id: e.id, status: e.status, authorization: e.authorization_status ?? "UNKNOWN", refs: [row.ref, ...(e.source_event_refs ?? [])], source: "ANALYST", observedAt: e.observed_at ?? row.timestamp.toISOString(), note: e.note, ...(e.lineage?.length ? { lineage: e.lineage } : {}) });
    }
    for (const t of a.targets ?? []) candidates.push({ type: t.type, origin: "ANALYST", evidenceRefs: [row.ref, ...(t.source_event_refs ?? [])], fields: t.fields });
    for (const s of a.scope ?? []) if (kb.scopeFlags.has(s)) scope.add(s); else ignored.push(`${row.ref}: unknown scope flag ${s}`);
    if (a.context?.active_damage_ongoing !== undefined) context["context.active_damage_ongoing"] = a.context.active_damage_ongoing;
  }

  // 3) org-config completion of fields Wazuh cannot know (never invented) ------------------------------------------------------
  for (const c of candidates) {
    const cfg = input.org;
    if (c.type === "service_endpoint" && !c.fields.enforcement_point) {
      const m = cfg.enforcementPoints.find((e) => norm(e.host) === norm(c.fields.host_id));
      if (m) { c.fields.enforcement_point = m.enforcement_point; if (!c.fields.service && m.service) c.fields.service = m.service; c.provenance = { ...c.provenance, enforcement_point: "organization-context" }; }
    }
    if (c.type === "account_identity" && !c.fields.provider && cfg.identity?.provider) { c.fields.provider = cfg.identity.provider; c.fields.tenant_or_scope = c.fields.tenant_or_scope ?? cfg.identity.tenant_or_scope ?? null; }
  }

  const resolved = resolveAll(kb, candidates, { agentIps, agentNames, approvedAccess: input.org.approvedAccess, approvedAutomation: input.org.approvedAutomation, trustedRmm: input.org.trustedRmm });
  const authority = new Map<string, boolean | null>();
  for (const a of kb.authorities) authority.set(a, input.org.authority[a] ?? null);
  authority.set("ir_execute", input.org.authority.ir_execute ?? true);
  const capability = new Map<string, boolean | null>();
  for (const c of kb.capabilities) capability.set(c, input.org.capability[c] ?? null);
  const facts: Facts = { evidence, targets: resolved, scope, authority, capability, context, mode: input.mode ?? "platform_neutral" };
  return {
    facts,
    audit: {
      evidence: [...evidence.values()],
      candidates: resolved.map((t) => ({ type: t.type, origin: t.origin, refs: t.evidenceRefs, validated: t.validated, findings: t.findings, display: t.display })),
      ignored, agentIps: [...agentIps], thresholds: THRESHOLDS,
    },
  };
}

export { processIdentity };
