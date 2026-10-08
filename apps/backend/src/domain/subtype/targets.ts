import { KnowledgeBase, ResolvedTarget, TargetCandidate } from "./types";

/**
 * Target resolver. A target is VALID only when (contracts/target-types.yaml):
 *   (1) every required_identity_field is present and non-empty,
 *   (2) type-specific validation holds (process identity != bare PID; attacker source != agent/observer; flow destination != agent ...),
 *   (3) it is bound to >=1 evidence reference (a target that rests on no evidence is never valid),
 *   (4) no exclusion applies (secrets by id only ...).
 * Approved-access / approved-automation matches do not silently drop a target: they raise a scope.* flag so the policy
 * layer reports PROHIBITED with the reason (nothing is hidden from the audit).
 */
export interface ResolverContext {
  /** agent.ip / agent.name of the alerting endpoint(s): observer identities, never an attacker or a destination. */
  agentIps: ReadonlySet<string>;
  agentNames: ReadonlySet<string>;
  approvedAccess: { match: string }[];
  approvedAutomation: { match: string }[];
  trustedRmm: { match: string }[];
}

const HOST_FIELDS = ["host_id", "source_host_id", "file_server_host_id", "db_host_id", "destination_host_id"];
const SYSTEM_BINARY = /^(?:[a-z]:\\windows\\(?:system32|syswow64)\\|\/(?:usr\/)?(?:s?bin)\/)/i;
const RAW_TOKEN = /^(?:Bearer\s+\S+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)$/;
const ATTACKER_SOURCE_ROLES = new Set(["attacker_source"]);
const FLOW_DESTINATION_ROLES = new Set(["remote_attacker_infra", "remote_c2", "unauthorized_external", "peer_host_infected", "db_egress_destination"]);

const present = (v: unknown): boolean => (Array.isArray(v) ? v.length > 0 : v !== undefined && v !== null && String(v).trim() !== "");
const norm = (v: unknown): string => String(v ?? "").trim().toLowerCase();
const matches = (list: { match: string }[], ...values: unknown[]): boolean => values.some((v) => present(v) && list.some((m) => norm(m.match) === norm(v)));

/** A process is identified by its GUID, or by PID + start time + image. A bare PID (or name) is not an identity. */
export function processIdentity(f: Record<string, unknown>): string | null {
  if (present(f.process_identity)) {
    const id = String(f.process_identity);
    return /^process_guid=\S+$/.test(id) || (/pid=\d+/.test(id) && /start=\S+/.test(id) && /image=\S+/.test(id)) ? id : null;
  }
  if (present(f.process_guid)) return `process_guid=${f.process_guid}`;
  if (present(f.pid) && present(f.start_time) && present(f.image_path)) return `pid=${f.pid};start=${f.start_time};image=${f.image_path}`;
  return null;
}

export function resolveTarget(kb: KnowledgeBase, c: TargetCandidate, ctx: ResolverContext): ResolvedTarget {
  const def = kb.targetTypes.get(c.type);
  const findings: string[] = [];
  const flags: string[] = [];
  const f: Record<string, unknown> = { ...c.fields };
  if (!def) return { ...c, fields: f, validated: false, findings: [`unknown target type ${c.type}`], identityKey: `${c.type}|?`, hostKey: null, display: c.type, scopeFlags: [] };

  if (c.type === "process") {
    const id = processIdentity(f);
    if (id) f.process_identity = id; else { delete f.process_identity; findings.push("process identity incomplete: need process GUID, or PID + start time + image (a bare PID/name is not an identity)"); }
    if (matches(ctx.approvedAutomation, f.image_path, f.process_name)) flags.push("is_approved_automation");
  }
  if (c.type === "process_children") {
    const ids = (Array.isArray(f.child_process_identities) ? f.child_process_identities : []) as unknown[];
    const good = ids.filter((x) => typeof x === "string" && processIdentity({ process_identity: x }) !== null);
    if (good.length !== ids.length || !good.length) findings.push("every child needs an identity-grade process identity with lineage evidence");
    f.child_process_identities = good;
  }
  if (c.type === "network_source") {
    if (!ATTACKER_SOURCE_ROLES.has(String(f.source_role))) { findings.push("source role is not explicitly attacker_source"); flags.push("source_role_ambiguous"); }
    if (ctx.agentIps.has(norm(f.address)) || ctx.agentNames.has(norm(f.address))) { findings.push("address is the agent/observer, not an attacker"); flags.push("uses_agent_ip_as_attacker"); }
    if (matches(ctx.approvedAccess, f.address)) flags.push("cuts_approved_access");
  }
  if (c.type === "network_flow") {
    if (!FLOW_DESTINATION_ROLES.has(String(f.destination_role))) findings.push("destination role is not an evidenced remote role");
    if (ctx.agentIps.has(norm(f.destination)) || ctx.agentNames.has(norm(f.destination))) { findings.push("destination is the agent/observer"); flags.push("uses_agent_ip_as_destination"); }
    if (matches(ctx.approvedAccess, f.destination)) flags.push("cuts_approved_access");
  }
  if (c.type === "destination_endpoint") {
    if (ctx.agentIps.has(norm(f.destination)) || ctx.agentNames.has(norm(f.destination))) { findings.push("destination is the agent/observer"); flags.push("uses_agent_ip_as_destination"); }
    if (matches(ctx.approvedAccess, f.destination)) flags.push("cuts_approved_access");
  }
  if (c.type === "file_object" && typeof f.object_locator === "string" && SYSTEM_BINARY.test(f.object_locator)) flags.push("object_is_legitimate_os_binary");
  if (c.type === "account_identity") {
    if (matches(ctx.approvedAccess, f.account_id)) flags.push("cuts_approved_access");
    if (norm(f.account_type) === "service" && !present(f.dependent_services)) flags.push("service_identity_without_dependency_plan");
  }
  if (c.type === "rmm_registration" && matches(ctx.trustedRmm, f.tool, f.registration_or_session_id)) flags.push("cuts_approved_access");
  if (c.type === "oauth_grant" || c.type === "session" || c.type === "secret_credential") {
    for (const v of Object.values(f)) if (typeof v === "string" && RAW_TOKEN.test(v)) findings.push("a raw token/secret value was supplied - targets reference credentials by id only");
    if ("secret_value" in f) { findings.push("raw secret value must never be stored in a target"); delete f.secret_value; }
  }

  for (const req of def.required_identity_fields) if (!present(f[req])) findings.push(`missing required field ${req}`);
  if (!c.evidenceRefs.length) findings.push("target is not bound to any evidence");

  const hostKey = HOST_FIELDS.map((k) => (present(f[k]) ? norm(f[k]) : null)).find(Boolean) ?? null;
  const idParts = def.required_identity_fields.map((k) => (Array.isArray(f[k]) ? (f[k] as unknown[]).map(String).sort().join(",") : String(f[k] ?? "")));
  const identityKey = `${c.type}|${idParts.join("|")}`;
  const display = displayOf(c.type, f);
  return { ...c, fields: f, validated: findings.length === 0, findings, identityKey, hostKey, display, scopeFlags: flags };
}

function displayOf(type: string, f: Record<string, unknown>): string {
  const pick = (...ks: string[]) => ks.map((k) => (Array.isArray(f[k]) ? (f[k] as unknown[]).join(", ") : f[k])).filter((v) => present(v)).join(" ");
  switch (type) {
    case "process": return `${f.host_id ?? ""} ${f.process_identity ?? ""}`.trim();
    case "network_source": return String(f.address ?? "");
    case "account_identity": return String(f.account_id ?? "");
    case "file_object": return `${f.host_id ?? ""} ${f.object_locator ?? ""}`.trim();
    case "persistence_artifact": return `${f.host_id ?? ""} ${f.artifact_locator ?? ""}`.trim();
    case "destination_endpoint": return String(f.destination ?? "");
    case "network_flow": return `${f.source_host_id ?? ""}->${f.destination ?? ""}:${f.port ?? ""}`;
    default: return pick(...Object.keys(f).slice(0, 2)) || type;
  }
}

export function resolveAll(kb: KnowledgeBase, candidates: TargetCandidate[], ctx: ResolverContext): ResolvedTarget[] {
  // identical identity from several evidence rows -> one target carrying all references (never double counted)
  const merged = new Map<string, ResolvedTarget>();
  for (const c of candidates) {
    const r = resolveTarget(kb, c, ctx);
    const k = r.identityKey;
    const prev = merged.get(k);
    if (!prev) merged.set(k, r);
    else {
      // fail closed: the merged target is valid only if EVERY duplicate was valid; references and findings are the union
      prev.evidenceRefs = [...new Set([...prev.evidenceRefs, ...r.evidenceRefs])];
      const unbound = "target is not bound to any evidence";
      prev.findings = [...new Set([...prev.findings, ...r.findings])].filter((x) => x !== unbound || !prev.evidenceRefs.length);
      prev.validated = prev.validated && r.validated;
    }
  }
  return [...merged.values()];
}
