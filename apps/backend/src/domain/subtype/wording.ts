/**
 * User-facing wording of internal field names and enum values. Identifiers an IR engineer must type (process GUID, addresses, paths)
 * are kept verbatim but introduced by a plain label; internal keys never appear as sentence parts. Nothing here adds facts:
 * a value is only re-labelled, never completed (no process name/path is ever filled in).
 */
export const FIELD_LABEL: Record<string, string> = {
  host_id: "เครื่องที่เกี่ยวข้อง", source_host_id: "เครื่องต้นทาง", destination_host_id: "เครื่องปลายทาง", db_host_id: "เครื่อง DB", file_server_host_id: "เครื่อง file server",
  service: "บริการ", enforcement_point: "จุดควบคุมการเข้าถึง", protocol: "โปรโตคอล", port: "พอร์ต", address: "ที่อยู่ต้นทาง", destination: "ปลายทาง",
  destination_role: "บทบาทของปลายทาง", source_role: "บทบาทของต้นทาง", granularity: "ระดับที่ตัด", route: "เส้นทาง request", parameter: "พารามิเตอร์",
  artifact_type: "ชนิดของ artifact", artifact_locator: "ชื่อ/ตำแหน่งของ artifact", object_locator: "ตำแหน่งไฟล์/object", process_identity: "ตัวระบุ Process",
  process_guid: "GUID ของ Process", child_process_identities: "ตัวระบุ Process ลูก", account_id: "บัญชี", provider: "ผู้ให้บริการ identity", session_ids_or_family: "session",
  application: "แอปพลิเคชัน", credential_id: "credential", factor_or_recovery_id: "MFA factor/ช่องทาง recovery", queue_id: "mail queue", path_or_sni: "path หรือ SNI", dns_name: "ชื่อ DNS",
};
export const VALUE_LABEL: Record<string, string> = {
  attacker_source: "IP ต้นทางที่หลักฐานระบุว่าเป็นผู้โจมตี", scheduled_task: "Scheduled Task", autorun: "Autorun entry", launch_entry: "Launch entry",
  remote_c2: "ปลายทาง C2 ภายนอก", remote_attacker_infra: "โครงสร้างพื้นฐานของผู้โจมตี", unauthorized_external: "ปลายทางภายนอกที่ไม่ได้รับอนุญาต",
  peer_host_infected: "เครื่องใกล้เคียงที่ติดเชื้อ", db_egress_destination: "ปลายทางที่ DB ส่งข้อมูลออก", victim_service: "บริการปลายทาง",
};
const FIELD_KEYS = Object.keys(FIELD_LABEL);
const VALUE_KEYS = Object.keys(VALUE_LABEL);
/** Any of these tokens in user text is a leaked internal key (checked by the output validator). */
export const RAW_KEY_TOKENS = [...new Set([...FIELD_KEYS.filter((k) => k.includes("_")), ...VALUE_KEYS.filter((k) => k.includes("_")), "process_guid="])];
export const RAW_KEY_RE = new RegExp(`(?<![A-Za-z0-9_])(?:${RAW_KEY_TOKENS.map((k) => k.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})(?![A-Za-z0-9_])`);

export const labelOfField = (f: string) => FIELD_LABEL[f] ?? f.replace(/_/g, " ");

/** A bound target value as it is shown to the user. */
export function humanizeValue(field: string, value: unknown): string {
  const v = Array.isArray(value) ? value.map((x) => humanizeValue(field, x)).join(", ") : String(value);
  if (field === "process_identity" || field === "child_process_identities") return humanizeProcessIdentity(v);
  return VALUE_LABEL[v] ?? v;
}
/** process_guid=<g> -> "GUID <g>";  pid=<n>;start=<t>;image=<p> -> "PID <n> เริ่ม <t> image <p>" (only what the evidence holds). */
export function humanizeProcessIdentity(id: string): string {
  const g = /^process_guid=(\S+)$/.exec(id);
  if (g) return `GUID ${g[1]}`;
  const m = /^pid=(\d+);start=([^;]+);image=(.+)$/.exec(id);
  if (m) return `PID ${m[1]} เริ่ม ${m[2]} image ${m[3]}`;
  return id;
}
/** Safety net over already-rendered text (the templates are written in plain Thai; this only re-labels leaked keys/values). */
export function humanizeText(text: string): string {
  let t = text.replace(/process_guid=(\S+)/g, "GUID $1");
  for (const k of [...VALUE_KEYS, ...FIELD_KEYS].filter((x) => x.includes("_")).sort((a, b) => b.length - a.length)) {
    const label = VALUE_LABEL[k] ?? FIELD_LABEL[k];
    t = t.replace(new RegExp(`(?<![A-Za-z0-9_])${k}(?![A-Za-z0-9_])`, "g"), label);
  }
  return t;
}

export const CAP_LABEL: Record<string, string> = {
  "cap.connection_state_termination": "การตัด session/connection ที่ค้างอยู่", "cap.scoped_network_enforcement": "การจำกัดการเข้าถึงแบบเฉพาะเจาะจง",
  "cap.process_termination": "การยุติ process", "cap.config_snapshot": "การบันทึกค่า configuration", "cap.egress_control": "การควบคุม egress",
  "cap.persistence_trigger_disable": "การ disable persistence trigger", "cap.file_quarantine": "การกักไฟล์", "cap.workload_isolation": "การแยกเครื่อง/workload",
};
export const labelOfCapability = (c: string) => CAP_LABEL[c] ?? c.replace(/^cap\./, "").replace(/_/g, " ");
