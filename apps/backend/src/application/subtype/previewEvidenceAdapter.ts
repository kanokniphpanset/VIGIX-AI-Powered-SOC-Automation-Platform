import { extractWazuhEvidenceV2 } from "../../domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import type { EvidenceV2 } from "../../domain/investigation/evidenceV2/types";
import type { IncidentAlertRow } from "../recommendation/ports/IRecommendationContextRepository";
import type { SubtypeEvidenceRow } from "./factBuilder";

/**
 * Recommendation Preview - READ-ONLY evidence adapter.
 *
 * Live evidence rows were stored without the Evidence Contract v2 document (EVIDENCE_CONTRACT_V2 off), although the raw Wazuh alert
 * they came from is stored (alerts.raw_payload). For the PREVIEW only, this runs the production v2 extractor on that raw alert in
 * memory and attaches the result to a COPY of the row - exactly what buildAlertEvidence would have stored with the flag on.
 *  - nothing is written, no analyst assertion is created, no judgement is added: facts still come only from factBuilder rules;
 *  - refs: an evidence row keeps its E<n>; a linked alert without an evidence row gets A<n> (never renumbering E<n>);
 *  - time: row.timestamp = the Wazuh alert time (alerts.received_at), ingest time (alerts.created_at) is kept separately;
 *  - provenance: the v2 provenance (class REAL_TELEMETRY / MOCK_FIXTURE / ..., alert ids) is kept and reported.
 * Related alerts of OTHER incidents are not used: the SOC must confirm such a relation first (RelatedAlertEvidence).
 */
export type AlertMapping = "STORED_V2" | "ADAPTED_IN_MEMORY" | "EXTRACT_FAILED" | "NOT_WAZUH" | "NO_RAW_ALERT";

export interface AdaptedAlertInfo {
  ref: string;
  externalAlertId: string | null;
  eventTime: string | null;
  ingestedAt: string | null;
  provenanceClass: string | null;
  mapping: AlertMapping;
  error: string | null;
  /** What the alert shows, as label/value pairs (values verbatim from the alert, never completed). */
  observed: { label: string; value: string }[];
  /** Raw alert fields with a value that the v2 contract does not carry (so no rule can use them yet). */
  unmapped: { label: string; path: string; value: string }[];
}

export interface AdaptedEvidence { rows: SubtypeEvidenceRow[]; alerts: AdaptedAlertInfo[]; assertions: number }

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

export function adaptEvidenceForPreview(rows: SubtypeEvidenceRow[], alerts: IncidentAlertRow[]): AdaptedEvidence {
  const byId = new Map(alerts.map((a) => [a.id, a]));
  const used = new Set<string>();
  const out: SubtypeEvidenceRow[] = [];
  const info: AdaptedAlertInfo[] = [];
  for (const row of rows) {
    const structured = obj(row.structured);
    const alert = row.alertId ? byId.get(row.alertId) : undefined;
    if (alert) used.add(alert.id);
    if (row.origin !== "SYSTEM" || row.type !== "WAZUH_ALERT") { out.push(row); continue; }
    if (Object.keys(obj(structured.contractV2)).length) {
      out.push(row);
      info.push(describe(row.ref, alert ?? null, structured.contractV2 as EvidenceV2, "STORED_V2", null));
      continue;
    }
    if (!alert) { out.push(row); info.push({ ...blank(row.ref), mapping: "NO_RAW_ALERT", eventTime: row.timestamp.toISOString() }); continue; }
    const v2 = extract(alert);
    out.push(v2.value ? { ...row, structured: { ...structured, contractV2: v2.value } } : row);
    info.push(describe(row.ref, alert, v2.value, v2.mapping, v2.error));
  }
  // linked alerts without an evidence row of this cycle (e.g. alerts added to the incident later)
  let n = 0;
  for (const alert of alerts) {
    if (used.has(alert.id)) continue;
    const ref = `A${++n}`;
    const v2 = extract(alert);
    const agent = typeof obj(obj(alert.rawPayload).agent).name === "string" ? (obj(obj(alert.rawPayload).agent).name as string) : null;
    if (v2.value) out.push({ id: alert.id, ref, type: "WAZUH_ALERT", origin: "SYSTEM", createdBy: "system", timestamp: alert.eventTime, title: alert.externalAlertId, host: agent, alertId: alert.id, structured: { agent, contractV2: v2.value } });
    info.push(describe(ref, alert, v2.value, v2.mapping, v2.error));
  }
  return { rows: out, alerts: info, assertions: rows.filter((r) => r.origin === "MANUAL" && Object.keys(obj(obj(r.structured).subtypeFacts)).length).length };
}

function extract(alert: IncidentAlertRow): { value: EvidenceV2 | null; mapping: AlertMapping; error: string | null } {
  if (alert.siemSource.toLowerCase() !== "wazuh") return { value: null, mapping: "NOT_WAZUH", error: null };
  const r = extractWazuhEvidenceV2(alert.rawPayload, { alertRowId: alert.id, receivedAt: alert.ingestedAt, externalAlertId: alert.externalAlertId });
  return r.isSuccess ? { value: r.value, mapping: "ADAPTED_IN_MEMORY", error: null } : { value: null, mapping: "EXTRACT_FAILED", error: r.error };
}

const blank = (ref: string): AdaptedAlertInfo => ({ ref, externalAlertId: null, eventTime: null, ingestedAt: null, provenanceClass: null, mapping: "NO_RAW_ALERT", error: null, observed: [], unmapped: [] });

function describe(ref: string, alert: IncidentAlertRow | null, v2: EvidenceV2 | null, mapping: AlertMapping, error: string | null): AdaptedAlertInfo {
  return {
    ref, externalAlertId: alert?.externalAlertId ?? v2?.provenance.source.alertId ?? null,
    eventTime: v2?.provenance.time.eventAt ?? alert?.eventTime.toISOString() ?? v2?.provenance.time.detectedAt ?? null,
    ingestedAt: alert?.ingestedAt.toISOString() ?? v2?.provenance.time.receivedAt ?? null,
    provenanceClass: v2?.provenance.class ?? null, mapping, error,
    observed: v2 ? observedOf(v2) : [], unmapped: alert && v2 ? unmappedOf(alert.rawPayload, v2) : [],
  };
}

function observedOf(v: EvidenceV2): { label: string; value: string }[] {
  const o: { label: string; value: string }[] = [];
  const add = (label: string, value: unknown) => { if (value !== null && value !== undefined && String(value).trim()) o.push({ label, value: String(value) }); };
  const e = v.evidence;
  add("เครื่องที่ตรวจพบ (agent)", [v.provenance.agent.name, v.provenance.agent.ip].filter(Boolean).join(" / "));
  add("กฎที่ตรวจจับ", `${v.detection.rule.id} — ${v.detection.rule.description}`);
  add("Process", e.process.image);
  add("Command line", e.process.commandLine);
  add("PID", e.process.pid);
  add("GUID ของ Process", e.process.guid);
  add("เวลาเริ่ม Process", e.process.startedAt);
  add("Process แม่", e.process.parent.image ?? e.process.parent.name);
  add("ผู้ใช้ของ Process", e.process.user?.raw);
  add("ผลการยืนยันตัวตน", e.authentication.result?.value === "FAILURE" ? "ล้มเหลว" : e.authentication.result?.value === "SUCCESS" ? "สำเร็จ" : null);
  add("ที่อยู่ต้นทางของการล็อกอิน", e.authentication.remote.ip);
  add("บัญชีที่ถูกใช้/พยายามใช้", e.authentication.attemptedAccount ?? e.authentication.account);
  add("ต้นทาง (network)", e.network.src.ip ? `${e.network.src.ip}${e.network.src.port ? `:${e.network.src.port}` : ""}` : null);
  add("ปลายทาง (network)", e.network.dst.ip ? `${e.network.dst.ip}${e.network.dst.port ? `:${e.network.dst.port}` : ""}` : null);
  add("URL", e.network.url);
  add("ชื่อ DNS", e.network.dnsQuery);
  add("ทิศทาง", e.network.direction?.value === "OUTBOUND" ? "ออกนอกเครือข่าย" : null);
  add("ปริมาณข้อมูลออก (bytes)", e.network.bytesOut);
  add("HTTP request", [e.http.method, e.http.requestTarget, e.http.status].filter((x) => x !== null && x !== undefined).join(" "));
  add("ไฟล์", e.file.path ?? e.syscheck.path);
  add("SHA256", e.file.hashes.sha256 ?? e.syscheck.hashes.after.sha256);
  add("การเปลี่ยนแปลงไฟล์", e.syscheck.operation);
  add("บัญชี/กลุ่มที่ถูกแก้", [e.account.user, e.account.group].filter(Boolean).join(" → "));
  add("ผู้ส่งอีเมล", e.email.sender);
  // carried by v2 only as indicators (no target is built from them): shown so the analyst can tie them to the activity
  for (const i of v.iocs) {
    if (i.type === "REGISTRY_KEY") add("Registry key (ตัวบ่งชี้ — ยังไม่ถูกใช้เป็นเป้าหมาย)", i.value);
    if (i.type === "REGISTRY_VALUE") add("ค่าใน Registry (ตัวบ่งชี้)", i.value);
  }
  return o;
}

/** Wazuh fields the subtype knowledge would need a mapping for (Thai label); anything else is listed by its path only. */
const RAW_LABEL: Record<string, string> = {
  "data.win.eventdata.targetObject": "Registry key ที่ถูกแก้", "data.win.eventdata.details": "ค่าที่เขียนลง Registry", "data.win.eventdata.eventType": "ชนิดเหตุการณ์ Registry",
  "data.win.eventdata.memberName": "สมาชิกที่ถูกเพิ่ม", "data.win.eventdata.targetUserName": "กลุ่ม/บัญชีปลายทาง", "data.win.eventdata.subjectUserName": "บัญชีที่ทำการเปลี่ยน",
  "data.virustotal.positives": "จำนวน engine ที่ตรวจพบ (VirusTotal)", "data.virustotal.malicious": "ผล VirusTotal", "data.virustotal.total": "จำนวน engine ทั้งหมด (VirusTotal)",
  "data.audit.command": "คำสั่ง (auditd)", "data.audit.exe": "ไฟล์ที่รัน (auditd)", "data.audit.ppid": "PID ของ Process แม่ (auditd)", "data.audit.auid": "audit user id", "data.audit.uid": "user id",
  "data.dstuser": "บัญชีปลายทาง", "data.srcuser": "บัญชีต้นทาง", "data.id": "HTTP status", "data.protocol": "HTTP method", "data.url": "URL ที่ถูกเรียก",
};

function unmappedOf(raw: unknown, v2: EvidenceV2): { label: string; path: string; value: string }[] {
  // fullLog is the raw log line as text: a value only present there is not usable by any rule, so it does not count as mapped
  const v2Text = JSON.stringify({ ...v2, fullLog: null }).toLowerCase();
  const out: { label: string; path: string; value: string }[] = [];
  const walk = (v: unknown, p: string) => {
    if (out.length >= 20) return;
    if (v && typeof v === "object") { if (!Array.isArray(v)) for (const [k, x] of Object.entries(v)) walk(x, p ? `${p}.${k}` : k); return; }
    if (!p.startsWith("data.") || v === null || v === undefined || String(v).trim() === "") return;
    const s = String(v);
    if (v2Text.includes(JSON.stringify(s).slice(1, -1).toLowerCase())) return;   // already carried by v2 (escaped as in the JSON text)
    out.push({ label: RAW_LABEL[p] ?? "", path: p, value: s.length > 160 ? `${s.slice(0, 157)}…` : s });
  };
  walk(obj(raw).data, "data");
  return out;
}
