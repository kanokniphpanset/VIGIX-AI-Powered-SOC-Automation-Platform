import { attackTypeForIncidentType } from "../../domain/knowledge/attackKnowledge";
import { Facts, KnowledgeBase, Predicate } from "../../domain/subtype/types";
import { labelOfField } from "../../domain/subtype/wording";

/**
 * Recommendation Preview - what the incident's evidence still lacks, stated SPECIFICALLY (read-only, no new facts):
 *  - targets found in the evidence and, for each one that did not validate, exactly what is missing (Thai wording of the
 *    target resolver findings; internal field names are re-labelled);
 *  - for the incident's attack family (SOC-chosen or MITRE-detected type), per subtype: the evidence the knowledge needs to
 *    classify it that is not PRESENT yet (the knowledge's own `confirm` instruction) and what is NOT enough on its own.
 */
export interface EvidenceGap {
  family: { label: string; source: "SOC" | "MITRE" } | null;
  targets: { label: string; value: string; ok: boolean; problems: string[] }[];
  needed: { subtype: string; items: string[]; notEnough: string[] }[];
}

const FAMILY_LABEL: Record<string, string> = {
  BRUTE_FORCE: "Brute force", MALWARE: "Malware", PHISHING: "Phishing", ACCOUNT_COMPROMISE: "บัญชีถูกยึด (Account compromise)", POWERSHELL: "PowerShell",
  SQL_INJECTION: "SQL injection", COMMAND_AND_CONTROL: "Command and control", SUSPICIOUS_PROCESS: "Process ที่น่าสงสัย", DATA_EXFILTRATION: "ข้อมูลรั่วไหล (Data exfiltration)",
  PRIVILEGE_ESCALATION: "ยกระดับสิทธิ์ (Privilege escalation)",
};

export function familyOfIncidentType(incidentType: string | null | undefined): string | null {
  const a = attackTypeForIncidentType(incidentType);
  return a === "SUSPICIOUS_PROCESS_EXECUTION" ? "SUSPICIOUS_PROCESS" : a;
}

/** Leaves that must hold for the predicate to be TRUE (none_of branches are exclusions, not requirements). */
function requiredLeaves(p: Predicate | undefined | null, out: { field: string; value: unknown }[] = []): { field: string; value: unknown }[] {
  if (!p) return out;
  if ("field" in p) { out.push({ field: p.field, value: p.value }); return out; }
  if ("all_of" in p) for (const k of p.all_of) requiredLeaves(k, out);
  else if ("any_of" in p) for (const k of p.any_of) requiredLeaves(k, out);
  return out;
}

const FINDING_TH: [RegExp, (m: RegExpMatchArray) => string][] = [
  [/^process identity incomplete/i, () => "ยังระบุ Process ไม่ได้: ต้องมี GUID ของ Process หรือ PID + เวลาเริ่ม + ไฟล์ที่รัน (มีเพียงชื่อหรือ PID ไม่พอ)"],
  [/^missing required field process_identity$/i, () => ""],
  [/^missing required field (\w+)/i, (m) => `ต้องระบุ${labelOfField(m[1])}`],
  [/^source role is not explicitly attacker_source/i, () => "หลักฐานยังไม่ยืนยันว่าที่อยู่นี้เป็นฝั่งผู้โจมตี"],
  [/^address is the agent\/observer/i, () => "ที่อยู่นี้เป็นเครื่องที่ตรวจจับ (agent) ไม่ใช่ผู้โจมตี"],
  [/^destination role is not an evidenced remote role/i, () => "ยังไม่มีหลักฐานระบุบทบาทของปลายทาง (เช่น C2 หรือปลายทางที่รับข้อมูลออก)"],
  [/^destination is the agent\/observer/i, () => "ปลายทางนี้เป็นเครื่องที่ตรวจจับ (agent)"],
  [/^every child needs/i, () => "Process ลูกทุกตัวต้องมีตัวระบุ Process และหลักฐานความสัมพันธ์แม่-ลูก"],
];
/** Knowledge text may cite internal ids, e.g. "(PS-P1)", "(BF-P1, BF-P2)"; they never reach the user text. */
const stripIds = (t: string) => t.replace(/\s*\((?:[A-Z0-9]+-[A-Z0-9-]+)(?:\s*[,/]\s*[A-Z0-9]+-[A-Z0-9-]+)*\)/g, "").trim();

function findingTh(f: string): string {
  for (const [re, fn] of FINDING_TH) { const m = f.match(re); if (m) return fn(m); }
  return "ข้อมูลเป้าหมายยังไม่ผ่านการตรวจ";
}

export function evidenceGap(
  kb: KnowledgeBase, facts: Facts | null, candidates: { type: string; validated: boolean; findings: string[]; display: string }[],
  family: { key: string; source: "SOC" | "MITRE" } | null, activeSubtypes: string[]
): EvidenceGap {
  const targets = candidates.map((c) => ({
    label: kb.targetTypes.get(c.type)?.label_th ?? c.type, value: c.display, ok: c.validated,
    problems: [...new Set(c.findings.map(findingTh).filter(Boolean))],
  }));
  const needed: EvidenceGap["needed"] = [];
  if (family) {
    for (const pb of [...kb.playbooks.values()].filter((p) => p.attack_family === family.key && !activeSubtypes.includes(p.subtype_id))) {
      const items: string[] = [];
      for (const leaf of requiredLeaves(pb.classification_evidence)) {
        const m = /^evidence\.([a-z0-9_]+)\.(status|authorization_status)$/.exec(leaf.field);
        if (!m) continue;
        const fact = facts?.evidence.get(m[1]);
        const ok = m[2] === "status" ? fact?.status === leaf.value : fact?.authorization === leaf.value;
        if (ok) continue;
        const def = kb.evidence.get(m[1]);
        if (def?.confirm) items.push(stripIds(def.confirm));
      }
      if (items.length) needed.push({ subtype: pb.subtype_name, items: [...new Set(items)], notEnough: (pb.insufficient_evidence ?? []).map(stripIds) });
    }
  }
  return { family: family ? { label: FAMILY_LABEL[family.key] ?? family.key, source: family.source } : null, targets, needed };
}
