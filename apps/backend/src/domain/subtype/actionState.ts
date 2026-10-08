import { InstanceState } from "./planner";
import { KnowledgeBase, ResolvedTarget } from "./types";

/**
 * ActionStateAssessor - what happened to an action instance since it was last proposed, from REAL records only:
 * Response Tickets (ResponsePlan status + the IR's own execution result) and the re-hunt Verification of the previous cycle.
 *
 * New activity after a re-hunt is NOT a reason to repeat the same action automatically. The next step is chosen from the facts:
 *
 *   decision      meaning                                                        when
 *   NO_NEW_ACTION nothing to propose now                                         still effective (covered re-hunt, no recurrence) or a ticket still open
 *   INVESTIGATE   gather information first; do not repeat, do not call it done   re-hunt missing / older than the execution / coverage incomplete /
 *                                                                                newer evidence than the re-hunt / recurrence not corroborated for THIS target /
 *                                                                                recurrence but the control state is unknown (the IR left no record of it)
 *   REPEAT        propose the same action again, with the reason                 execution FAILED, or the IR recorded the control as NOT_APPLIED / PARTIAL
 *   ADJUST        do NOT repeat; scope/path must be re-examined                  corroborated recurrence at this target although the IR attested the control was applied
 *   ADD           a target/scope not handled before -> a new instance            no earlier ticket for this action on this target in a later round
 *
 * "No new alert" is never evidence of containment: only a re-hunt that is newer than the execution, newer than the target's latest evidence and
 * whose coverage was complete counts. The IR's `executionResult` is opaque, so the control state is only what the IR wrote:
 * `controlState` (APPLIED | PARTIAL | NOT_APPLIED) if given, otherwise a non-empty note counts as an attestation that it was applied,
 * otherwise the control state is UNKNOWN.
 */
export type RehuntDecision = "NEW" | "ADD" | "NO_NEW_ACTION" | "INVESTIGATE" | "REPEAT" | "ADJUST";
export interface TicketRecord {
  actionCode: string;
  target: string;
  status: string; // ResponsePlan.status
  executionNote?: string | null;
  /** IR-supplied control state when the IR recorded one (opaque executionResult.controlState). */
  controlState?: string | null;
  completedAt?: Date | null;
  investigationNumber: number;
}
export interface RehuntRecord {
  verifiedInvestigationNumber: number;
  result: "RESOLVED" | "NOT_RESOLVED";
  classification?: string | null;      // NO_MATCH_COVERED | IN_SCOPE_ACTIVITY | NEW_SCOPE_ACTIVITY ...
  coverageComplete?: boolean | null;   // false/null => absence cannot be claimed
  spreadDetected: boolean;
  matchingEvents: number;
  originalHosts: string[];
  affectedHosts: string[];
  newHosts: string[];
  verifiedAt?: Date | null;
}
export interface StateInput {
  tickets: TicketRecord[]; rehunt: RehuntRecord | null; currentInvestigationNumber: number;
  /** latest evidence time among these evidence refs (current cycle), or null when unknown. */
  evidenceAt?: (refs: string[]) => Date | null;
}
export interface StateAssessment { state: InstanceState; reason: string | null; needs?: string[]; decision: RehuntDecision }

const OPEN = new Set(["PENDING_IR_DECISION", "APPROVED", "IN_PROGRESS", "DRAFT", "READY", "STARTED"]);
const norm = (s: string | null | undefined) => (s ?? "").trim().toLowerCase();
const iso = (d: Date) => d.toISOString();

export function controlStateOf(t: TicketRecord): "APPLIED" | "NOT_APPLIED" | "UNKNOWN" {
  const c = norm(t.controlState);
  if (c === "applied") return "APPLIED";
  if (c === "partial" || c === "not_applied" || c === "not applied") return "NOT_APPLIED";
  return norm(t.executionNote) ? "APPLIED" : "UNKNOWN";
}

export function makeStateAssessor(kb: KnowledgeBase, input: StateInput) {
  const laterRound = input.currentInvestigationNumber > 1 || input.tickets.length > 0 || !!input.rehunt;
  return (a: { action_id: string; primary: ResolvedTarget | null }): StateAssessment => {
    const legacy = new Set([a.action_id, ...(kb.actions.get(a.action_id)?.legacy_action_refs ?? [])]);
    const target = norm(a.primary?.display);
    const mine = input.tickets.filter((t) => legacy.has(t.actionCode) && (!target || norm(t.target) === target));
    if (!mine.length) return { state: "NEW", reason: null, decision: laterRound ? "ADD" : "NEW" };
    const latest = mine[mine.length - 1];
    if (OPEN.has(latest.status)) return { state: "PROPOSED_PENDING", reason: "มี Response Ticket ของมาตรการนี้ที่ยังรอ/กำลังดำเนินการ (ticket ที่สร้างแล้วยังไม่ใช่การดำเนินการเสร็จ) จึงไม่เสนอซ้ำ", decision: "NO_NEW_ACTION" };
    if (latest.status === "FAILED") return { state: "FAILED", reason: `การดำเนินการรอบก่อนล้มเหลว${latest.executionNote ? ` (${latest.executionNote})` : ""} จึงเสนอใหม่ — ตรวจสาเหตุที่ IR บันทึกไว้ก่อนทำซ้ำ`, decision: "REPEAT" };
    if (latest.status === "REJECTED" || latest.status === "CANCELLED") return { state: "NEW", reason: "IR ไม่ได้ดำเนินการตามคำแนะนำรอบก่อน", decision: "ADD" };
    if (latest.status !== "COMPLETED") return { state: "NEW", reason: null, decision: "ADD" };

    const where = a.primary?.display ?? "มาตรการนี้";
    const unverified = (reason: string, needs: string[]): StateAssessment => ({ state: "EXECUTED_UNVERIFIED", reason, needs, decision: "INVESTIGATE" });
    const r = input.rehunt;
    if (!r || r.verifiedInvestigationNumber < latest.investigationNumber) {
      return unverified("ดำเนินการแล้วแต่ยังไม่มีผล Re-hunt หลังการดำเนินการที่ใช้ยืนยันได้ จึงยังไม่ถือว่ามาตรการมีผล และไม่เสนอซ้ำโดยไม่มีเหตุ", [`ผล Re-hunt หลังการดำเนินการของ ${where}`]);
    }
    if (r.verifiedAt && latest.completedAt && r.verifiedAt <= latest.completedAt) {
      return unverified(`Re-hunt ทำเมื่อ ${iso(r.verifiedAt)} ซึ่งไม่ใหม่กว่าเวลาที่ IR ดำเนินการเสร็จ (${iso(latest.completedAt)}) จึงยืนยันผลของมาตรการไม่ได้`, [`ผล Re-hunt ที่ทำหลังเวลา ${iso(latest.completedAt)} ของ ${where}`]);
    }
    const evAt = input.evidenceAt ? input.evidenceAt(a.primary?.evidenceRefs ?? []) : null;
    if (evAt && r.verifiedAt && evAt > r.verifiedAt && r.result === "RESOLVED") {
      return unverified(`มีหลักฐานของ target นี้ใหม่กว่าเวลา Re-hunt (${iso(evAt)} > ${iso(r.verifiedAt)}) ผล Re-hunt จึงไม่ครอบคลุมช่วงล่าสุด`, [`Re-hunt ใหม่ที่ครอบคลุมถึง ${iso(evAt)} ของ ${where}`]);
    }
    if (r.coverageComplete !== true && r.result === "RESOLVED") {
      return unverified("Re-hunt ไม่ครอบคลุมเพียงพอ จึงยืนยันไม่ได้ทั้งว่ามาตรการยังมีผลหรือล้มเหลว (ไม่ถือว่า contained)", [`telemetry ที่ครอบคลุมครบและเป็นข้อมูลล่าสุดของ ${a.primary?.display ?? "เครื่องที่เกี่ยวข้อง"} ในช่วงตรวจ (agent ออนไลน์ ส่ง log ต่อเนื่อง ครอบคลุมแหล่งข้อมูลที่เกี่ยวข้อง)`]);
    }
    const affected = r.affectedHosts.map(norm);
    const original = r.originalHosts.map(norm);
    const host = norm(a.primary?.hostKey);
    // recurrence IN THIS TARGET'S SCOPE: its host shows corroborated activity again; a target without a host falls back to the original scope.
    const recurredHere = r.result === "NOT_RESOLVED" && r.matchingEvents > 0
      && (host ? affected.includes(host) : original.some((h) => affected.includes(h)) || (!r.newHosts.length && affected.length > 0));
    if (recurredHere) {
      const seen = `Re-hunt พบ ${r.matchingEvents} เหตุการณ์ที่เกี่ยวข้องกลับมาในขอบเขตเดียวกัน${r.affectedHosts.length ? ` (เครื่อง: ${r.affectedHosts.join(", ")})` : ""}`;
      // the recurrence must be corroborated for THIS target: its own evidence has to be newer than the execution
      const corroborated = !!(evAt && latest.completedAt && evAt > latest.completedAt);
      if (!corroborated) {
        return unverified(`${seen} แต่ยังไม่พบหลักฐานของ target นี้ที่เกิดหลังเวลาที่ IR ดำเนินการเสร็จ${latest.completedAt ? ` (${iso(latest.completedAt)})` : " (ไม่ทราบเวลา)"} จึงยังไม่ถือว่ามาตรการนี้ไม่ได้ผล และยังไม่เสนอซ้ำ`, [`เวลาของเหตุการณ์ที่เกี่ยวกับ ${where} เทียบกับเวลาที่ IR ดำเนินการเสร็จ และรายละเอียดว่ากิจกรรมใหม่ใช้เส้นทาง/ขอบเขตเดียวกับมาตรการเดิมหรือไม่`]);
      }
      const cs = controlStateOf(latest);
      if (cs === "NOT_APPLIED") return { state: "EXECUTED_NOT_APPLIED", reason: `${seen} และ IR บันทึกว่ามาตรการเดิมไม่ได้ใช้ครบ (${latest.controlState}) จึงเสนอทำซ้ำ — ตรวจบันทึกการดำเนินการของ IR ก่อนลงมือ`, decision: "REPEAT" };
      if (cs === "APPLIED") return { state: "RECURRED_CONTROL_APPLIED", reason: `${seen} หลังจาก IR บันทึกว่าได้ใช้มาตรการเดิมแล้ว จึงไม่เสนอทำซ้ำ — มาตรการเดิมอาจไม่ครอบคลุมเส้นทาง/ขอบเขตของกิจกรรมใหม่ ต้องตรวจเส้นทาง บัญชี หรือบริการที่กิจกรรมใหม่ใช้ แล้วประเมินปรับขอบเขตหรือเพิ่มมาตรการอื่น`, needs: [`เส้นทาง/บริการ/บัญชีที่กิจกรรมใหม่ของ ${where} ใช้ เทียบกับขอบเขตของมาตรการเดิม`], decision: "ADJUST" };
      return { state: "RECURRED_CONTROL_UNKNOWN", reason: `${seen} หลังเวลาที่ IR ดำเนินการเสร็จ แต่ไม่มีบันทึกสถานะของมาตรการเดิม (control state) จึงไม่เสนอซ้ำจนกว่าจะตรวจสถานะนั้น`, needs: [`สถานะปัจจุบันของมาตรการเดิมที่ ${where} (ยังบังคับใช้อยู่หรือไม่ ใช้กับ target/scope นี้จริงหรือไม่) จากบันทึกของ IR หรือจุดควบคุม`], decision: "INVESTIGATE" };
    }
    if (r.result === "RESOLVED") return { state: "EXECUTED_EFFECTIVE", reason: "Re-hunt ที่ coverage ครบและใหม่กว่าการดำเนินการไม่พบกิจกรรมซ้ำในช่วงตรวจ มาตรการเดิมจึงยังมีผลตามข้อมูลล่าสุด (ไม่ใช่การยืนยันว่า incident ปิดแล้ว) จึงไม่เสนอซ้ำ", decision: "NO_NEW_ACTION" };
    return { state: "EXECUTED_EFFECTIVE", reason: "กิจกรรมใหม่เกิดที่ scope ใหม่ ไม่ใช่ target นี้ — มาตรการเดิมของ target นี้ยังคงอยู่", decision: "NO_NEW_ACTION" };
  };
}
