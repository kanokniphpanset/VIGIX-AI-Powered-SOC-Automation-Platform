import { TicketRecord } from "../../src/domain/subtype/actionState";
import { RehuntContextRow } from "../../src/application/recommendation/ports/IRecommendationContextRepository";
import { ORG_SSH, orgLoader } from "./subtypeFlowHarness";
import { analystRow, evaluate, realAlert, resetRefs, syntheticAlert } from "./subtypeFixtures";

/**
 * Fixtures for the user-facing format review (8 backend sample outputs + authority/capability-missing cases).
 * Recorded Wazuh alerts (5712, 100320) go through the real Evidence Contract v2 extractor; the Scheduled Task Hijack rows are synthetic Sysmon +
 * analyst assertions. The organization contexts below are TEST FIXTURES, not the real organization (the repo's own context is all UNKNOWN).
 */
export const sysmon = () => syntheticAlert({ ruleId: "92200", eventdata: { processGuid: "{7f3a21aa-0001-6700-0000-001000000200}", processId: "4242", utcTime: "2026-10-08 01:00:00.000", image: "C:\\Users\\Public\\upd.exe", commandLine: "upd.exe /s", user: "WKS\\fin.user" } });
const TASK = { type: "persistence_artifact", fields: { host_id: "WKS-FIN-07", artifact_type: "scheduled_task", artifact_locator: "\\Maintenance\\SyncReport" }, source_event_refs: ["E1"] };
const PERSIST = { id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] };
const PAYLOAD = { id: "payload_linked_malicious_execution", status: "PRESENT", source_event_refs: ["E1"] };
const C2 = { id: "c2_web_channel_correlated", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] };
export const hijackBasic = () => analystRow({ evidence: [PERSIST, PAYLOAD], targets: [TASK] } as never);
export const hijackFull = () => analystRow({
  evidence: [PERSIST, PAYLOAD, C2],
  targets: [
    TASK,
    { type: "destination_endpoint", fields: { destination: "update-cdn.example-bad.test/api/v2/poll", granularity: "URL path" }, source_event_refs: ["E1"] },
    { type: "network_flow", fields: { source_host_id: "WKS-FIN-07", destination: "203.0.113.45", destination_role: "remote_c2", protocol: "TCP", port: 443 }, source_event_refs: ["E1"] },
    { type: "file_object", fields: { host_id: "WKS-FIN-07", object_locator: "C:\\Users\\Public\\upd.exe" }, source_event_refs: ["E1"] },
  ],
} as never);

export const T = "172.19.0.3";
export const ticket = (o: Partial<TicketRecord> = {}): TicketRecord => ({ actionCode: "ACT-AUTH-SOURCE-RESTRICT", target: T, status: "COMPLETED", investigationNumber: 1, completedAt: new Date("2026-10-08T04:00:00Z"), ...o });
export const rehunt = (o: Partial<RehuntContextRow> = {}): RehuntContextRow => ({
  verificationId: "ver-1", verifiedInvestigationNumber: 1, source: "WAZUH_INDEXER", result: "RESOLVED", spreadDetected: false, matchingEvents: 0, originalHosts: ["attack-endpoint"], affectedHosts: [],
  newHosts: [], truncated: false, classification: "NO_MATCH_COVERED", coverageComplete: true, ...o,
});
const FW_TOOLS = `${ORG_SSH}capability:\n  cap.scoped_network_enforcement: true\n  cap.connection_state_termination: true\n`;

export const acctRows = () => [realAlert("5712"), analystRow({
  evidence: [{ id: "ac_unauthorized_password_auth", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] }],
  targets: [{ type: "account_identity", fields: { account_id: "fin.user", provider: "ตัวอย่าง IdP ใน fixture", tenant_or_scope: "fixture-tenant" }, source_event_refs: ["E1"] }],
} as never)];
/** Evidence 5712 is dated 2026-10-03; EARLIER is before it (so the target's activity is AFTER the execution), the default ticket time is after it. */
export const EARLIER = new Date("2026-10-01T00:00:00Z");
export const recurred = (o: Partial<RehuntContextRow> = {}) => rehunt({ result: "NOT_RESOLVED", matchingEvents: 4, affectedHosts: ["attack-endpoint"], classification: "IN_SCOPE_ACTIVITY", verifiedAt: new Date("2026-10-02T00:00:00Z"), ...o });
export type Scenario = { id: string; title: string; note: string; run: () => ReturnType<typeof evaluate> };
const fresh = <R>(f: () => R) => () => { resetRefs(); return f(); };
export const SCENARIOS: Scenario[] = [
  { id: "ssh-restriction", title: "SSH brute force - จำกัดต้นทาง", note: "recorded 5712 + org fixture (enforcement point; ยังไม่ระบุเครื่องมือตัด connection)", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH) })) },
  { id: "ssh-tools-confirmed", title: "SSH brute force - ระบุเครื่องมือตัด connection แล้ว", note: "recorded 5712 + org fixture (cap.connection_state_termination = true)", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(FW_TOOLS) })) },
  { id: "missing-enforcement-point", title: "ขาดข้อมูลจุดควบคุม (org context ว่าง = ค่าจริงของ repo)", note: "recorded 5712 + org context ว่าง", run: fresh(() => evaluate([realAlert("5712")])) },
  { id: "outbound-only", title: "Outbound อย่างเดียว ไม่พอสรุป C2", note: "recorded 100320", run: fresh(() => evaluate([realAlert("100320")])) },
  { id: "hijack-basic", title: "Scheduled Task Hijack - หลักฐานเบื้องต้น", note: "synthetic Sysmon + analyst assertion", run: fresh(() => evaluate([sysmon(), hijackBasic()])) },
  { id: "hijack-full", title: "Scheduled Task Hijack - หลักฐานครบ (ยังไม่ระบุเครื่องมือตัด connection)", note: "synthetic Sysmon + analyst assertion", run: fresh(() => evaluate([sysmon(), hijackFull()])) },
  { id: "rehunt-effective", title: "หลัง Re-hunt - มาตรการยังมีผล", note: "recorded 5712 + ticket COMPLETED + re-hunt coverage ครบ", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), tickets: [ticket()], rehunt: rehunt(), investigationNumber: 2 })) },
  { id: "rehunt-unverified", title: "หลัง Re-hunt - ยืนยันไม่ได้ (coverage ไม่ครบ)", note: "recorded 5712 + ticket COMPLETED + re-hunt coverage ไม่ครบ", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), tickets: [ticket()], rehunt: rehunt({ coverageComplete: false }), investigationNumber: 2 })) },
  { id: "rehunt-returned-control-unknown", title: "หลัง Re-hunt - ภัยกลับมา แต่ไม่มีบันทึกสถานะมาตรการเดิม", note: "recorded 5712 + ticket COMPLETED (ไม่มี note/controlState) ก่อนหลักฐานล่าสุด + re-hunt พบกิจกรรมกลับมา", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), tickets: [ticket({ completedAt: EARLIER })], rehunt: recurred(), investigationNumber: 2 })) },
  { id: "rehunt-returned-control-applied", title: "หลัง Re-hunt - ภัยกลับมา หลัง IR บันทึกว่าใช้มาตรการแล้ว", note: "ticket COMPLETED + note จาก IR + หลักฐานของ target ใหม่กว่าเวลาดำเนินการ", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), tickets: [ticket({ completedAt: EARLIER, executionNote: "IR ตั้ง deny ที่ FW-EDGE-1 ตามขั้นตอน (บันทึกตัวอย่างใน fixture)" })], rehunt: recurred(), investigationNumber: 2 })) },
  { id: "rehunt-returned-not-applied", title: "หลัง Re-hunt - ภัยกลับมา และ IR บันทึกว่าไม่ได้ใช้มาตรการครบ", note: "ticket COMPLETED + controlState=PARTIAL + หลักฐานใหม่กว่าเวลาดำเนินการ", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(ORG_SSH), tickets: [ticket({ completedAt: EARLIER, controlState: "PARTIAL", executionNote: "ตั้ง rule ได้เฉพาะบางส่วน (บันทึกตัวอย่างใน fixture)" })], rehunt: recurred(), investigationNumber: 2 })) },
  { id: "needs-authorization", title: "ต้องขออนุมัติ - IR ยังไม่ได้รับอำนาจดำเนินการ", note: "recorded 5712 + org fixture (authority.ir_execute = false) ; ผู้ติดต่อไม่ได้ระบุ", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(`${FW_TOOLS}authority:\n  ir_execute: false\n`) })) },
  { id: "needs-authorization-contact", title: "ต้องขออนุมัติ - องค์กรระบุผู้ติดต่อ", note: "เหมือนกันแต่ org fixture ระบุ authority_contacts.ir_execute", run: fresh(() => evaluate([realAlert("5712")], { loader: orgLoader(`${FW_TOOLS}authority:\n  ir_execute: false\nauthority_contacts:\n  ir_execute: "IR on-call (ช่องทางตัวอย่างใน fixture)"\n`) })) },
  { id: "needs-asset-owner", title: "ต้องขออนุมัติ - asset สำคัญ ต้องได้รับอนุมัติจากเจ้าของ asset", note: "recorded 5712 (E1) + analyst assertion บัญชีถูกยึด + asset CRITICAL; ไม่ระบุผู้ติดต่อ", run: fresh(() => evaluate(acctRows(), { criticality: "CRITICAL" })) },
  { id: "needs-asset-owner-contact", title: "ต้องขออนุมัติ - องค์กรระบุผู้ติดต่อเจ้าของ asset", note: "เหมือนกันแต่ org fixture ระบุ authority_contacts.asset_owner", run: fresh(() => evaluate(acctRows(), { criticality: "CRITICAL", loader: orgLoader(`authority_contacts:\n  asset_owner: "ทีมเจ้าของระบบ Finance (ช่องทางตัวอย่างใน fixture)"\n`) })) },
];
