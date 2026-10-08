import * as fs from "node:fs";
import * as path from "node:path";
import { extractWazuhEvidenceV2 } from "../../domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import { TicketRecord } from "../../domain/subtype/actionState";
import { SubtypeKnowledgeLoader } from "../../infrastructure/knowledge/SubtypeKnowledgeLoader";
import { IRecommendationContextRepository, RehuntContextRow } from "../recommendation/ports/IRecommendationContextRepository";
import { SubtypeEvidenceRow } from "./factBuilder";
import { SubtypePreview, presentEvaluation } from "./PreviewSubtypeRecommendation.usecase";
import { SubtypeRecommendationService } from "./SubtypeRecommendationService";

/**
 * FIXTURE Recommendation Preview (simulated data). Shows the new recommendation format with targets when no real incident carries
 * Evidence Contract v2 / analyst-assertion evidence yet. Disabled unless RECOMMENDATION_PREVIEW_FIXTURES=true.
 *
 * Inputs: a RECORDED Wazuh alert from test/fixtures/wazuh-real run through the production Evidence Contract v2 extractor, synthetic
 * analyst assertions, synthetic tickets / re-hunt results, and fixture organization contexts (test/fixtures/recommendation-preview).
 * Everything runs in memory through the production SubtypeRecommendationService: no database, no ticket, no action, nothing persisted.
 * The output is never attached to a real incident; it is labelled FIXTURE_PREVIEW.
 */
export const previewFixturesEnabled = (env: NodeJS.ProcessEnv = process.env) => env.RECOMMENDATION_PREVIEW_FIXTURES === "true";

const BACKEND = path.resolve(__dirname, "../../..");
const RECORDED = path.join(BACKEND, "test/fixtures/wazuh-real");
const ORG = path.join(BACKEND, "test/fixtures/recommendation-preview");

type Rows = () => SubtypeEvidenceRow[];
interface FixtureScenario { id: string; title: string; note: string; rows: Rows; org?: string; tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null; investigationNumber?: number; criticality?: string }

function wazuhRow(file: string, n: number): SubtypeEvidenceRow {
  const payload = JSON.parse(fs.readFileSync(path.join(RECORDED, fs.readdirSync(RECORDED).find((f) => f.startsWith(`${file}-`))!), "utf8"));
  const r = extractWazuhEvidenceV2(payload, { receivedAt: new Date("2026-10-08T02:00:00Z") });
  if (r.isFailure) throw new Error(r.error);
  const agent = payload.agent?.name ?? null;
  return { id: `fixture-${n}`, ref: `E${n}`, type: "WAZUH_ALERT", origin: "SYSTEM", createdBy: "system", timestamp: new Date(payload.timestamp), title: payload.rule?.description ?? "alert", host: agent, structured: { agent, ruleId: String(payload.rule?.id ?? ""), contractV2: r.value } };
}
const assertion = (n: number, facts: unknown): SubtypeEvidenceRow => ({
  id: `fixture-${n}`, ref: `E${n}`, type: "ANALYST_ASSERTION", origin: "MANUAL", createdBy: "fixture.analyst@example.test", timestamp: new Date("2026-10-08T03:00:00Z"), title: "SOC analyst assertion (fixture)", host: null, structured: { subtypeFacts: facts },
});
function sysmonRow(n: number): SubtypeEvidenceRow {
  const r = extractWazuhEvidenceV2({
    id: "1759900000.100001", timestamp: "2026-10-08T01:00:00.000+0000", agent: { id: "011", name: "WKS-FIN-07", ip: "10.20.0.7" }, manager: { name: "wazuh.manager" },
    rule: { id: "92200", level: 12, description: "synthetic Sysmon process (fixture)", groups: ["sysmon"] }, decoder: { name: "windows_eventchannel" }, location: "EventChannel", full_log: "",
    data: { win: { system: { eventID: "1", channel: "Microsoft-Windows-Sysmon/Operational" }, eventdata: { processGuid: "{7f3a21aa-0001-6700-0000-001000000200}", processId: "4242", utcTime: "2026-10-08 01:00:00.000", image: "C:\\Users\\Public\\upd.exe", commandLine: "upd.exe /s", user: "WKS\\fin.user" } } },
  }, { receivedAt: new Date("2026-10-08T02:00:00Z") });
  if (r.isFailure) throw new Error(r.error);
  return { id: `fixture-${n}`, ref: `E${n}`, type: "WAZUH_ALERT", origin: "SYSTEM", createdBy: "system", timestamp: new Date("2026-10-08T01:00:00Z"), title: "synthetic Sysmon process (fixture)", host: "WKS-FIN-07", structured: { agent: "WKS-FIN-07", ruleId: "92200", contractV2: r.value } };
}

const ATTACKER = "172.19.0.3";   // source address in the recorded 5712 alert
const ticket = (o: Partial<TicketRecord> = {}): TicketRecord => ({ actionCode: "ACT-AUTH-SOURCE-RESTRICT", target: ATTACKER, status: "COMPLETED", investigationNumber: 1, completedAt: new Date("2026-10-08T04:00:00Z"), executionNote: null, controlState: null, ...o });
const rehunt = (o: Partial<RehuntContextRow> = {}): RehuntContextRow => ({
  verificationId: "fixture-verification", verifiedInvestigationNumber: 1, source: "WAZUH_INDEXER", result: "RESOLVED", spreadDetected: false, matchingEvents: 0,
  originalHosts: ["attack-endpoint"], affectedHosts: [], newHosts: [], truncated: false, classification: "NO_MATCH_COVERED", coverageComplete: true, ...o,
});
const TASK = { type: "persistence_artifact", fields: { host_id: "WKS-FIN-07", artifact_type: "scheduled_task", artifact_locator: "\\Maintenance\\SyncReport" }, source_event_refs: ["E1"] };

const SCENARIOS: FixtureScenario[] = [
  { id: "ssh-restriction", title: "SSH brute force — จำกัดต้นทางที่จุดควบคุม", note: "Alert 5712 ที่บันทึกไว้ + จุดควบคุมตัวอย่าง (FW-EDGE-1 เป็นค่าจำลอง ไม่ใช่ firewall จริง)", rows: () => [wazuhRow("5712", 1)], org: "org-ssh.yaml" },
  { id: "missing-enforcement-point", title: "SSH brute force — องค์กรยังไม่ระบุจุดควบคุม", note: "Alert 5712 ที่บันทึกไว้ + org context จริงของ repo (ยังไม่กรอก)", rows: () => [wazuhRow("5712", 1)] },
  { id: "needs-authorization", title: "SSH brute force — ต้องขออนุมัติก่อน", note: "Alert 5712 ที่บันทึกไว้ + org ตัวอย่างที่ IR ยังไม่มีอำนาจดำเนินการ และไม่ได้ระบุผู้อนุมัติ", rows: () => [wazuhRow("5712", 1)], org: "org-ssh-no-authority.yaml" },
  {
    id: "task-hijack", title: "Scheduled Task Hijack — หลักฐานครบหลายเป้าหมาย", note: "Sysmon สังเคราะห์ + analyst assertion สังเคราะห์ (เครื่อง/ไฟล์/ปลายทางเป็นค่าจำลอง)",
    rows: () => [sysmonRow(1), assertion(2, {
      evidence: [
        { id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] },
        { id: "payload_linked_malicious_execution", status: "PRESENT", source_event_refs: ["E1"] },
        { id: "c2_web_channel_correlated", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] },
      ],
      targets: [
        TASK,
        { type: "destination_endpoint", fields: { destination: "update-cdn.example-bad.test/api/v2/poll", granularity: "URL path" }, source_event_refs: ["E1"] },
        { type: "network_flow", fields: { source_host_id: "WKS-FIN-07", destination: "203.0.113.45", destination_role: "remote_c2", protocol: "TCP", port: 443 }, source_event_refs: ["E1"] },
        { type: "file_object", fields: { host_id: "WKS-FIN-07", object_locator: "C:\\Users\\Public\\upd.exe" }, source_event_refs: ["E1"] },
      ],
    })],
  },
  { id: "rehunt-effective", title: "หลัง Re-hunt — มาตรการเดิมยังมีผล", note: "Ticket ตัวอย่างดำเนินการแล้ว + Re-hunt ตัวอย่างครอบคลุมครบ ไม่พบภัยซ้ำ", rows: () => [wazuhRow("5712", 1)], org: "org-ssh.yaml", tickets: [ticket()], rehunt: rehunt(), investigationNumber: 2 },
  { id: "rehunt-unverified", title: "หลัง Re-hunt — ยังยืนยันผลไม่ได้", note: "Ticket ตัวอย่างดำเนินการแล้ว + Re-hunt ตัวอย่างครอบคลุมไม่ครบ", rows: () => [wazuhRow("5712", 1)], org: "org-ssh.yaml", tickets: [ticket()], rehunt: rehunt({ coverageComplete: false }), investigationNumber: 2 },
  {
    id: "rehunt-not-applied", title: "หลัง Re-hunt — ภัยกลับมา และ IR บันทึกว่าใช้มาตรการไม่ครบ", note: "Ticket ตัวอย่าง (บันทึกว่าใช้ได้บางส่วน) + Re-hunt ตัวอย่างพบกิจกรรมกลับมา",
    rows: () => [wazuhRow("5712", 1)], org: "org-ssh.yaml", investigationNumber: 2,
    tickets: [ticket({ completedAt: new Date("2026-10-01T00:00:00Z"), controlState: "PARTIAL", executionNote: "ตั้ง rule ได้เฉพาะบางส่วน (บันทึกตัวอย่างใน fixture)" })],
    rehunt: rehunt({ result: "NOT_RESOLVED", matchingEvents: 4, affectedHosts: ["attack-endpoint"], classification: "IN_SCOPE_ACTIVITY", verifiedAt: new Date("2026-10-02T00:00:00Z") }),
  },
];

export function listPreviewFixtures(): { id: string; title: string; note: string }[] {
  return SCENARIOS.map(({ id, title, note }) => ({ id, title, note }));
}

export async function runPreviewFixture(id: string): Promise<SubtypePreview | null> {
  const s = SCENARIOS.find((x) => x.id === id);
  if (!s) return null;
  const rows = s.rows();
  const repo = { getSubtypeEvidence: async () => rows, getTicketHistory: async () => s.tickets ?? [], getRehuntContext: async () => s.rehunt ?? null } as unknown as IRecommendationContextRepository;
  const loader = new SubtypeKnowledgeLoader(undefined, s.org ? path.join(ORG, s.org) : undefined);
  const service = new SubtypeRecommendationService(loader, repo, { resolve: () => ({ criticality: s.criticality ?? "MEDIUM" }) }, () => "shadow");
  const investigationNumber = s.investigationNumber ?? 1;
  const ev = await service.evaluate({ incidentId: `fixture:${s.id}`, tenantId: "fixture", investigationNumber, rehunt: s.rehunt ?? null });
  const preview = presentEvaluation(ev, "FIXTURE_PREVIEW", investigationNumber);
  return {
    ...preview, fixture: { id: s.id, title: s.title, note: s.note },
    basis: { ticketCount: s.tickets?.length ?? 0, rehunt: s.rehunt ? { round: s.rehunt.verifiedInvestigationNumber, result: s.rehunt.result === "RESOLVED" ? "ไม่พบภัยซ้ำ" : "ยังพบกิจกรรม", verifiedAt: s.rehunt.verifiedAt?.toISOString() ?? null } : null, organizationContextComplete: ev.kb.organization.status === "COMPLETE" },
  };
}
