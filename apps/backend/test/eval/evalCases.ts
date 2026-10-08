import * as fs from "node:fs";
import * as path from "node:path";
import { RehuntContextRow } from "../../src/application/recommendation/ports/IRecommendationContextRepository";
import { TicketRecord } from "../../src/domain/subtype/actionState";
import { SubtypeEvidenceRow } from "../../src/application/subtype/factBuilder";
import { ORG_SSH } from "../helpers/subtypeFlowHarness";
import { EARLIER, acctRows, hijackBasic, hijackFull, recurred, rehunt, sysmon, ticket } from "../helpers/formatScenarios";
import { analystRow, realAlert, wazuhRow } from "../helpers/subtypeFixtures";

/**
 * INPUT side of the evaluation kit: how each Ground-Truth case is fed to the runtime. Recorded Wazuh alerts come from test/fixtures/wazuh-real
 * (real alert JSON); isolated fixtures are synthetic Sysmon rows + analyst assertions; Re-hunt rounds add SIMULATED ticket / re-hunt records.
 * Nothing here writes to a database or calls a service: the kit runs GenerateRecommendationUseCase over in-memory repositories.
 * Organization contexts are FIXTURES (the repository's real context is all UNKNOWN - that case is GT-R1-02).
 */
export type DataClass = "RECORDED_ALERT" | "RECORDED_ALERT+ANALYST_ASSERTION" | "SYNTHETIC_FIXTURE" | "RECORDED_ALERT+SIMULATED_ROUND2_RECORDS";
export interface EvalInput {
  caseId: string; dataClass: DataClass; rows: () => SubtypeEvidenceRow[]; orgYaml: string; criticality?: string;
  tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null; investigationNumber?: number;
  /** the legacy stand-in agent is driven by a hand-fixed SSH context; only SSH single-source cases are comparable */
  legacy: boolean;
}
const TOOLS = `${ORG_SSH}capability:\n  cap.scoped_network_enforcement: true\n  cap.connection_state_termination: true\n`;
const CONN_ONLY = "capability:\n  cap.connection_state_termination: true\n";
const second = (): SubtypeEvidenceRow => {
  const dir = path.join(__dirname, "../fixtures/wazuh-real");
  const payload = JSON.parse(fs.readFileSync(path.join(dir, fs.readdirSync(dir).find((f) => f.startsWith("5712-"))!), "utf8"));
  payload.id = "1759900001.999"; payload.data = { ...payload.data, srcip: "172.19.0.9" };
  return wazuhRow(payload);
};
const pidOnly = () => analystRow({ evidence: [{ id: "proc_app_to_interpreter_chain", status: "PRESENT", authorization_status: "UNAUTHORIZED", lineage: ["E1"], source_event_refs: ["E1"] }] } as never);
const authorizedTask = () => analystRow({ evidence: [{ id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "AUTHORIZED", source_event_refs: ["E1"] }], targets: [{ type: "persistence_artifact", fields: { host_id: "WKS-FIN-07", artifact_type: "scheduled_task", artifact_locator: "\\Maintenance\\SyncReport" }, source_event_refs: ["E1"] }] } as never);
const r2 = (id: string, o: Partial<EvalInput>): EvalInput => ({ caseId: id, dataClass: "RECORDED_ALERT+SIMULATED_ROUND2_RECORDS", rows: () => [realAlert("5712")], orgYaml: ORG_SSH, investigationNumber: 2, legacy: true, ...o });
const V = (s: string) => new Date(s);

export const EVAL_INPUTS: EvalInput[] = [
  { caseId: "GT-R1-01", dataClass: "RECORDED_ALERT", rows: () => [realAlert("5712")], orgYaml: ORG_SSH, legacy: true },
  { caseId: "GT-R1-02", dataClass: "RECORDED_ALERT", rows: () => [realAlert("5712")], orgYaml: "", legacy: true },
  { caseId: "GT-R1-03", dataClass: "RECORDED_ALERT", rows: () => [realAlert("5712")], orgYaml: TOOLS, legacy: true },
  { caseId: "GT-R1-04", dataClass: "SYNTHETIC_FIXTURE", rows: () => [realAlert("5712"), second()], orgYaml: ORG_SSH, legacy: false },
  { caseId: "GT-R1-05", dataClass: "RECORDED_ALERT", rows: () => [realAlert("40112")], orgYaml: ORG_SSH, legacy: false },
  { caseId: "GT-R1-06", dataClass: "RECORDED_ALERT", rows: () => [realAlert("5503")], orgYaml: ORG_SSH, legacy: false },
  { caseId: "GT-R1-07", dataClass: "RECORDED_ALERT", rows: () => [realAlert("100320")], orgYaml: "", legacy: false },
  { caseId: "GT-R1-08", dataClass: "RECORDED_ALERT", rows: () => [realAlert("31103")], orgYaml: "", legacy: false },
  { caseId: "GT-R1-09", dataClass: "RECORDED_ALERT", rows: () => [realAlert("92027")], orgYaml: "", legacy: false },
  { caseId: "GT-R1-10", dataClass: "RECORDED_ALERT", rows: () => [realAlert("100330")], orgYaml: "", legacy: false },
  { caseId: "GT-R1-11", dataClass: "RECORDED_ALERT+ANALYST_ASSERTION", rows: () => [realAlert("100330"), pidOnly()], orgYaml: "", legacy: false },
  { caseId: "GT-R1-12", dataClass: "SYNTHETIC_FIXTURE", rows: () => [sysmon(), hijackBasic()], orgYaml: "", legacy: false },
  { caseId: "GT-R1-13", dataClass: "SYNTHETIC_FIXTURE", rows: () => [sysmon(), hijackFull()], orgYaml: CONN_ONLY, legacy: false },
  { caseId: "GT-R1-14", dataClass: "SYNTHETIC_FIXTURE", rows: () => [sysmon(), hijackFull()], orgYaml: "", legacy: false },
  { caseId: "GT-R1-15", dataClass: "SYNTHETIC_FIXTURE", rows: () => [sysmon(), authorizedTask()], orgYaml: "", legacy: false },
  { caseId: "GT-R1-16", dataClass: "SYNTHETIC_FIXTURE", rows: () => [sysmon(), hijackBasic(), realAlert("5712")], orgYaml: ORG_SSH, legacy: false },
  { caseId: "GT-R1-17", dataClass: "RECORDED_ALERT+ANALYST_ASSERTION", rows: () => acctRows(), orgYaml: "", criticality: "CRITICAL", legacy: false },
  { caseId: "GT-R1-18", dataClass: "RECORDED_ALERT", rows: () => [realAlert("5712")], orgYaml: `${TOOLS}authority:\n  ir_execute: false\n`, legacy: false },
  { caseId: "GT-R1-19", dataClass: "RECORDED_ALERT", rows: () => [realAlert("5712")], orgYaml: `${ORG_SSH}capability:\n  cap.scoped_network_enforcement: false\n`, legacy: false },

  r2("GT-R2-01", { tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ verifiedAt: V("2026-10-04T00:00:00Z") }) }),
  r2("GT-R2-02", { tickets: [ticket()], rehunt: null }),
  r2("GT-R2-03", { tickets: [ticket({ completedAt: V("2026-10-08T04:00:00Z") })], rehunt: rehunt({ verifiedAt: V("2026-10-05T00:00:00Z") }) }),
  r2("GT-R2-04", { tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ coverageComplete: false, verifiedAt: V("2026-10-04T00:00:00Z") }) }),
  r2("GT-R2-05", { tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ verifiedAt: V("2026-10-02T00:00:00Z") }) }),
  r2("GT-R2-06", { tickets: [ticket({ completedAt: V("2026-10-08T04:00:00Z") })], rehunt: recurred({ verifiedAt: V("2026-10-09T00:00:00Z") }) }),
  r2("GT-R2-07", { tickets: [ticket({ completedAt: EARLIER })], rehunt: recurred() }),
  r2("GT-R2-08", { tickets: [ticket({ completedAt: EARLIER, executionNote: "IR ตั้ง deny ตามขั้นตอน (บันทึกตัวอย่างใน fixture)" })], rehunt: recurred() }),
  r2("GT-R2-09", { tickets: [ticket({ completedAt: EARLIER, controlState: "PARTIAL", executionNote: "ตั้ง rule ได้เฉพาะบางส่วน (fixture)" })], rehunt: recurred() }),
  r2("GT-R2-10", { tickets: [ticket({ status: "FAILED", executionNote: "firewall rule rejected (fixture)" })], rehunt: null }),
  r2("GT-R2-11", { tickets: [ticket({ status: "PENDING_IR_DECISION" })], rehunt: null }),
  r2("GT-R2-12", { rows: () => [realAlert("5712"), second()], tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ verifiedAt: V("2026-10-06T00:00:00Z") }), legacy: false }),
  r2("GT-R2-13", { tickets: [ticket({ completedAt: EARLIER })], rehunt: rehunt({ result: "NOT_RESOLVED", matchingEvents: 3, affectedHosts: ["other-host"], newHosts: ["other-host"], classification: "NEW_SCOPE_ACTIVITY", verifiedAt: V("2026-10-04T00:00:00Z") }) }),
];
