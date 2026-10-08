import fs from "node:fs";
import path from "node:path";
import { extractWazuhEvidenceV2 } from "../../src/domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import { SubtypeEvidenceRow, AssertionShape } from "../../src/application/subtype/factBuilder";
import { SubtypeKnowledgeLoader } from "../../src/infrastructure/knowledge/SubtypeKnowledgeLoader";
import { SubtypeMode, SubtypeRecommendationService } from "../../src/application/subtype/SubtypeRecommendationService";
import { IRecommendationContextRepository, RehuntContextRow } from "../../src/application/recommendation/ports/IRecommendationContextRepository";
import { TicketRecord } from "../../src/domain/subtype/actionState";

/**
 * Fixtures for the subtype pipeline tests.
 *  - realAlert(): a RECORDED Wazuh alert (test/fixtures/wazuh-real, captured read-only from the lab Indexer) run through the REAL
 *    Evidence Contract v2 extractor -> a SYSTEM evidence row. (recorded-alert replay)
 *  - syntheticAlert(): a hand-written Wazuh payload through the same extractor. (synthetic fixture)
 *  - analystRow(): a MANUAL ANALYST_ASSERTION row (the only way classification evidence the Wazuh contract cannot carry enters).
 * Nothing here touches a database.
 */
const REAL = path.join(__dirname, "..", "fixtures", "wazuh-real");
export const loader = new SubtypeKnowledgeLoader();
export const kb = () => loader.load();

let seq = 0;
export function wazuhRow(payload: Record<string, any>, over: Partial<SubtypeEvidenceRow> = {}): SubtypeEvidenceRow {
  const r: any = extractWazuhEvidenceV2(payload, { receivedAt: new Date("2026-10-08T02:00:00Z") });
  if (r.isFailure) throw new Error(r.error);
  const n = ++seq;
  const agent = payload.agent?.name ?? null;
  return { id: `row-${n}`, ref: `E${n}`, type: "WAZUH_ALERT", origin: "SYSTEM", createdBy: "system", timestamp: new Date(payload.timestamp ?? "2026-10-08T01:00:00Z"), title: payload.rule?.description ?? "alert", host: agent, structured: { agent, ruleId: String(payload.rule?.id ?? ""), contractV2: r.value }, ...over };
}
export const realAlert = (prefix: string, over: Partial<SubtypeEvidenceRow> = {}) => {
  const f = fs.readdirSync(REAL).find((x) => x.startsWith(prefix + "-"))!;
  return wazuhRow(JSON.parse(fs.readFileSync(path.join(REAL, f), "utf8")), over);
};
export function resetRefs() { seq = 0; }

/** Synthetic Sysmon-style process/network alert (the fields the v2 extractor reads). */
export function syntheticAlert(o: { agent?: string; ip?: string; ruleId?: string; groups?: string[]; ts?: string; eventdata?: Record<string, string>; data?: Record<string, unknown> }): SubtypeEvidenceRow {
  return wazuhRow({
    id: `1759900000.${100000 + ++seq}`, timestamp: o.ts ?? "2026-10-08T01:00:00.000+0000", agent: { id: "011", name: o.agent ?? "WKS-FIN-07", ip: o.ip ?? "10.20.0.7" },
    manager: { name: "wazuh.manager" }, rule: { id: o.ruleId ?? "92200", level: 12, description: "synthetic", groups: o.groups ?? ["sysmon"] },
    decoder: { name: "windows_eventchannel" }, location: "EventChannel", data: { ...(o.data ?? {}), win: { system: { eventID: "1", channel: "Microsoft-Windows-Sysmon/Operational" }, eventdata: o.eventdata ?? {} } }, full_log: "",
  });
}

export function analystRow(facts: AssertionShape, by = "soc.analyst@example.test", title = "SOC analyst assertion"): SubtypeEvidenceRow {
  const n = ++seq;
  return { id: `row-${n}`, ref: `E${n}`, type: "ANALYST_ASSERTION", origin: "MANUAL", createdBy: by, timestamp: new Date("2026-10-08T03:00:00Z"), title, host: null, structured: { subtypeFacts: facts } };
}

export function fakeContextRepo(rows: SubtypeEvidenceRow[], tickets: TicketRecord[] = [], rehunt: RehuntContextRow | null = null): IRecommendationContextRepository {
  return { getSubtypeEvidence: async () => rows, getTicketHistory: async () => tickets, getRehuntContext: async () => rehunt } as unknown as IRecommendationContextRepository;
}

export function service(rows: SubtypeEvidenceRow[], o: { tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null; mode?: SubtypeMode; criticality?: string; loader?: SubtypeKnowledgeLoader; strict?: boolean } = {}) {
  return new SubtypeRecommendationService(o.loader ?? loader, fakeContextRepo(rows, o.tickets, o.rehunt ?? null), { resolve: () => ({ criticality: o.criticality ?? "MEDIUM" }) }, () => o.mode ?? "shadow", o.strict ?? false);
}
export const evaluate = (rows: SubtypeEvidenceRow[], o: Parameters<typeof service>[1] & { investigationNumber?: number } = {}) =>
  service(rows, o).evaluate({ incidentId: "inc-1", tenantId: "t-1", investigationNumber: o.investigationNumber ?? 1, rehunt: o.rehunt ?? null });
