import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { SubtypeKnowledgeLoader } from "../src/infrastructure/knowledge/SubtypeKnowledgeLoader";
import { analystRow, evaluate, kb, realAlert, resetRefs, syntheticAlert, wazuhRow } from "./helpers/subtypeFixtures";

/**
 * INTEGRATION (no DB, no LLM): recorded + synthetic Wazuh alerts -> Evidence Contract v2 extractor -> facts -> validated targets ->
 * subtype/scenario -> policy -> ordering -> deterministic composition -> output validation, all through SubtypeRecommendationService
 * (the same service GenerateRecommendationUseCase calls).
 */
const orgFile = (yaml: string) => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "org-")), "org.yaml");
  fs.writeFileSync(f, yaml);
  return f;
};
const ORG_SSH = `
enforcement_points:
  - {host: attack-endpoint, service: "SSH (22/TCP)", enforcement_point: "perimeter firewall FW-EDGE-1"}
`;
const orderedActions = (e: Awaited<ReturnType<typeof evaluate>>) => e.plan!.ordered.map((n) => n.action_id);
const decisionOf = (e: Awaited<ReturnType<typeof evaluate>>, action: string) => e.plan!.instances.find((i) => i.action_id === action)?.decision;

beforeEach(() => resetRefs());

describe("recorded-alert replay: sshd brute force (Wazuh rule 5712, real alert)", () => {
  it("classifies BF-GUESS from the v2 contract; the attacker source comes from authentication.remote, never from agent.ip", async () => {
    const e = await evaluate([realAlert("5712")]);
    expect(e.kb.status).toBe("VALID");
    expect(e.plan!.active).toEqual(["BF-GUESS"]);
    const src = e.facts!.targets.find((t) => t.type === "network_source")!;
    expect(src.fields.address).toBe("172.19.0.3");
    expect(src.fields.address).not.toBe("172.19.0.8"); // agent.ip
    expect(src.validated).toBe(true);
    expect(src.evidenceRefs).toEqual(["E1"]);
  });

  it("without an enforcement point in the organization context the action is NEEDS_TARGET (nothing is guessed) and the output asks for it", async () => {
    const e = await evaluate([realAlert("5712")]);
    expect(decisionOf(e, "ACT-AUTH-SOURCE-RESTRICT")?.decision).toBe("NEEDS_TARGET");
    expect(orderedActions(e)).toEqual(["ACT-INVESTIGATE-MISSING-EVIDENCE"].filter(() => false));
    expect(e.composition!.steps.every((s) => s.stepType !== "ACTION")).toBe(true);
    expect(e.composition!.userText).toContain("บริการปลายทางและจุดควบคุมการเข้าถึง");
  });

  it("with the organization's enforcement point the action is ELIGIBLE with TOOL_MAPPING_REQUIRED, and no account action is opened from failed logins", async () => {
    const loader = new SubtypeKnowledgeLoader(undefined, orgFile(ORG_SSH));
    const e = await evaluate([realAlert("5712")], { loader });
    expect(orderedActions(e)).toEqual(["ACT-AUTH-SOURCE-RESTRICT"]);
    expect(decisionOf(e, "ACT-AUTH-SOURCE-RESTRICT")!.flags).toContain("TOOL_MAPPING_REQUIRED");
    expect(e.plan!.instances.some((i) => ["ACT-IDENTITY-CREDENTIAL-CONTAIN", "ACT-SESSION-REVOKE"].includes(i.action_id))).toBe(false);
    expect(e.violations).toEqual([]);
    expect(e.composition!.userText).toMatch(/^\*\*คำแนะนำเพื่อยับยั้ง Incident\*\*/);
    expect(e.composition!.userText).toContain("172.19.0.3");
    expect(e.composition!.userText).not.toMatch(/172\.19\.0\.8/);
  });
});

describe("PID-only process (recorded harness alert 100330) never opens termination", () => {
  it("a process known only by PID is not an identity: NEEDS_TARGET and no terminate step", async () => {
    const e = await evaluate([realAlert("100330"), analystRow({ evidence: [{ id: "proc_app_to_interpreter_chain", status: "PRESENT", authorization_status: "UNAUTHORIZED", lineage: ["E1"], source_event_refs: ["E1"] }] })]);
    const proc = e.facts!.targets.find((t) => t.type === "process");
    expect(proc?.validated).toBe(false);
    expect(proc?.findings.join(" ")).toMatch(/PID/);
    expect(e.plan!.active).toContain("PROC-CHAIN");
    expect(decisionOf(e, "ACT-EXECUTION-CHAIN-CONTAIN")?.decision).toBe("NEEDS_TARGET");
    expect(e.composition!.userText).not.toMatch(/ยุติ/);
  });
});

describe("outbound alone is not C2", () => {
  it("a recorded outbound flow (100320) without analyst-confirmed C2 evidence opens no network containment", async () => {
    const e = await evaluate([realAlert("100320")]);
    expect(e.plan!.active).toEqual([]);
    expect(orderedActions(e)).toEqual([]);
    expect(e.plan!.investigationFallback).toBe(true);
    expect(e.composition!.userText).toContain("ยังไม่พบหลักฐานที่ยืนยันประเภทภัย");
  });
});

describe("indicator-only alerts (recorded)", () => {
  it("web SQLi keyword alert (31103) classifies no SQLi subtype and proposes no WAF/DB action", async () => {
    const e = await evaluate([realAlert("31103")]);
    expect(e.plan!.active).toEqual([]);
    expect(e.plan!.instances.some((i) => i.action_id === "ACT-WEB-REQUEST-RESTRICT")).toBe(false);
  });
  it("encoded PowerShell on a recorded Sysmon process (92027) is an indicator only", async () => {
    const e = await evaluate([realAlert("92027")]);
    expect(e.plan!.active).toEqual([]);
    expect(e.facts!.targets.find((t) => t.type === "process")?.validated).toBe(true); // GUID + start time + image => identity-grade
    expect(orderedActions(e)).toEqual([]);
  });
});

describe("Scheduled Task Hijack (synthetic Sysmon + analyst assertions)", () => {
  const sysmonProc = () => syntheticAlert({ ruleId: "92200", eventdata: { processGuid: "{7f3a21aa-0001-6700-0000-001000000200}", processId: "4242", utcTime: "2026-10-08 01:00:00.000", image: "C:\\Users\\Public\\upd.exe", commandLine: "upd.exe /s", user: "WKS\\svc_sync", hashes: "SHA256=" + "a".repeat(64) } });
  const hijackFacts = (extra: Record<string, unknown> = {}) => analystRow({
    evidence: [
      { id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] },
      { id: "payload_linked_malicious_execution", status: "PRESENT", source_event_refs: ["E1"] },
    ],
    targets: [
      { type: "persistence_artifact", fields: { host_id: "WKS-FIN-07", artifact_type: "scheduled_task", artifact_locator: "\\Maintenance\\SyncReport" }, source_event_refs: ["E1"] },
    ],
    ...extra,
  } as never);

  it("PS-PERSIST: trigger disabled, running instance stopped, payload terminated by identity; no network deny and no quarantine without their evidence", async () => {
    const e = await evaluate([sysmonProc(), hijackFacts()]);
    expect(e.plan!.active).toContain("PS-PERSIST");
    expect(orderedActions(e)).toEqual(["ACT-PERSISTENCE-TRIGGER-DISABLE"]);
    const text = e.composition!.userText;
    expect(text).toContain("Disable");
    expect(text).toContain("หยุด instance ของ");                // a separate step: Disable Task does not stop a running instance
    expect(text).toContain("ตัวระบุ Process: GUID {7f3a21aa-0001-6700-0000-001000000200}");
    expect(text).not.toContain("process_guid");
    expect(text).not.toMatch(/Quarantine/);                      // no file identity yet -> no quarantine
    expect(text).not.toMatch(/ตัดการติดต่อ|deny/);               // outbound/C2 not evidenced -> no network containment
    expect(decisionOf(e, "ACT-QUARANTINE-FILE-OBJECT")?.decision).toBe("NEEDS_TARGET");
  });

  it("with C2 evidence + file identity: trigger -> instance -> payload -> channel (+ established connections) -> quarantine, each once", async () => {
    const rows = [sysmonProc(), hijackFacts({
      evidence: [
        { id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] },
        { id: "payload_linked_malicious_execution", status: "PRESENT", source_event_refs: ["E1"] },
        { id: "c2_web_channel_correlated", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] },
      ],
      targets: [
        { type: "persistence_artifact", fields: { host_id: "WKS-FIN-07", artifact_type: "scheduled_task", artifact_locator: "\\Maintenance\\SyncReport" }, source_event_refs: ["E1"] },
        { type: "destination_endpoint", fields: { destination: "update-cdn.example-bad.test/api/v2/poll", granularity: "URL path" }, source_event_refs: ["E1"] },
        { type: "network_flow", fields: { source_host_id: "WKS-FIN-07", destination: "203.0.113.45", destination_role: "remote_c2", protocol: "TCP", port: 443 }, source_event_refs: ["E1"] },
        { type: "file_object", fields: { host_id: "WKS-FIN-07", object_locator: "C:\\Users\\Public\\upd.exe" }, source_event_refs: ["E1"] },
      ],
    })];
    const e = await evaluate(rows, { loader: new SubtypeKnowledgeLoader(undefined, orgFile("capability:\n  cap.connection_state_termination: true\n")) });
    expect(orderedActions(e)).toEqual(["ACT-PERSISTENCE-TRIGGER-DISABLE", "ACT-WEB-C2-CONTAIN", "ACT-QUARANTINE-FILE-OBJECT"]);
    const t = e.composition!.userText;
    const idx = (s: string) => t.indexOf(s);
    expect(idx("Disable")).toBeLessThan(idx("หยุด instance ของ"));
    expect(idx("หยุด instance ของ")).toBeLessThan(idx("ยุติ payload process"));
    expect(idx("ยุติ payload process")).toBeLessThan(idx("ตัดการติดต่อไปยัง"));
    expect(idx("ตัดการติดต่อไปยัง")).toBeLessThan(idx("ตัด connection ที่ established"));
    expect(idx("ตัด connection ที่ established")).toBeLessThan(idx("Quarantine"));
    expect((t.match(/ยุติ (?:payload |initiator )?process/g) ?? []).length).toBe(1); // the C2 runbook's terminate of the SAME process is deduplicated
    expect(e.violations).toEqual([]);
  });

  it("approved task change (AUTHORIZED) opens no malicious containment", async () => {
    const e = await evaluate([sysmonProc(), analystRow({
      evidence: [{ id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "AUTHORIZED", source_event_refs: ["E1"] }],
      targets: [{ type: "persistence_artifact", fields: { host_id: "WKS-FIN-07", artifact_type: "scheduled_task", artifact_locator: "\\Maintenance\\SyncReport" }, source_event_refs: ["E1"] }],
    })]);
    expect(decisionOf(e, "ACT-PERSISTENCE-TRIGGER-DISABLE")?.decision).toBe("PROHIBITED");
    expect(orderedActions(e)).toEqual([]);
    expect(e.composition!.userText).toContain("ได้รับอนุมัติ");
  });

  it("an approved-automation image is flagged and prohibited, not silently dropped", async () => {
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "org-")), "org.yaml");
    fs.writeFileSync(f, ["approved_automation:", "  - {match: 'C:\\Users\\Public\\upd.exe', note: \"approved updater\"}", ""].join("\n"));
    const e = await evaluate([sysmonProc(), hijackFacts()], { loader: new SubtypeKnowledgeLoader(undefined, f) });
    expect(e.facts!.targets.find((t) => t.type === "process")?.scopeFlags).toContain("is_approved_automation");
    expect(decisionOf(e, "ACT-PERSISTENCE-TRIGGER-DISABLE")?.decision).toBe("PROHIBITED");
  });
});

describe("analyst assertions are the only route for judgement-type evidence", () => {
  it("an assertion row without an authenticated author is ignored (system-authored cannot assert)", async () => {
    const e = await evaluate([syntheticAlert({}), analystRow({ evidence: [{ id: "ps_persistence_relaunch", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E1"] }] }, "system")]);
    expect(e.facts!.evidence.has("ps_persistence_relaunch")).toBe(false);
    expect((e.audit.ignoredInputs as string[]).join(" ")).toMatch(/without an authenticated author/);
  });
  it("PRESENT without any reference is downgraded to UNKNOWN; evidence needing lineage stays UNKNOWN without it", async () => {
    const e = await evaluate([analystRow({ evidence: [{ id: "ps_download_execute_chain", status: "PRESENT", authorization_status: "UNAUTHORIZED" }] })]);
    expect(e.facts!.evidence.get("ps_download_execute_chain")?.status).not.toBe("PRESENT");
    const e2 = await evaluate([analystRow({ evidence: [{ id: "ps_download_execute_chain", status: "PRESENT", authorization_status: "UNAUTHORIZED", source_event_refs: ["E9"] }] })]);
    expect(e2.facts!.evidence.get("ps_download_execute_chain")?.status).toBe("UNKNOWN");
  });
  it("unknown evidence ids and unknown scope flags are ignored and audited, never trusted", async () => {
    const e = await evaluate([analystRow({ evidence: [{ id: "totally_made_up", status: "PRESENT", source_event_refs: ["E1"] }], scope: ["nonsense_flag"] })]);
    expect(e.facts!.evidence.has("totally_made_up")).toBe(false);
    expect((e.audit.ignoredInputs as string[]).length).toBeGreaterThanOrEqual(2);
  });
  it("absence of data is UNKNOWN, never ABSENT or false-as-pass", async () => {
    const e = await evaluate([]);
    expect(e.facts!.evidence.size).toBe(0);
    expect(e.plan!.active).toEqual([]);
    expect(e.composition!.steps.every((s) => s.stepType === "CHECK")).toBe(true);
    expect(e.composition!.userText).toContain("**ข้อมูลที่ต้องตรวจเพิ่ม**");
  });
});

describe("knowledge is fail-closed", () => {
  it("invalid knowledge opens no action and says why (shadow fallback)", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kb-"));
    fs.cpSync(path.resolve(__dirname, "../../knowledge/subtype-playbooks"), dir, { recursive: true });
    const f = path.join(dir, "families/MALWARE.yaml");
    fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace("{action_id: ACT-ACTIVE-DAMAGE-CONTAIN, condition: POLICY_ELIGIBLE, depends_on: [],", "{action_id: ACT-ACTIVE-DAMAGE-CONTAIN, condition: POLICY_ELIGIBLE, depends_on: [ACT-QUARANTINE-FILE-OBJECT],"));
    const e = await evaluate([realAlert("5712")], { loader: new SubtypeKnowledgeLoader(dir), mode: "enforce" });
    expect(e.kb.status).toBe("INVALID");
    expect(e.plan).toBeNull();
    expect(e.effectiveMode).toBe("shadow");
    expect(e.fallbackReason).toMatch(/INVALID/);
  });
  it("enforce is requested but unreviewed knowledge is not deployable: falls back to shadow with the reason", async () => {
    const e = await evaluate([realAlert("5712")], { mode: "enforce" });
    expect(e.requestedMode).toBe("enforce");
    expect(e.effectiveMode).toBe("shadow");
    expect(e.fallbackReason).toMatch(/await IR review/);
    process.env.SUBTYPE_ALLOW_UNREVIEWED = "true";
    try { expect((await evaluate([realAlert("5712")], { mode: "enforce" })).effectiveMode).toBe("enforce"); } finally { delete process.env.SUBTYPE_ALLOW_UNREVIEWED; }
  });
});

it("knowledge version is stamped in the audit", async () => {
  const e = await evaluate([wazuhRow({ id: "1.1", timestamp: "2026-10-08T01:00:00.000+0000", agent: { id: "1", name: "h" }, rule: { id: "1", level: 3, description: "x" } })]);
  expect((e.audit.knowledge as { version: string }).version).toBe(kb().version);
});
