import { presentRecommendation } from "../src/presentation/http/controllers/RecommendationController";
import { RAW_KEY_RE } from "../src/domain/subtype/wording";
import { SCENARIOS } from "./helpers/formatScenarios";

/**
 * INTEGRATION (no DB, no LLM): the user-facing format of the 8 reviewed backend outputs (+ the approval cases). Every scenario runs the real
 * service (recorded Wazuh alerts 5712 / 100320 through the Evidence Contract v2 extractor; the Scheduled Task Hijack rows are synthetic Sysmon +
 * analyst assertions; organization contexts are FIXTURES, not the real organization). A pass here is NOT an actual-LLM or live-alert pass.
 */
type Ev = Awaited<ReturnType<(typeof SCENARIOS)[number]["run"]>>;
const cache = new Map<string, Ev>();
const get = async (id: string): Promise<Ev> => {
  if (!cache.has(id)) cache.set(id, await SCENARIOS.find((s) => s.id === id)!.run());
  return cache.get(id)!;
};
const text = async (id: string) => (await get(id)).composition!.userText;
const lines = (t: string) => t.split("\n");
const numbered = (t: string) => lines(t).filter((l) => /^\d+\. \*\*/.test(l));
const sectionBullets = (t: string, heading: string) => {
  const ls = lines(t); const i = ls.indexOf(`**${heading}**`);
  if (i < 0) return null;
  const out: string[] = []; for (let k = i + 1; k < ls.length && ls[k].startsWith("- "); k++) out.push(ls[k]);
  return out;
};

describe("every scenario: shared format rules", () => {
  it.each(SCENARIOS.map((s) => s.id))("%s", async (id) => {
    const e = await get(id); const t = e.composition!.userText;
    expect(e.violations).toEqual([]);                                                       // the output validator passes
    expect(t.startsWith("**คำแนะนำเพื่อยับยั้ง Incident**\n")).toBe(true);
    expect(t).not.toMatch(RAW_KEY_RE);                                                     // no raw field/enum key
    expect(t).not.toMatch(/^[ \t]*-[ \t]*$/m);                                             // no bare "-"
    expect(t).not.toMatch(/ดำเนินการตาม\s*RB-|\b(?:ACT|RB|PBK|POL)-[A-Z]|confidence|[{]"/);
    expect((t.match(/\*\*ข้อมูลที่ต้องตรวจเพิ่ม\*\*/g) ?? []).length).toBeLessThanOrEqual(1);   // one missing-information section, never repeated
    if (t.includes("**ข้อมูลที่ต้องตรวจเพิ่ม**")) expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.length).toBeGreaterThan(0);
    expect(t).not.toContain("ข้อมูลที่ต้องตรวจเพิ่ม:");                                      // the old inline form is gone
    // scope, pre-checks and rollback are never squeezed into one paragraph
    for (const l of lines(t)) expect(/ก่อนลงมือ/.test(l) && /ย้อนกลับ/.test(l)).toBe(false);
    // ready steps and approval-needed actions are never mixed: an approval line is not a numbered step
    expect(numbered(t).some((l) => l.includes("ขออนุมัติ"))).toBe(false);
  });
});

describe("1) SSH restriction (organization names an enforcement point, tools not named)", () => {
  it("one ready step with each part on its own line, in a fixed order", async () => {
    const t = await text("ssh-restriction");
    expect(numbered(t)).toHaveLength(1);
    const ls = lines(t); const at = (p: string) => ls.findIndex((l) => l.includes(p));
    const order = ["วิธีลงมือ:", "ก่อนลงมือ:", "*ผลกระทบ:", "*ตรวจผล:", "ย้อนกลับ:"].map(at);
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(ls[at("ก่อนลงมือ:") + 1]).toMatch(/^   - /);                                    // pre-checks are a bullet list
    expect(t).toContain("เฉพาะ 172.19.0.3 → SSH (22/TCP) บน attack-endpoint");              // scope kept, not dropped to shorten the text
    expect(t).toContain("ไม่ใช่ global block");
  });
  it("accuracy: no guarantee that other users are unaffected; no 'snapshot stored' claim", async () => {
    const t = await text("ssh-restriction");
    expect(t).toContain("NAT ร่วม");
    expect(t).not.toMatch(/ผู้ใช้อื่นไม่ถูกตัด|มี snapshot สำหรับ|snapshot เก็บใน/);
    expect(t).toContain("บันทึกค่า rule/limit ปัจจุบัน");                                    // an instruction to record, not a claim it exists
  });
  it("the connection cut is NOT a ready step while the tool is unconfirmed; it is listed as information needed", async () => {
    const e = await get("ssh-restriction"); const t = e.composition!.userText;
    expect(numbered(t)).toHaveLength(1);
    expect(t).not.toMatch(/หาก control รองรับ/);
    const missing = sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.join(" ");
    expect(missing).toContain("ตัด session/connection");
    expect(missing).toContain("ยังไม่ได้ระบุว่ารองรับ");
    expect(t).toContain("**หมายเหตุเรื่องเครื่องมือ**");
  });
  it("with the tool confirmed the cut is a complete instruction: flow, service, tool-side identifier, flow-specific verification", async () => {
    const t = await text("ssh-tools-confirmed");
    expect(numbered(t)).toHaveLength(2);
    const step = t.slice(t.indexOf("2. **"));
    expect(step).toContain("172.19.0.3");
    expect(step).toContain("attack-endpoint");
    expect(step).toContain("SSH (22/TCP)");
    expect(step).toContain("ตัวระบุ session/connection ตามที่เครื่องมือแสดง");
    expect(step).toContain("วิธีลงมือ:");
    expect(step).toMatch(/\*ตรวจผล: connection table ไม่แสดง flow จาก 172\.19\.0\.3/);
    expect(step).not.toMatch(/หาก control รองรับ/);
  });
});

describe("2) missing enforcement point", () => {
  it("says the organization's access-control point is missing - not that the evidence is insufficient", async () => {
    const e = await get("missing-enforcement-point"); const t = e.composition!.userText;
    expect(numbered(t)).toHaveLength(0);
    expect(t).toContain("ขาดข้อมูลเป้าหมาย จุดควบคุม หรือเครื่องมือขององค์กร");
    expect(t).toContain("หลักฐานที่มีผ่านเงื่อนไขของมาตรการแล้ว");
    expect(t).not.toMatch(/หลักฐานยังไม่พอ/);
    expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")).toEqual(["- บริการปลายทางและจุดควบคุมการเข้าถึง: ต้องระบุ เครื่องที่เกี่ยวข้อง, บริการ, จุดควบคุมการเข้าถึง"]);
    expect(e.composition!.steps.every((s) => s.stepType !== "ACTION")).toBe(true);
  });
  it("outbound alone: no containment and no C2 claim; the explanation is about the missing classification", async () => {
    const t = await text("outbound-only");
    expect(numbered(t)).toHaveLength(0);
    expect(t).toContain("ยังไม่พบหลักฐานที่ยืนยันประเภทภัย");
    expect(t).not.toMatch(/C2 ที่ยืนยัน|ยืนยันว่าเป็น C2/);
  });
});

describe("3) Scheduled Task Hijack", () => {
  it("basic evidence: Disable != stopped instance; PID-only never; no quarantine without file identity; process shown as a labelled identifier", async () => {
    const t = await text("hijack-basic");
    const n = numbered(t);
    expect(n).toHaveLength(3);
    expect(n[0]).toContain("Disable"); expect(n[1]).toContain("หยุด instance"); expect(n[2]).toContain("ยุติ payload process");
    expect(t).toContain("(Scheduled Task)");
    expect(n[2]).toContain("ตัวระบุ Process: GUID {7f3a21aa-0001-6700-0000-001000000200}");
    expect(t).not.toMatch(/scheduled_task|process_guid|host_id/);
    expect(t).not.toMatch(/Quarantine/);
    expect(t).toContain("ไม่ยุติซ้ำ");                                                      // no re-terminate without checking first
    expect(t).toContain("การ disable ไม่หยุด instance ที่ทำงานอยู่แล้ว");
    expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.join(" ")).toContain("ไฟล์/object ที่จะ quarantine");
    expect(t).not.toMatch(/ปลายทาง C2|ตัดการติดต่อ/);                                       // outbound/C2 not evidenced
  });
  it("no process name or path is invented: only identifiers present in the evidence appear", async () => {
    const t = await text("hijack-basic");
    expect(t).not.toMatch(/powershell\.exe|cmd\.exe|svchost|rundll32|wscript/i);
  });
  it("full evidence: URL-path restriction is not delegated to DNS control; quarantine pre-check is an instruction, not a claim", async () => {
    const t = await text("hijack-full");
    const step4 = t.slice(t.indexOf("4. **"), t.indexOf("5. **"));
    expect(step4).toContain("URL path");
    expect(step4).toContain("DNS control ตัดได้ระดับ domain เท่านั้น จึงใช้แทนไม่ได้");
    expect(step4).not.toMatch(/ด้วย egress\/web\/DNS control/);
    expect(t).toContain("บันทึก metadata ของ C:\\Users\\Public\\upd.exe");
    expect(t).not.toMatch(/มี metadata ใน incident record/);
    expect(t.indexOf("Quarantine")).toBeGreaterThan(t.indexOf("ตัดการติดต่อไปยัง"));
  });
  it("full evidence: established-connection cut waits for a confirmed tool and does not claim deny rules always/never cut connections", async () => {
    const t = await text("hijack-full");
    expect(t).not.toContain("ตัด connection ที่ established ของ WKS-FIN-07 → 203.0.113.45**");   // not a ready step
    expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.join(" ")).toContain("ตัด connection ที่ established ของ WKS-FIN-07 → 203.0.113.45");
    expect(t).not.toMatch(/deny rule ไม่ตัด connection|deny rule ตัด connection ทุก/);
  });
});

describe("4) after Re-hunt", () => {
  it("effective: status first, no repeat, no generic 'confirm the evidence' investigation, and no 'incident closed' claim", async () => {
    const t = await text("rehunt-effective");
    expect(numbered(t)).toHaveLength(0);
    expect(t).toContain("**สถานะมาตรการจากรอบก่อน**");
    expect(t).toContain("ไม่เสนอซ้ำ");
    expect(t).toContain("ไม่ใช่การยืนยันว่า incident ปิดแล้ว");
    expect(t).not.toMatch(/ยืนยันหลักฐานที่ทำให้เกิดการแจ้งเตือน|หลักฐานยังไม่พอ|ยังไม่มีมาตรการ containment/);
    expect(t).not.toContain("**ข้อมูลที่ต้องตรวจเพิ่ม**");
  });
  it("unverified: names the missing coverage / telemetry; says neither contained nor failed", async () => {
    const t = await text("rehunt-unverified");
    expect(numbered(t)).toHaveLength(0);
    expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.join(" ")).toMatch(/telemetry.*agent ออนไลน์/);
    expect(t).toContain("ไม่ถือว่า contained และไม่ถือว่าล้มเหลว");
    expect(t).not.toMatch(/ยังมีผลอยู่|ยังคงมีผล/);
  });
  it("threat returned, IR recorded the control as only partly applied: REPEAT with the reason, the recurrence and the instruction to check the IR record", async () => {
    const t = await text("rehunt-returned-not-applied");
    expect(numbered(t).length).toBeGreaterThanOrEqual(1);
    const reason = lines(t).find((l) => l.includes("เหตุผลที่เสนออีกครั้ง:"))!;
    expect(reason).toContain("กลับมา");
    expect(reason).toContain("เครื่อง: attack-endpoint");
    expect(reason).toContain("ตรวจบันทึกการดำเนินการของ IR");
  });
  it("threat returned after the IR attested the control was applied: NOT repeated; the path / scope must be re-examined", async () => {
    const t = await text("rehunt-returned-control-applied");
    expect(numbered(t)).toHaveLength(0);
    expect(t).toContain("ไม่เสนอทำมาตรการเดิมซ้ำ");
    expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.join(" ")).toContain("เส้นทาง/บริการ/บัญชีที่กิจกรรมใหม่");
  });
  it("threat returned but the IR left no control state: NOT repeated; the control state is requested", async () => {
    const t = await text("rehunt-returned-control-unknown");
    expect(numbered(t)).toHaveLength(0);
    expect(sectionBullets(t, "ข้อมูลที่ต้องตรวจเพิ่ม")!.join(" ")).toContain("สถานะปัจจุบันของมาตรการเดิม");
  });
});

describe("5) approval is separate from ready steps", () => {
  it("IR execution authority denied: no ready step; only the approval list; the authority named is the one the knowledge requires; no invented contact", async () => {
    const e = await get("needs-authorization"); const t = e.composition!.userText;
    expect(numbered(t)).toHaveLength(0);
    expect(e.composition!.steps.filter((s) => s.stepType === "ACTION")).toHaveLength(0);
    expect(e.composition!.steps.filter((s) => s.stepType === "MANUAL").every((s) => s.actionCode === null && s.requiresApproval)).toBe(true);
    expect(t).toContain("**ต้องขออนุมัติก่อนดำเนินการ (ยังไม่ใช่ขั้นตอนพร้อมลงมือ)**");
    expect(t).toContain("IR (ผู้ดำเนินการ)");
    expect(t).toContain("องค์กรยังไม่ได้ระบุผู้รับหรือช่องทางอนุมัติในระบบ");
    expect(t).not.toContain("**ข้อมูลที่ต้องตรวจเพิ่ม**");
  });
  it("a contact is shown ONLY when the organization configured it", async () => {
    const t = await text("needs-authorization-contact");
    expect(t).toContain("ผู้ติดต่อที่องค์กรระบุ: IR on-call (ช่องทางตัวอย่างใน fixture)");
    expect(t).not.toContain("องค์กรยังไม่ได้ระบุผู้รับ");
  });
  it("CRITICAL asset: the account action needs the asset owner; it is not a ready step", async () => {
    const e = await get("needs-asset-owner"); const t = e.composition!.userText;
    const approval = lines(t).find((l) => l.includes("ตัดการเข้าถึงของ identity ที่ถูกยึด"))!;
    expect(approval.startsWith("- ")).toBe(true);
    expect(approval).toContain("เจ้าของ asset/workload");
    expect(approval).toContain("ความสำคัญสูง");
    expect(approval).toContain("องค์กรยังไม่ได้ระบุผู้รับหรือช่องทางอนุมัติในระบบ");
    expect(numbered(t).some((l) => l.includes("identity"))).toBe(false);
    expect(e.composition!.steps.some((s) => s.stepType === "ACTION" && /IDENTITY-CREDENTIAL/.test(s.actionCode ?? ""))).toBe(false);
  });
  it("asset owner contact appears only when configured", async () => {
    const t = await text("needs-asset-owner-contact");
    expect(t).toContain("ผู้ติดต่อที่องค์กรระบุ: ทีมเจ้าของระบบ Finance (ช่องทางตัวอย่างใน fixture)");
  });
});

describe("the API renders stored steps to exactly the same text (backend, API and ticket format agree)", () => {
  it.each(SCENARIOS.map((s) => s.id))("%s", async (id) => {
    const comp = (await get(id)).composition!;
    const stored = JSON.parse(JSON.stringify({ steps: comp.steps.map((s) => ({ stepType: s.stepType, title: s.title, actionId: s.actionCode, reason: s.reason, instructions: s.instructions })) }));
    const out = presentRecommendation(stored);
    expect(out.recommendationText).toBe(comp.userText);
  });
});

describe("the output validator and wording layer actually bite (negative tests)", () => {
  const { validateUserText } = jest.requireActual("../src/domain/subtype/outputValidator") as typeof import("../src/domain/subtype/outputValidator");
  const { humanizeText, humanizeValue } = jest.requireActual("../src/domain/subtype/wording") as typeof import("../src/domain/subtype/wording");
  const { loader } = jest.requireActual("./helpers/subtypeFixtures") as typeof import("./helpers/subtypeFixtures");
  const kb = loader.load();
  it.each([
    ["a raw key", "ต้องระบุ host_id และ enforcement_point", /RAW_KEY/],
    ["a raw enum value", "บทบาทของต้นทางคือ attacker_source", /RAW_KEY/],
    ["a guarantee about other users", "จำกัดเฉพาะบริการนี้ ผู้ใช้อื่นไม่ถูกตัด", /OVERCLAIM/],
    ["a storage claim", "มี snapshot สำหรับ rollback", /OVERCLAIM/],
    ["a bare condition shown as an instruction", "2. **ตัด session**\n   หาก control รองรับ\n", /CONDITION_ONLY/],
    ["an empty bullet", "**ข้อมูลที่ต้องตรวจเพิ่ม**\n-\n", /EMPTY_SECTION/],
    ["an empty heading", "x\n**ข้อมูลที่ต้องตรวจเพิ่ม**\n", /EMPTY_SECTION/],
  ])("rejects %s", (_n, t, re) => expect(validateUserText(kb, t).join(" ")).toMatch(re));
  it("humanizes values but never completes them", () => {
    expect(humanizeValue("process_identity", "process_guid={abc}")).toBe("GUID {abc}");
    expect(humanizeValue("process_identity", "pid=4242;start=2026-10-08T01:00:00Z;image=C:/x/a.exe")).toBe("PID 4242 เริ่ม 2026-10-08T01:00:00Z image C:/x/a.exe");
    expect(humanizeValue("artifact_type", "scheduled_task")).toBe("Scheduled Task");
    expect(humanizeText("source_role คือ attacker_source")).not.toMatch(/source_role|attacker_source/);
    expect(humanizeText("PID 4242")).toBe("PID 4242");                                    // nothing is added
  });
});
