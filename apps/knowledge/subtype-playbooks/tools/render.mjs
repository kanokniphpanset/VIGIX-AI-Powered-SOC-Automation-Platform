// render.mjs — reference renderer for the user-facing recommendation (prompt §7) + internal audit record (§7.1).
// usage: node render.mjs <case_id> [--audit]      |   node render.mjs --write-examples
// Prototype of the RUNTIME "recommendation composer". Inputs: policy plan (lib.planIncident) + resolved target VALUES (case.target_values).
// Rules enforced here: only ELIGIBLE actions become numbered steps; a step whose placeholder cannot be filled is OMITTED (never shown with {{..}});
// internal ids (family/subtype/Playbook/Policy/Runbook, confidence) never appear in the user text; nothing claims execution/success.
import fs from "node:fs";
import path from "node:path";
import { loadAll, ROOT, planIncident, selectSteps, placeholdersOf } from "./lib.mjs";

const AUTH_LABEL = { ir_emergency: "IR (อำนาจเร่งด่วน)", dba: "DBA", business_authority: "ผู้มีอำนาจของ business item", asset_owner: "เจ้าของ asset/workload", change_approval: "ผู้อนุมัติ change/control", ir_execute: "IR" };

function fill(text, tv) {
  let missing = false;
  const out = text.replace(/\{\{\s*([a-z_]+)\.([a-z_]+)\s*\}\}/g, (_, t, f) => {
    const v = tv?.[t]?.[f];
    if (v === undefined || v === null || v === "") { missing = true; return `{{${t}.${f}}}`; }
    return Array.isArray(v) ? v.join(", ") : String(v);
  });
  return missing ? null : out;
}

function split(text, minIdx = 20) {
  // title = first clause (verb + target); remainder = detail. Delimiters are Thai connectors and are ignored inside parentheses.
  let pre = "";
  const f = text.match(/^(เนื่องจาก[^:]{3,80}):\s*/);   // critical-workload variants: "เนื่องจาก X เป็น workload สำคัญ: <action>"
  if (f) { pre = f[1]; text = text.slice(f[0].length); minIdx = Math.max(12, minIdx - f[0].length); }
  const re = / เฉพาะ| เพื่อ| โดย| แล้ว| ด้วย| หาก| เมื่อ| เพราะ| — /g;
  let m, title = text, rest = "";
  while ((m = re.exec(text))) {
    if (m.index < minIdx) continue;
    const depth = (text.slice(0, m.index).match(/\(/g) ?? []).length - (text.slice(0, m.index).match(/\)/g) ?? []).length;
    if (depth > 0) continue;
    title = text.slice(0, m.index).trim(); rest = text.slice(m.index).replace(/^ — /, "").trim(); break;
  }
  return { title, rest: [pre, rest].filter(Boolean).join(" — ") };
}
function minIdxFor(raw, tv) {
  const m = raw.match(/\{\{\s*[a-z_]+\.[a-z_]+\s*\}\}/);
  if (!m) return 20;
  const filledPrefix = fill(raw.slice(0, m.index + m[0].length), tv);
  return filledPrefix ? filledPrefix.length : 20;
}
const isVerify = (def) => def.kind === "verify" || (!def.fold && /^ตรวจ/.test(def.instruction));

export function renderCase(kb, c) {
  const plan = planIncident(kb, c.facts, c.mode ?? "platform_neutral");
  const tv = c.target_values ?? {};
  const eligibleIds = new Set(plan.ordered.map((n) => n.action_id));
  const steps = [];
  const missingInfo = [];
  const seen = new Set();
  const dedupeKeys = new Set();
  const verifyLines = [];
  for (const node of plan.ordered) {
    const act = kb.actions.get(node.action_id);
    if (act.phase !== "CONTAINMENT") continue;
    for (const rb of act.runbook_refs) {
      const sel = selectSteps(kb, rb, plan.facts, node.decision.variant, 0, eligibleIds);
      let pending = [];
      for (const inc of sel.included) {
        const def = inc.def;
        const text = fill(def.instruction, tv);
        if (text === null) { missingInfo.push(`${def.instruction.match(/\{\{([a-z_]+)\.([a-z_]+)\}\}/g)?.filter((p) => fill(p, tv) === null).join(" ") ?? ""}`); continue; }
        if (inc.fold) { pending.push(`${def.expected_result}${def.verify ? ` (${def.verify})` : ""}`); continue; }
        if (isVerify(def)) { verifyLines.push(text); continue; }
        const { title, rest } = split(text, minIdxFor(def.instruction, tv));
        if (/^ยุติ/.test(title) && def.instruction.includes("{{process.process_identity}}") && !def.instruction.includes("process_children")) {
          // same process terminated by two actions (e.g. persistence trigger + C2 initiator) -> one step, never a wider scope
          const k = `terminate:${tv.process?.host_id}:${tv.process?.process_identity}`;
          if (dedupeKeys.has(k)) continue;
          dedupeKeys.add(k);
        }
        const key = title + "|" + rest;
        if (seen.has(key)) continue;
        seen.add(key);
        const pre = pending.length ? `ตรวจก่อนลงมือ: ${pending.join(" / ")}` : "";
        pending = [];
        steps.push({ title, body: [rest, pre].filter(Boolean).join(" — "), impact: def.impact, verify: def.verify, owner: def.manual_owner, action: node.action_id, flags: node.decision.flags });
      }
      for (const om of sel.omitted) {
        if (om.def?.fold) continue;
        for (const t of om.missing_targets) missingInfo.push(`${kb.targetTypes[t].label_th ?? t}: ต้องระบุ ${kb.targetTypes[t].required_identity_fields.join(", ")}`);
      }
    }
  }
  // actions that did not pass policy -> what is missing (never shown as executable)
  const gaps = [];
  let authorizedNote = null;
  for (const n of plan.notEligible) {
    const d = n.decision;
    if (d.reasons.some((r) => r.code.startsWith("AUTHORIZED:"))) authorizedNote = "หลักฐานระบุว่ากิจกรรมที่ตรวจพบได้รับอนุมัติ (approved) จึงไม่เปิดมาตรการ containment — ให้ยืนยันกับ change record/เจ้าของงานก่อน หากพบว่าไม่ได้รับอนุมัติจริงจึงประเมินใหม่";
    if (d.decision === "PROHIBITED") continue;
    if (d.decision === "NEEDS_EVIDENCE") for (const e of d.missing_evidence) { const ev = kb.evidence.get(e); if (ev) gaps.push(`${ev.confirm.startsWith("ยืนยัน") ? "" : "ยืนยัน: "}${ev.confirm} (เพื่อเปิดมาตรการ: ${kb.actions.get(n.action_id).action_name})`); }
    if (d.decision === "NEEDS_TARGET") for (const t of d.missing_targets) gaps.push(`${kb.targetTypes[t].label_th ?? t}: ต้องระบุ ${kb.targetTypes[t].required_identity_fields.join(", ")}`);
    if (d.decision === "NEEDS_AUTHORIZATION") gaps.push(`ต้องได้รับอนุมัติจากผู้มีอำนาจก่อนดำเนินการ (${n.action_id.replace(/^ACT-/, "").toLowerCase().replace(/-/g, " ")}); ขั้นตอนขออนุมัติขององค์กร: ไม่มีข้อมูลในระบบ`);
    if (d.decision === "UNSUPPORTED") gaps.push(`เครื่องมือที่รองรับมาตรการนี้ยังไม่ทราบ/ไม่รองรับ (${d.reasons.map((r) => r.detail).join("; ")})`);
  }
  if (authorizedNote && !plan.ordered.some((n) => kb.actions.get(n.action_id)?.phase === "CONTAINMENT")) { gaps.length = 0; gaps.push(authorizedNote); }
  // user text
  const L = ["**คำแนะนำเพื่อยับยั้ง Incident**", ""];
  if (steps.length) {
    steps.forEach((s, i) => {
      L.push(`${i + 1}. **${s.title}**`);
      if (s.owner) L.push(`   ผู้รับผิดชอบ: ${AUTH_LABEL[s.owner] ?? s.owner} (ดำเนินการโดยผู้มีอำนาจ — IR ไม่ดำเนินการแทน)`);
      if (s.body) L.push(`   ${s.body}`);
      if (s.impact) L.push(`   *ผลกระทบ: ${s.impact}*`);
      if (s.verify) L.push(`   *ตรวจผล: ${s.verify}*`);
      L.push("");
    });
  } else {
    const inv = plan.ordered.find((n) => n.action_id === "ACT-INVESTIGATE-MISSING-EVIDENCE");
    L.push("ยังไม่มีมาตรการ containment ที่ผ่านเงื่อนไขหลักฐานและ target จึงให้ตรวจสอบสิ่งต่อไปนี้ก่อน:", "");
    const items = [...new Set(gaps)];
    if (!items.length && inv) items.push("ยืนยันหลักฐานที่ทำให้เกิดการแจ้งเตือน (สถานะ เวลา และ entity) จาก log ที่มีอยู่ โดยไม่ execute script/binary ที่น่าสงสัย");
    items.forEach((g, i) => L.push(`${i + 1}. ${g}`));
    L.push("");
  }
  const ginfo = [...new Set([...gaps.filter(() => steps.length), ...missingInfo])];
  if (ginfo.length && steps.length) L.push(`ข้อมูลที่ต้องตรวจเพิ่ม: ${ginfo.join("; ")}`, "");
  if (steps.length && verifyLines.length) { L.push("**ตรวจผลรวมหลังดำเนินการ**"); [...new Set(verifyLines)].forEach((v) => L.push(`- ${v}`)); L.push(""); }
  const user = L.join("\n").trimEnd() + "\n";
  // audit record (never appended to the user text)
  const audit = {
    selected_branches: plan.active, opened_branches: plan.opened,
    policy_decisions: [...plan.nodes.values()].map((n) => ({ action_id: n.action_id, policies: n.decision.policies, decision: n.decision.decision, reasons: n.decision.reasons, flags: n.decision.flags, variant: n.decision.variant })),
    action_order: plan.ordered.map((n) => ({ action_id: n.action_id, depends_on: [...n.depends_on], reason: n.reason })),
    missing_evidence: [...new Set(plan.notEligible.flatMap((n) => n.decision.missing_evidence))],
    missing_targets: [...new Set(plan.notEligible.flatMap((n) => n.decision.missing_targets))],
    runbooks: plan.ordered.flatMap((n) => kb.actions.get(n.action_id).runbook_refs).map((r) => ({ runbook_id: r, version: "2.0.0" })),
    resolved_targets: tv,
  };
  return { user, audit, plan };
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` || process.argv[1]?.endsWith("render.mjs")) {
  const kb = loadAll();
  if (process.argv.includes("--write-examples")) {
    const dir = path.join(ROOT, "recommendation/examples");
    fs.mkdirSync(dir, { recursive: true });
    const wanted = kb.cases.filter((c) => c.example);
    for (const c of wanted) {
      const { user } = renderCase(kb, c);
      const md = [`# ตัวอย่าง ${c.example.file} — ${c.title}`, "", `> สร้างจาก validation case \`${c.case_id}\` ด้วย tools/render.mjs (อินพุต: facts + target_values ใน validation/cases.yaml). ข้อความด้านล่างคือสิ่งที่ผู้ใช้เห็นเท่านั้น; ไม่มี ID/subtype/confidence.`, "", "---", "", user, "---", "", `**สิ่งที่ตรวจในเคสนี้:** ${c.example.checks}`, ""].join("\n");
      fs.writeFileSync(path.join(dir, `${c.example.file}.md`), md);
      console.log("wrote", c.example.file);
    }
  } else {
    const id = process.argv[2];
    const c = kb.cases.find((x) => x.case_id === id);
    if (!c) { console.error("case not found"); process.exit(1); }
    const r = renderCase(kb, c);
    console.log(r.user);
    if (process.argv.includes("--audit")) console.log(JSON.stringify(r.audit, null, 2));
  }
}
