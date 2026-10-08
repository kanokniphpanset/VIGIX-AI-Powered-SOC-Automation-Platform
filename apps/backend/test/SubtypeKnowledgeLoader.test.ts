import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { DEFAULT_SUBTYPE_KNOWLEDGE_DIR, SubtypeKnowledgeLoader, deployability } from "../src/infrastructure/knowledge/SubtypeKnowledgeLoader";

/** UNIT: the production loader validates the real knowledge and fails CLOSED on a broken copy. */
function copyKnowledge(): string {
  const dst = fs.mkdtempSync(path.join(os.tmpdir(), "subtype-kb-"));
  fs.cpSync(DEFAULT_SUBTYPE_KNOWLEDGE_DIR, dst, { recursive: true, filter: (s) => !/node_modules|[\\/]rag[\\/]|[\\/]recommendation[\\/]/.test(s) });
  return dst;
}
const edit = (file: string, from: string | RegExp, to: string) => {
  const s = fs.readFileSync(file, "utf8");
  if (!(typeof from === "string" ? s.includes(from) : from.test(s))) throw new Error(`pattern not found in ${file}`);
  fs.writeFileSync(file, s.replace(from, to));
};

describe("SubtypeKnowledgeLoader", () => {
  it("loads the real subtype knowledge as VALID with a content-derived version", () => {
    const kb = new SubtypeKnowledgeLoader().load();
    expect(kb.errors).toEqual([]);
    expect(kb.status).toBe("VALID");
    expect(kb.playbooks.size).toBe(50);
    expect(kb.actions.size).toBe(49);
    expect(kb.runbooks.size).toBe(49);
    expect(kb.version).toMatch(/^2\.0\.0\+[0-9a-f]{8}$/);
  });

  it("every ACTION_GATE action has policy + runbook and every legacy action maps to new ids (migration map)", () => {
    const kb = new SubtypeKnowledgeLoader().load();
    for (const a of kb.actions.values()) expect(a.runbook_refs.length).toBeGreaterThan(0);
    expect(kb.legacyActionMap.get("ACT-KILL-PROCESS")).toContain("ACT-PERSISTENCE-TRIGGER-DISABLE");
  });

  it("the organization context is UNKNOWN by default: only ir_execute is granted, no capability is assumed", () => {
    const kb = new SubtypeKnowledgeLoader().load();
    expect(kb.organization.authority.ir_execute).toBe(true);
    expect(kb.organization.authority.dba).toBeNull();
    expect(Object.values(kb.organization.capability).every((v) => v === null)).toBe(true);
  });

  it("is not deployable for enforcement while items await IR review; SUBTYPE_ALLOW_UNREVIEWED is the explicit override", () => {
    const kb = new SubtypeKnowledgeLoader().load();
    expect(kb.unreviewed.length).toBeGreaterThan(0);
    expect(deployability(kb).deployable).toBe(false);
    process.env.SUBTYPE_ALLOW_UNREVIEWED = "true";
    try { expect(deployability(kb).deployable).toBe(true); } finally { delete process.env.SUBTYPE_ALLOW_UNREVIEWED; }
  });

  it("a cyclic dependency makes the knowledge INVALID (no action may be opened from it)", () => {
    const dir = copyKnowledge();
    edit(path.join(dir, "families/MALWARE.yaml"), "{action_id: ACT-ACTIVE-DAMAGE-CONTAIN, condition: POLICY_ELIGIBLE, depends_on: [],", "{action_id: ACT-ACTIVE-DAMAGE-CONTAIN, condition: POLICY_ELIGIBLE, depends_on: [ACT-QUARANTINE-FILE-OBJECT],");
    const kb = new SubtypeKnowledgeLoader(dir).load();
    expect(kb.status).toBe("INVALID");
    expect(kb.errors.some((e) => /cyclic dependency/.test(e))).toBe(true);
    expect(deployability(kb).deployable).toBe(false);
  });

  it("a dangling runbook reference, an undefined predicate field and a runbook that defers to an id are rejected", () => {
    const dir = copyKnowledge();
    edit(path.join(dir, "families/COMMAND_AND_CONTROL.yaml"), "runbook_refs: [RB-WEB-C2-CONTAIN]", "runbook_refs: [RB-WEB-C2-NOPE]");
    edit(path.join(dir, "families/BRUTE_FORCE.yaml"), "field: evidence.bf_attempts_correlated.status, operator: equals, value: PRESENT", "field: confidence.score, operator: gte, value: 0.9");
    edit(path.join(dir, "families/POWERSHELL.yaml"), /instruction: "ยุติ payload process \(ตัวระบุ Process: \{\{process\.process_identity\}\}\)[^"]*"/, 'instruction: "ดำเนินการตาม RB-KILL ที่ {{process.host_id}}"');
    const kb = new SubtypeKnowledgeLoader(dir).load();
    expect(kb.status).toBe("INVALID");
    expect(kb.errors.join("\n")).toMatch(/RB-WEB-C2-NOPE/);
    expect(kb.errors.join("\n")).toMatch(/field outside dictionary confidence\.score/);
    expect(kb.errors.join("\n")).toMatch(/defers to a runbook id/);
  });

  it("a missing knowledge directory is INVALID, not an exception", () => {
    const kb = new SubtypeKnowledgeLoader(path.join(os.tmpdir(), "does-not-exist-subtype")).load();
    expect(kb.status).toBe("INVALID");
  });
});
