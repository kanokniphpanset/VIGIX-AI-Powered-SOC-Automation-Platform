import * as fs from "node:fs";
import * as path from "node:path";
/**
 * CorrectRecommendation.test.ts - unit tests for the deterministic Correct Recommendation scoring and its
 * Ground Truth (v3). Pure functions only (no DB, no LLM).
 */
import { aggregateCorrectness, evaluateCorrectRecommendation, CorrectnessGroundTruth } from "../src/evaluation/correctRecommendation";
import { CORRECTNESS_GROUND_TRUTH, CORRECTNESS_GT_VERSION, correctnessGroundTruthMetadata, correctnessGroundTruthSha256, resolveCorrectnessGroundTruth } from "../src/evaluation/groundTruthCorrectness";
import { INCIDENT_PLAYBOOKS } from "../prisma/seeds/playbook.seed";
import { REAL_GROUND_TRUTH } from "../src/evaluation/groundTruthReal";
import { findActionKnowledge } from "../src/domain/knowledge/actionKnowledge";

const gt = (recs: CorrectnessGroundTruth["expectedRecommendations"]): CorrectnessGroundTruth => ({ caseId: "T", expectedPlaybook: "PB-X", expectedRecommendations: recs });
const ip = (v: string) => ({ type: "ip", value: v });

describe("evaluateCorrectRecommendation", () => {
  it("A - exact match -> CORRECT", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }] });
    expect(r.correct).toBe(true);
    expect(r.playbookMatch).toBe(true);
    expect(r.actionTargetMatches).toBe(true);
  });

  it("B - wrong target -> INCORRECT with a mismatchedTargets entry", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.5" }] });
    expect(r.correct).toBe(false);
    expect(r.playbookMatch).toBe(true);
    expect(r.actionTargetMatches).toBe(false);
    expect(r.mismatchedTargets).toEqual([{ action: "BLOCK-IP", expected: ["1.2.3.4"], actual: "1.2.3.5" }]);
  });

  it("C - missing action -> INCORRECT", () => {
    const r = evaluateCorrectRecommendation(
      gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }, { action: "DISABLE-ACCOUNT", targets: [{ type: "account", value: "victim" }] }]),
      { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }] }
    );
    expect(r.correct).toBe(false);
    expect(r.missingRecommendations.map((m) => m.action)).toEqual(["DISABLE-ACCOUNT"]);
  });

  it("D - additional unauthorized action -> INCORRECT even if the action is globally allowed", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), {
      playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }, { action: "ISOLATE-ENDPOINT", target: "endpoint-01" }],
    });
    expect(r.correct).toBe(false);
    expect(r.unexpectedRecommendations).toEqual([{ action: "ISOLATE-ENDPOINT", target: "endpoint-01" }]);
    expect(r.missingRecommendations).toEqual([]);
  });

  it("E - several actions in a different order -> CORRECT", () => {
    const g = gt([{ action: "A", targets: [{ type: "ip", value: "X" }] }, { action: "B", targets: [{ type: "domain", value: "Y" }] }]);
    const r = evaluateCorrectRecommendation(g, { playbook: "PB-X", steps: [{ action: "B", target: "Y" }, { action: "A", target: "X" }] });
    expect(r.correct).toBe(true);
  });

  it("F - right value but wrong target type -> INCORRECT", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4", targetType: "domain" }] });
    expect(r.correct).toBe(false);
    const ok = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4", targetType: "ip" }] });
    expect(ok.correct).toBe(true);
  });

  it("G - acceptable alternative targets for one action are any-of; optional pairs are neither required nor unexpected", () => {
    const g = gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4"), ip("5.6.7.8")] }, { action: "ISOLATE-ENDPOINT", targets: [{ type: "host", value: "h1" }], optional: true }]);
    expect(evaluateCorrectRecommendation(g, { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "5.6.7.8" }] }).correct).toBe(true);
    expect(evaluateCorrectRecommendation(g, { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }, { action: "ISOLATE-ENDPOINT", target: "h1" }] }).correct).toBe(true);
    // the optional action on a different target is still unexpected
    expect(evaluateCorrectRecommendation(g, { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }, { action: "ISOLATE-ENDPOINT", target: "h2" }] }).correct).toBe(false);
  });

  it("wrong playbook -> INCORRECT even when every pair matches", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), { playbook: "PB-OTHER", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }] });
    expect(r.correct).toBe(false);
    expect(r.playbookMatch).toBe(false);
    expect(r.actionTargetMatches).toBe(true);
  });

  it("compares values case-insensitively and ignores duplicate identical steps", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-DOMAIN", targets: [{ type: "domain", value: "Evil.NET" }] }]), {
      playbook: "PB-X", steps: [{ action: "BLOCK-DOMAIN", target: " evil.net " }, { action: "BLOCK-DOMAIN", target: "evil.net" }],
    });
    expect(r.correct).toBe(true);
  });

  it("the same action on an unexpected extra target is unexpected", () => {
    const r = evaluateCorrectRecommendation(gt([{ action: "BLOCK-IP", targets: [ip("1.2.3.4")] }]), { playbook: "PB-X", steps: [{ action: "BLOCK-IP", target: "1.2.3.4" }, { action: "BLOCK-IP", target: "9.9.9.9" }] });
    expect(r.correct).toBe(false);
    expect(r.unexpectedRecommendations).toEqual([{ action: "BLOCK-IP", target: "9.9.9.9" }]);
  });

  it("allowedActions play no role: a Compliance-valid recommendation is not thereby correct", () => {
    // BLOCK-SOURCE-IP and DISABLE-ACCOUNT are both allowed for brute force, but only the former is expected.
    const t = CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === "TC-01")!;
    const r = evaluateCorrectRecommendation(resolveCorrectnessGroundTruth(t, { ATTACKER_IP: "10.0.0.7" }), {
      playbook: "PB-SSH-BRUTEFORCE", steps: [{ action: "ACT-BLOCK-SOURCE-IP", target: "10.0.0.7" }, { action: "ACT-DISABLE-ACCOUNT", target: "root" }],
    });
    expect(r.correct).toBe(false);
  });
});

describe("aggregateCorrectness", () => {
  it("excludes non-evaluable cases from the denominator", () => {
    const ok = evaluateCorrectRecommendation(gt([{ action: "A", targets: [ip("x")] }]), { playbook: "PB-X", steps: [{ action: "A", target: "x" }] });
    const bad = evaluateCorrectRecommendation(gt([{ action: "A", targets: [ip("x")] }]), { playbook: "PB-X", steps: [] });
    const a = aggregateCorrectness([{ caseId: "TC-01", result: ok }, { caseId: "TC-02", result: bad }, { caseId: "TC-05", result: null }]);
    expect(a).toMatchObject({ nEvaluated: 2, nCorrect: 1, ratePct: 50, correctCases: ["TC-01"], incorrectCases: ["TC-02"], notEvaluable: ["TC-05"] });
  });
  it("no evaluable case -> null rate", () => {
    expect(aggregateCorrectness([{ caseId: "TC-05", result: null }]).ratePct).toBeNull();
  });
});


const gtOf = (id: string) => CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === id)!;
const pairsOf = (id: string) => gtOf(id).expectedRecommendations.map((r) => `${r.action}|${r.targets.map((t) => `${t.type}:${t.value}`).join(",")}`).sort();
const TC05_DOMAIN = "vigix-eval-ps-stager.test";

describe("Correct Recommendation Ground Truth v3.3 (derivation integrity)", () => {
  it("covers TC-01..TC-10 once each", () => {
    expect(CORRECTNESS_GROUND_TRUTH.map((g) => g.caseId)).toEqual(Array.from({ length: 10 }, (_, i) => `TC-${String(i + 1).padStart(2, "0")}`));
  });

  it("adds no knowledge: playbook is groundTruthReal's; every action is a groundTruthReal expectedAction or an unconditional playbook step; every target is a groundTruthReal expectedTarget or a REAL_WAZUH scenario field; nothing optional or dropped", () => {
    for (const g of CORRECTNESS_GROUND_TRUTH) {
      const base = REAL_GROUND_TRUTH.find((b) => b.caseId === g.caseId)!;
      expect(g.expectedPlaybook).toBe(base.expectedPlaybook);
      expect(g.expectedRecommendations.map((r) => r.action).sort()).toEqual([...new Set(g.expectedRecommendations.map((r) => r.action))].sort());
      for (const r of g.expectedRecommendations) {
        expect(r.optional).toBeUndefined();
        const scenarioTarget = r.source?.kind === "PLAYBOOK_STANDARD_STEP" && r.source.targetFrom?.kind === "REAL_WAZUH_SCENARIO";
        if (!scenarioTarget) for (const t of r.targets) expect(base.expectedTargets).toContain(t.value);
        if (r.source?.kind !== "PLAYBOOK_STANDARD_STEP") expect(base.expectedActions).toContain(r.action);
      }
      for (const a of base.expectedActions) expect(g.expectedRecommendations.some((r) => r.action === a)).toBe(true);
    }
  });

  it("playbook-sourced pairs come from an UNCONDITIONAL step of the case's playbook, name the action, are allowed by the playbook, and are the only additions", () => {
    const sourced = CORRECTNESS_GROUND_TRUTH.flatMap((g) => g.expectedRecommendations.filter((r) => r.source?.kind === "PLAYBOOK_STANDARD_STEP").map((r) => ({ g, r })));
    expect(sourced.map((x) => `${x.g.caseId}:${x.r.action}`).sort()).toEqual(["TC-02:ACT-ISOLATE-ENDPOINT", "TC-04:ACT-BLOCK-SOURCE-IP", "TC-05:ACT-BLOCK-DOMAIN", "TC-08:ACT-BLOCK-HASH"]);
    for (const { g, r } of sourced) {
      const src = r.source as { kind: "PLAYBOOK_STANDARD_STEP"; playbook: string; stepOrder: number };
      expect(src.playbook).toBe(g.expectedPlaybook);
      const pb = INCIDENT_PLAYBOOKS.find((p) => p.code === src.playbook)!;
      expect(pb.allowedActions).toContain(r.action);
      const step = pb.steps.find((st) => st.stepOrder === src.stepOrder)!;
      expect(step.description).toContain(r.action);
      expect(step.description).not.toMatch(/\b(only|if|when|unless)\b/i); // not a conditional step
    }
  });

  it("regression: TC-02 / TC-04 / TC-08 expected pairs are exactly those of v3.2", () => {
    expect(pairsOf("TC-02")).toEqual([
      "ACT-BLOCK-HASH|hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "ACT-ISOLATE-ENDPOINT|host:attack-endpoint",
      "ACT-QUARANTINE-FILE|file:/root/Downloads/Invoice_Q4_2026.xls.exe",
    ]);
    expect(pairsOf("TC-04")).toEqual(["ACT-BLOCK-SOURCE-IP|ip:@ATTACKER_IP", "ACT-DISABLE-ACCOUNT|account:victim", "ACT-RESET-CREDENTIAL|account:victim"]);
    expect(pairsOf("TC-08")).toEqual(["ACT-BLOCK-HASH|hash:@KWORKERD_SHA256", "ACT-KILL-PROCESS|process:/tmp/.cache/kworkerd", "ACT-QUARANTINE-FILE|file:/tmp/.cache/kworkerd"]);
    for (const id of ["TC-04", "TC-08"]) expect(pairsOf(id).join()).not.toContain("ACT-ISOLATE-ENDPOINT");
  });

  it("v3.3: TC-05 expects exactly ACT-BLOCK-DOMAIN -> vigix-eval-ps-stager.test (domain) and no ISOLATE-ENDPOINT or any other action", () => {
    expect(pairsOf("TC-05")).toEqual([`ACT-BLOCK-DOMAIN|domain:${TC05_DOMAIN}`]);
    expect(gtOf("TC-05").expectedPlaybook).toBe("PB-POWERSHELL");
    const actions = gtOf("TC-05").expectedRecommendations.map((r) => r.action);
    for (const a of ["ACT-ISOLATE-ENDPOINT", "ACT-DISABLE-ACCOUNT", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH"]) expect(actions).not.toContain(a);
    expect(gtOf("TC-05").expectedRecommendations[0].source).toMatchObject({ kind: "PLAYBOOK_STANDARD_STEP", playbook: "PB-POWERSHELL", stepOrder: 2, targetFrom: { kind: "REAL_WAZUH_SCENARIO", ruleId: "100300", field: "data.win.eventdata.queryName" } });
  });

  it("v3.3: the TC-05 domain is the one the installed REAL_WAZUH rule 100300 matches (T1059.001), and queryName is a field the re-hunt adapter searches", () => {
    const xml = fs.readFileSync(path.join(__dirname, "../../../infra/docker/wazuh-manager/vigix_eval_rules.xml"), "utf8");
    const rule = xml.slice(xml.indexOf('<rule id="100300"'), xml.indexOf("</rule>", xml.indexOf('<rule id="100300"')));
    expect(rule).toContain('level="12"');
    expect(rule).toContain("win.eventdata.queryName");
    expect(rule).toContain("vigix-eval-ps-stager\\.test");
    expect(rule).toContain("<id>T1059.001</id>");
    const adapter = fs.readFileSync(path.join(__dirname, "../src/infrastructure/external-services/siem/WazuhRehuntAdapter.ts"), "utf8");
    expect(adapter).toContain("data.win.eventdata.queryName");
  });

  it("TC-05 scoring 1 - BLOCK-DOMAIN on the expected domain is CORRECT", () => {
    const r = evaluateCorrectRecommendation(gtOf("TC-05"), { playbook: "PB-POWERSHELL", steps: [{ action: "ACT-BLOCK-DOMAIN", target: TC05_DOMAIN, targetType: "domain" }] });
    expect(r.correct).toBe(true);
  });
  it("TC-05 scoring 2 - missing BLOCK-DOMAIN is INCORRECT", () => {
    const r = evaluateCorrectRecommendation(gtOf("TC-05"), { playbook: "PB-POWERSHELL", steps: [] });
    expect(r.correct).toBe(false);
    expect(r.missingRecommendations.map((m) => m.action)).toEqual(["ACT-BLOCK-DOMAIN"]);
  });
  it("TC-05 scoring 3 - wrong domain is INCORRECT", () => {
    const r = evaluateCorrectRecommendation(gtOf("TC-05"), { playbook: "PB-POWERSHELL", steps: [{ action: "ACT-BLOCK-DOMAIN", target: "another-domain.test", targetType: "domain" }] });
    expect(r.correct).toBe(false);
    expect(r.mismatchedTargets).toEqual([{ action: "ACT-BLOCK-DOMAIN", expected: [TC05_DOMAIN], actual: "another-domain.test" }]);
  });
  it("TC-05 scoring 4 - an extra ISOLATE-ENDPOINT -> vigix-win10-ps is UNEXPECTED, hence INCORRECT (strict)", () => {
    const r = evaluateCorrectRecommendation(gtOf("TC-05"), {
      playbook: "PB-POWERSHELL",
      steps: [{ action: "ACT-ISOLATE-ENDPOINT", target: "vigix-win10-ps", targetType: "host" }, { action: "ACT-BLOCK-DOMAIN", target: TC05_DOMAIN, targetType: "domain" }],
    });
    expect(r.correct).toBe(false);
    expect(r.unexpectedRecommendations).toEqual([{ action: "ACT-ISOLATE-ENDPOINT", target: "vigix-win10-ps" }]);
    expect(r.missingRecommendations).toEqual([]);
  });
  it("TC-05 scoring 5 - order and case do not matter; a duplicated identical step counts once", () => {
    const r = evaluateCorrectRecommendation(gtOf("TC-05"), {
      playbook: "PB-POWERSHELL",
      steps: [{ action: "ACT-BLOCK-DOMAIN", target: "VIGIX-EVAL-PS-STAGER.TEST" }, { action: "ACT-BLOCK-DOMAIN", target: ` ${TC05_DOMAIN} ` }],
    });
    expect(r.correct).toBe(true);
  });
  it("TC-05 scoring 6 - wrong playbook is INCORRECT even with the right pair", () => {
    const r = evaluateCorrectRecommendation(gtOf("TC-05"), { playbook: "PB-C2", steps: [{ action: "ACT-BLOCK-DOMAIN", target: TC05_DOMAIN }] });
    expect(r.correct).toBe(false);
    expect(r.playbookMatch).toBe(false);
  });

  it("TC-04 / TC-08 resolve placeholders from pre-attack facts and score by the strict rule", () => {
    const ctx = { ATTACKER_IP: "10.0.0.7", KWORKERD_SHA256: "ab".repeat(32) };
    const tc04 = resolveCorrectnessGroundTruth(gtOf("TC-04"), ctx);
    const pb04 = [{ action: "ACT-DISABLE-ACCOUNT", target: "victim" }, { action: "ACT-RESET-CREDENTIAL", target: "victim" }, { action: "ACT-BLOCK-SOURCE-IP", target: "10.0.0.7" }];
    expect(evaluateCorrectRecommendation(tc04, { playbook: "PB-ACCOUNT-COMPROMISE", steps: pb04 }).correct).toBe(true);
    expect(evaluateCorrectRecommendation(tc04, { playbook: "PB-ACCOUNT-COMPROMISE", steps: [...pb04, { action: "ACT-ISOLATE-ENDPOINT", target: "attack-endpoint" }] }).correct).toBe(false);
    expect(evaluateCorrectRecommendation(tc04, { playbook: "PB-ACCOUNT-COMPROMISE", steps: pb04.slice(0, 2) }).correct).toBe(false);
    const tc08 = resolveCorrectnessGroundTruth(gtOf("TC-08"), ctx);
    const pb08 = [{ action: "ACT-KILL-PROCESS", target: "/tmp/.cache/kworkerd" }, { action: "ACT-QUARANTINE-FILE", target: "/tmp/.cache/kworkerd" }, { action: "ACT-BLOCK-HASH", target: "AB".repeat(32) }];
    expect(evaluateCorrectRecommendation(tc08, { playbook: "PB-SUSPICIOUS-PROCESS", steps: pb08 }).correct).toBe(true);
    expect(evaluateCorrectRecommendation(tc08, { playbook: "PB-SUSPICIOUS-PROCESS", steps: pb08.slice(0, 2) }).correct).toBe(false);
  });

  it("metadata records version, source, rule, rationale and the SHA-256", () => {
    const m = correctnessGroundTruthMetadata();
    expect(m.version).toBe("correctness-gt-v3.3");
    expect(CORRECTNESS_GT_VERSION).toBe(m.version);
    expect(m.sha256).toBe(correctnessGroundTruthSha256());
    expect(m.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(m.source).toMatch(/groundTruthCorrectness\.ts$/);
    expect(m.rule).toMatch(/allowedActions not used/);
    const rationale = m.rationale.join(" ");
    expect(rationale).toMatch(/PB-ACCOUNT-COMPROMISE step 2/);
    expect(rationale).toMatch(/PB-SUSPICIOUS-PROCESS step 2/);
    expect(rationale).toMatch(/PB-MALWARE step 1/);
    expect(rationale).toMatch(/TC-05 uses a controlled REAL_WAZUH PowerShell\/DNS scenario/);
    expect(rationale).toMatch(/rule 100300 \(level 12, MITRE T1059\.001\)/);
    expect(rationale).toMatch(/Sysmon Event ID 22/);
    expect(rationale).toMatch(/re-hunted successfully through WazuhRehuntAdapter/);
    expect(rationale).toMatch(/two independent scenario runs/);
    expect(rationale).toMatch(/ISOLATE-ENDPOINT is excluded because the scenario demonstrates PowerShell\/DNS activity/);
    expect(rationale).not.toMatch(/AI output was|because the AI|v2 result showed/i);
  });

  it("each pair satisfies the Action Catalog targetKind rule (target type is the catalog's, not inferred from the string)", () => {
    for (const g of CORRECTNESS_GROUND_TRUTH) {
      for (const r of g.expectedRecommendations) {
        const kind = findActionKnowledge(r.action)?.targetKind;
        expect(kind).toBeTruthy();
        for (const t of r.targets) expect(t.type).toBe(kind);
      }
    }
  });

  it("the GT hash is stable, covers TC-05 (a TC-05 change would change it) and is not the v3.2 hash", () => {
    expect(correctnessGroundTruthSha256()).toMatch(/^[0-9a-f]{64}$/);
    expect(correctnessGroundTruthSha256()).toBe(correctnessGroundTruthSha256());
    expect(correctnessGroundTruthSha256()).not.toBe("05d81e1b79b4fc1c1cef5a8cc838e27bdb156bdc33e30bcdea497106bf7f2278");
  });
});
