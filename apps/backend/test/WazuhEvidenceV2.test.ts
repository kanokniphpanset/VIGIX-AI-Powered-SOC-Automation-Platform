import fs from "node:fs";
import path from "node:path";
import { extractWazuhEvidenceV2 } from "../src/domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import { classifyProvenance } from "../src/domain/investigation/evidenceV2/classifyProvenance";
import { EvidenceV2, EvidenceV2Context } from "../src/domain/investigation/evidenceV2/types";
import { extractAlertIocs } from "../src/domain/investigation/alertIocs";

/**
 * Evidence Contract v2 extractor, tested against REAL Wazuh alerts captured read-only from the lab Wazuh Indexer on
 * 2026-10-08 (test/fixtures/wazuh-real, user/host names masked). Rule 100300-100350 documents are HARNESS_GENERATED:
 * real Wazuh pipeline, log line written by the evaluation harness. TC fixtures in resources/ are MOCK_FIXTURE.
 */
const REAL_DIR = path.join(__dirname, "fixtures", "wazuh-real");
const TC_DIR = path.resolve(__dirname, "../../../resources/mock-attacks-tc");
const read = (dir: string, file: string): Record<string, any> => JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
const realFiles = fs.readdirSync(REAL_DIR).filter((f) => /^\d+-.*\.json$/.test(f)).sort();
const real = (prefix: string) => read(REAL_DIR, realFiles.find((f) => f.startsWith(prefix + "-"))!);
const ctx: EvidenceV2Context = { receivedAt: new Date("2026-10-08T01:00:00.000Z"), alertRowId: "row-1" };
const run = (payload: unknown, c: EvidenceV2Context = ctx): EvidenceV2 => {
  const r = extractWazuhEvidenceV2(payload, c);
  if (r.isFailure) throw new Error(r.error);
  return r.value;
};
const ioc = (e: EvidenceV2, type: string, value: string, sourcePath?: string) =>
  e.iocs.find((i) => i.type === type && i.value === value && (!sourcePath || i.sourcePath === sourcePath));

describe("Evidence Contract v2 extractor", () => {
  it("has the real fixtures to work with", () => {
    expect(realFiles.length).toBeGreaterThanOrEqual(20);
  });

  it("extracts every real alert, JSON-serialisably, without mutating the input", () => {
    for (const f of realFiles) {
      const payload = read(REAL_DIR, f);
      const before = JSON.stringify(payload);
      const e = run(payload);
      expect(e.contractVersion).toBe(2);
      expect(e.provenance.source.alertId).toBe(payload.id);
      expect(e.detection.rule.id).toBe(String(payload.rule.id));
      expect(JSON.stringify(payload)).toBe(before);
      expect(() => JSON.stringify(e)).not.toThrow();
      expect(e.iocs.every((i) => i.sourcePath && i.value && i.role)).toBe(true);
    }
  });

  describe("provenance", () => {
    it("separates real telemetry, harness-generated events and mock fixtures", () => {
      expect(run(real("5712")).provenance.class).toBe("REAL_TELEMETRY");
      expect(run(real("31103")).provenance.class).toBe("REAL_TELEMETRY");
      expect(run(real("550")).provenance.class).toBe("REAL_TELEMETRY");
      expect(run(real("92027")).provenance.class).toBe("REAL_TELEMETRY");
      for (const id of ["100320", "100330", "100340", "100310", "100350", "100301", "100300"]) {
        const e = run(real(id));
        expect(e.provenance.class).toBe("HARNESS_GENERATED");
        expect(e.provenance.classBasis.length).toBeGreaterThan(0);
      }
      const tc = read(TC_DIR, "TC-01-brute-force.json");
      expect(run(tc).provenance.class).toBe("MOCK_FIXTURE");
      expect(run(real("5712"), { ...ctx, externalAlertId: "mock-TC-01-123-abc" }).provenance.class).toBe("MOCK_FIXTURE");
    });

    it("treats a fixture that copies the native id format as mock when the caller lists it", () => {
      const payload = read(path.resolve(__dirname, "../../../resources/mock-attacks/malware"), "case-01-resolved.json").alert;
      expect(run(payload).provenance.class).toBe("REAL_TELEMETRY"); // no marker in the file itself: the limit is stated in classBasis
      expect(run(payload, { ...ctx, knownFixtureIds: new Set([payload.id]) }).provenance.class).toBe("MOCK_FIXTURE");
    });

    it("never claims real for an alert id that is not a native Wazuh id", () => {
      const payload = { ...real("5712"), id: "abc" };
      expect(classifyProvenance(payload, "abc").class).toBe("UNKNOWN_ORIGIN");
    });

    it("keeps VIGIX receipt time separate from the Wazuh alert time and resolves the syslog time", () => {
      const e = run(real("5712"));
      expect(e.provenance.time.detectedAt).toBe("2026-10-03T12:23:49.540Z");
      expect(e.provenance.time.receivedAt).toBe("2026-10-08T01:00:00.000Z");
      expect(e.provenance.time.reportedAtRaw).toBe("Oct  3 12:23:47");
      expect(e.provenance.time.reportedAt).toBe("2026-10-03T12:23:47.000Z");
      expect(run(real("92027")).provenance.time.eventAt).toBe("2026-10-03T11:49:26.419Z");
      expect(run(real("550")).provenance.time.reportedAt).toBeNull();
    });

    it("records the indexer document reference only when supplied", () => {
      expect(run(real("5712")).provenance.source.indexerRef).toBeNull();
      expect(run(real("5712"), { ...ctx, indexerRef: { index: "wazuh-alerts-4.x-2026.10.03", docId: "x" } }).provenance.source.indexerRef).toEqual({ index: "wazuh-alerts-4.x-2026.10.03", docId: "x" });
    });
  });

  describe("MITRE is detection metadata", () => {
    it("pairs technique ids with names and keeps tactics as an unpaired set", () => {
      const e = run(real("40112"));
      expect(e.detection.mitre.techniques).toEqual([{ id: "T1078", name: "Valid Accounts" }, { id: "T1110", name: "Brute Force" }]);
      expect(e.detection.mitre.tactics.length).toBe(5);
      expect(new Set(e.detection.mitre.tactics).size).toBe(5);
      const f = run(real("553"));
      expect(f.detection.mitre.techniques.map((t) => t.id)).toEqual(["T1070.004", "T1485"]);
    });

    it("returns empty lists when Wazuh sent no MITRE and never guesses", () => {
      const e = run(real("5901"));
      expect(e.detection.mitre).toEqual({ techniques: [], tactics: [] });
    });

    it("does not shift names when the arrays differ in length", () => {
      const p = real("40112");
      p.rule.mitre = { id: ["T1", "T2"], technique: ["Only one"], tactic: ["A", "A"] };
      const e = run(p);
      expect(e.detection.mitre.techniques).toEqual([{ id: "T1", name: null }, { id: "T2", name: null }]);
      expect(e.detection.mitre.tactics).toEqual(["A"]);
    });

    it("keeps MITRE out of the evidence section (a SQLi rule mapped to T1055 proves nothing)", () => {
      const e = run(real("31152"));
      expect(e.detection.mitre.techniques.map((t) => t.id)).toContain("T1055");
      expect(JSON.stringify(e.evidence)).not.toContain("T1055");
      expect(e.evidence.http.status).toBe(404);
    });
  });

  describe("syscheck (FIM)", () => {
    it("reads the real *_after fields, not the non-existent syscheck.uid/gid", () => {
      const e = run(real("100301"));
      const s = e.evidence.syscheck;
      expect(s.path).toBe("/root/Downloads/Invoice_Q4_2026.xls.exe");
      expect(s.operation).toBe("added");
      expect(s.detectionMode).toBe("realtime");
      expect(s.hashes.after.sha256).toBe("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
      expect(s.hashes.before.sha256).toBeNull();
      expect(s.size.after).toBe(68);
      expect(s.owner.after.uid).toBe("0");
      const p = { ...real("100301"), syscheck: { path: "/x", event: "added", uid: "5", gid: "5" } };
      expect(run(p).evidence.syscheck.owner.after).toEqual({ uid: null, gid: null, uname: null, gname: null });
    });

    it("creates the FILE_PATH and hash IOCs that the old extractor missed", () => {
      for (const prefix of ["100301", "550", "553", "554"]) {
        const payload = real(prefix);
        expect(extractAlertIocs(payload)).toEqual([]);
        const e = run(payload);
        expect(ioc(e, "FILE_PATH", payload.syscheck.path, "syscheck.path")).toBeDefined();
        expect(ioc(e, "SHA256", payload.syscheck.sha256_after, "syscheck.sha256_after")).toBeDefined();
      }
    });

    it("marks a deleted file's attributes as last known and never as a live indicator", () => {
      const e = run(real("553"));
      expect(e.evidence.syscheck.operation).toBe("deleted");
      expect(e.evidence.syscheck.hashes.after.lastKnown).toBe(true);
      expect(e.iocs.filter((i) => i.sourcePath.startsWith("syscheck.")).every((i) => i.lastKnown)).toBe(true);
      expect(run(real("554")).iocs.filter((i) => i.sourcePath.startsWith("syscheck.")).every((i) => !i.lastKnown)).toBe(true);
    });

    it("keeps before-hashes out of the IOC list and records changed attributes on a modification", () => {
      const e = run(real("550"));
      expect(e.evidence.syscheck.changedAttributes.length).toBeGreaterThan(0);
      expect(e.iocs.some((i) => i.sourcePath.endsWith("_before"))).toBe(false);
    });

    it("never copies Wazuh's content diff", () => {
      const p = real("550");
      p.syscheck.diff = "SECRET-FILE-CONTENT-DIFF";
      const e = run(p);
      expect(e.evidence.syscheck.diffPresent).toBe(true);
      expect(JSON.stringify(e)).not.toContain("SECRET-FILE-CONTENT-DIFF");
      expect(run(real("554")).evidence.syscheck.diffPresent).toBe(false);
    });
  });

  describe("IOC roles come only from stated rules", () => {
    it("treats the sshd/web remote address as SOURCE", () => {
      const e = run(real("5712"));
      expect(ioc(e, "IPV4", "172.19.0.3", "data.srcip")).toMatchObject({ role: "SOURCE" });
      expect(ioc(e, "IPV4", "172.19.0.3", "data.srcip")!.roleBasis).toMatch(/decoder sshd/);
      expect(ioc(run(real("31103")), "IPV4", "172.19.0.3", "data.srcip")).toMatchObject({ role: "SOURCE" });
    });

    it("never treats the reporting host as an attacker (C2 and exfiltration events)", () => {
      for (const id of ["100320", "100340"]) {
        const payload = real(id);
        const e = run(payload);
        expect(ioc(e, "IPV4", payload.agent.ip, "data.srcip")).toMatchObject({ role: "ENDPOINT_SELF" });
        expect(ioc(e, "IPV4", payload.data.dstip, "data.dstip")).toMatchObject({ role: "DESTINATION" });
      }
    });

    it("leaves the role UNKNOWN when no rule applies", () => {
      const p = real("5712");
      p.decoder = { name: "some-other-decoder" };
      p.data.srcip = "203.0.113.9";
      expect(ioc(run(p), "IPV4", "203.0.113.9", "data.srcip")).toMatchObject({ role: "UNKNOWN", roleBasis: null });
    });

    it("types a web request target as HTTP_REQUEST, not as an outbound URL", () => {
      const e = run(real("31103"));
      expect(e.iocs.find((i) => i.sourcePath === "data.url")).toMatchObject({ type: "HTTP_REQUEST" });
      expect(e.evidence.network.url).toBeNull();
      expect(e.evidence.http).toMatchObject({ method: "GET", status: 404 });
      expect(e.evidence.http.requestTarget).toContain("union%20select");
    });

    it("assigns account roles by field and skips group names on membership events", () => {
      expect(ioc(run(real("5712")), "USERNAME", "git", "data.srcuser")).toMatchObject({ role: "ACTOR" });
      expect(ioc(run(real("5902")), "USERNAME", "evaluser", "data.dstuser")).toMatchObject({ role: "TARGET" });
      const p = real("60106");
      p.data.win.eventdata.memberName = "CN=x";
      expect(run(p).iocs.some((i) => i.sourcePath === "data.win.eventdata.targetUserName")).toBe(false);
    });
  });

  describe("evidence categories and completeness", () => {
    it("derives the authentication result only from rule.groups", () => {
      expect(run(real("5712")).evidence.authentication.result).toEqual({ value: "FAILURE", derivedFrom: "rule.groups" });
      expect(run(real("40112")).evidence.authentication.result).toBeNull();
      expect(run(real("60106")).evidence.authentication.result).toEqual({ value: "SUCCESS", derivedFrom: "rule.groups" });
    });

    it("flags a logon without a source address as INCOMPLETE instead of filling it", () => {
      const e = run(real("60106"));
      expect(e.evidence.authentication.logon.type).toBe("5");
      expect(e.evidence.authentication.remote.ip).toBeNull();
      expect(e.provenance.completeness.authentication).toBe("INCOMPLETE");
      expect(e.provenance.missing).toContain("data.win.eventdata.ipAddress");
    });

    it("flags an alert that carries only full_log (rule 5901) as INCOMPLETE", () => {
      const e = run(real("5901"));
      expect(e.provenance.completeness.account).toBe("INCOMPLETE");
      expect(e.evidence.account.user).toBeNull();
      expect(e.fullLog).toContain("new group");
    });

    it("extracts Windows process identity, parent and split hashes (Sysmon EID 1)", () => {
      const payload = real("92027");
      const e = run(payload);
      const ed = payload.data.win.eventdata;
      expect(e.evidence.process.image).toBe(ed.image);
      expect(e.evidence.process.guid).toBe(ed.processGuid);
      expect(e.evidence.process.pid).toBe(ed.processId);
      expect(e.evidence.process.parent.pid).toBe(ed.parentProcessId);
      expect(e.evidence.process.hashes).toEqual([{ alg: "SHA256", value: "9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3" }]);
      expect(e.evidence.process.user).toMatchObject({ domain: "WIN-LAB01", name: "labuser" });
      expect(e.evidence.process.windowsEvent).toMatchObject({ id: "1", provider: "Microsoft-Windows-Sysmon" });
      expect(ioc(e, "SHA256", "9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3")).toBeDefined();
      expect(e.provenance.completeness.process).toBe("OBSERVED");
    });

    it("extracts the PowerShell script block (EID 4104) that the old extractor ignored", () => {
      const payload = real("91822");
      expect(extractAlertIocs(payload)).toEqual([]);
      const e = run(payload);
      expect(e.evidence.powershell.scriptBlockText).toContain("Invoke-Command");
      expect(e.evidence.powershell).toMatchObject({ part: 1, totalParts: 1 });
      expect(e.evidence.process.image).toBeNull();
    });

    it("extracts the phishing sender/recipient and the privilege-change target group", () => {
      const m = run(real("100310"));
      expect(m.evidence.email.sender).toBe("it-support@vigix-eval-phish.net");
      expect(m.evidence.email.recipients).toEqual(["hr.clerk@corp.local"]);
      expect(ioc(m, "EMAIL", "hr.clerk@corp.local")).toMatchObject({ role: "TARGET" });
      const g = run(real("100350"));
      expect(g.evidence.account).toMatchObject({ user: "evaluser", group: "sudo" });
    });

    it("keeps network facts numeric and derives direction only when it can", () => {
      const n = run(real("100320")).evidence.network;
      expect(n.dst.port).toBe(8080);
      expect(n.direction).toEqual({ value: "OUTBOUND", derivedFrom: "data.srcip equals agent.ip and data.dstip differs" });
      expect(run(real("5712")).evidence.network.direction).toBeNull();
      expect(run(real("100340")).evidence.network.bytesOut).toBe(3145728);
    });

    it("extracts harness process events from data.audit", () => {
      const e = run(real("100330"));
      expect(e.evidence.process.image).toBe("/tmp/.cache/kworkerd");
      expect(e.evidence.process.parent.name).toBe("tail");
      expect(e.evidence.process.pid).toBe("1450");
    });
  });

  describe("absent data and invalid input", () => {
    it("returns null / [] for everything Wazuh did not send", () => {
      const e = run({ id: "1790000000.123456", timestamp: "2026-10-03T12:00:00.000+0000", rule: { id: "1", level: 3, description: "d" }, agent: { name: "a" } });
      expect(e.detection.mitre).toEqual({ techniques: [], tactics: [] });
      expect(e.evidence.syscheck.path).toBeNull();
      expect(e.evidence.syscheck.hashes.after).toEqual({ md5: null, sha1: null, sha256: null, lastKnown: false });
      expect(e.evidence.email.recipients).toEqual([]);
      expect(e.evidence.network.src).toEqual({ ip: null, port: null });
      expect(e.iocs).toEqual([]);
      expect(e.fullLog).toBeNull();
      expect(e.provenance.completeness).toEqual({});
    });

    it("rejects payloads that lack the required fields instead of padding them", () => {
      const ok = real("5712");
      expect(extractWazuhEvidenceV2(null, ctx).isFailure).toBe(true);
      expect(extractWazuhEvidenceV2({ ...ok, rule: { ...ok.rule, description: "" } }, ctx).isFailure).toBe(true);
      expect(extractWazuhEvidenceV2({ ...ok, id: undefined }, ctx).isFailure).toBe(true);
      expect(extractWazuhEvidenceV2({ ...ok, timestamp: "not a time" }, ctx).isFailure).toBe(true);
      expect(extractWazuhEvidenceV2({ ...ok, agent: {} }, ctx).isFailure).toBe(true);
      expect(extractWazuhEvidenceV2(ok, { receivedAt: new Date("x") }).isFailure).toBe(true);
    });
  });

  describe("parity with the existing extractAlertIocs", () => {
    it("never loses an indicator the old extractor finds (real fixtures and the TC mocks)", () => {
      const payloads = [
        ...realFiles.map((f) => read(REAL_DIR, f)),
        ...fs.readdirSync(TC_DIR).filter((f) => /^TC-\d\d-.*\.json$/.test(f)).map((f) => read(TC_DIR, f)),
      ];
      expect(payloads.length).toBeGreaterThanOrEqual(30);
      for (const payload of payloads) {
        const v2 = run(payload);
        for (const old of extractAlertIocs(payload)) {
          expect({ id: payload.id, type: old.iocType, value: old.value, found: !!ioc(v2, old.iocType, old.value) }).toEqual({ id: payload.id, type: old.iocType, value: old.value, found: true });
        }
      }
    });
  });
});
