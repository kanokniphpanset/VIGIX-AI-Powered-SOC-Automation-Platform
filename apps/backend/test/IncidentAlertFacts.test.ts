import { incidentTypeFacts } from "../src/domain/incident/incidentTypeFacts";
import { GetIncidentAlertFactsUseCase } from "../src/application/incident/use-cases/GetIncidentAlertFacts.usecase";
import { Result } from "../src/shared/result/Result";

/** Wazuh-format payloads as the manager sends them. */
const sshBruteForce = {
  rule: { id: "5712", level: 10, description: "sshd: brute force trying to get access to the system.", firedtimes: 8, mitre: { id: ["T1110"] } },
  agent: { name: "srv-web-01", ip: "10.0.0.5" },
  predecoder: { program_name: "sshd" },
  data: { srcip: "203.0.113.7", srcport: "52144", dstuser: "root" },
  full_log: "Failed password for root from 203.0.113.7 port 52144 ssh2",
};
const powershell = {
  rule: { id: "92057", level: 12, description: "Suspicious PowerShell execution", mitre: { id: ["T1059.001"] } },
  agent: { name: "WKS-DEMO-01" },
  data: {
    srcip: "10.0.0.20",
    dstip: "198.51.100.9",
    win: { eventdata: { commandLine: "powershell -enc SQBFAFgA", parentImage: "C:\\Windows\\explorer.exe", image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", user: "CORP\\alice" } },
  },
};

describe("incidentTypeFacts", () => {
  it("SSH brute force: user, source port, attempts, program and the log line — as received", () => {
    expect(incidentTypeFacts("SSH_BRUTE_FORCE", sshBruteForce)).toEqual([
      { key: "user", value: "root" },
      { key: "sourcePort", value: "52144" },
      { key: "attempts", value: "8" },
      { key: "program", value: "sshd" },
      { key: "log", value: "Failed password for root from 203.0.113.7 port 52144 ssh2" },
    ]);
  });

  it("PowerShell: command line, parent process, process and user", () => {
    expect(incidentTypeFacts("POWERSHELL", powershell).map((f) => f.key)).toEqual(["commandLine", "parentProcess", "process", "user"]);
    expect(incidentTypeFacts("POWERSHELL", powershell)[0]).toEqual({ key: "commandLine", value: "powershell -enc SQBFAFgA" });
  });

  it("malware: SHA256 is read from the Sysmon Hashes field", () => {
    const raw = { data: { win: { eventdata: { image: "C:\\Temp\\x.exe", hashes: "MD5=00,SHA256=" + "a".repeat(64) } } } };
    expect(incidentTypeFacts("MALWARE", raw)).toEqual(expect.arrayContaining([{ key: "sha256", value: "a".repeat(64) }, { key: "process", value: "C:\\Temp\\x.exe" }]));
  });

  it("missing fields are left out (never guessed); a malformed payload yields nothing", () => {
    expect(incidentTypeFacts("SSH_BRUTE_FORCE", { rule: "Suspicious PowerShell execution", agent: "WKS-DEMO-01" })).toEqual([]);
    expect(incidentTypeFacts(null, null)).toEqual([]);
  });

  it("unknown type -> a general set of fields", () => {
    expect(incidentTypeFacts(null, sshBruteForce).map((f) => f.key)).toEqual(["user", "attempts", "log"]);
  });
});

describe("GetIncidentAlertFactsUseCase", () => {
  const playbook = (code: string, incidentType: string, mitreTechniques: string[]) => ({ code, name: code, version: "1.0", status: "ACTIVE", steps: [], triggerConditions: { scope: "INCIDENT", incidentType, mitreTechniques, allowedActions: [] } });
  const playbooks = { findAll: async () => [playbook("PB-SSH-BRUTEFORCE", "SSH_BRUTE_FORCE", ["T1110"]), playbook("PB-POWERSHELL", "POWERSHELL", ["T1059.001"])] };
  const alert = (id: string, severity: string, rawPayload: unknown) => ({ id, externalAlertId: `wazuh-${id}`, severity, rawPayload });
  const useCase = (alerts: unknown[], mitre: string[] = []) =>
    new GetIncidentAlertFactsUseCase(
      { execute: async () => Result.ok(alerts) } as never,
      { execute: async () => Result.ok(mitre.map((techniqueId) => ({ techniqueId, tactic: "", confidence: null }))) } as never,
      playbooks as never
    );

  it("incident type from the playbook its techniques match; one row per alert with IPs, level and type facts", async () => {
    const r = (await useCase([alert("a1", "high", powershell)]).execute({ incidentId: "i", tenantId: "t" })).value;
    expect(r).toMatchObject({ incidentType: "POWERSHELL", playbook: { code: "PB-POWERSHELL" }, matchedTechniques: ["T1059.001"] });
    expect(r.rows).toEqual([
      expect.objectContaining({ alertId: "a1", severity: "high", ruleLevel: 12, sourceIp: "10.0.0.20", destinationIp: "198.51.100.9", incidentType: "POWERSHELL" }),
    ]);
    expect(r.rows[0].facts[0]).toEqual({ key: "commandLine", value: "powershell -enc SQBFAFgA" });
  });

  it("each alert keeps its own type; an alert with no matching technique takes the incident's", async () => {
    const r = (await useCase([alert("a1", "high", sshBruteForce), alert("a2", "medium", { rule: { level: 5 } })]).execute({ incidentId: "i", tenantId: "t" })).value;
    expect(r.incidentType).toBe("SSH_BRUTE_FORCE");
    expect(r.rows.map((x) => x.incidentType)).toEqual(["SSH_BRUTE_FORCE", "SSH_BRUTE_FORCE"]);
  });

  it("the incident's MITRE mappings count too; no technique at all -> type null (not invented)", async () => {
    expect((await useCase([alert("a1", "high", {})], ["T1110.001"]).execute({ incidentId: "i", tenantId: "t" })).value.incidentType).toBe("SSH_BRUTE_FORCE");
    const none = (await useCase([alert("a1", "high", {})]).execute({ incidentId: "i", tenantId: "t" })).value;
    expect(none).toMatchObject({ incidentType: null, playbook: null, matchedTechniques: [] });
    expect(none.rows[0]).toMatchObject({ incidentType: null, sourceIp: null, destinationIp: null, ruleLevel: null });
  });
});
