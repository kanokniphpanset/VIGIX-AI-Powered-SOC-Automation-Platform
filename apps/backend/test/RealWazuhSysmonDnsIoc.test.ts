import { extractAlertIocs } from "../src/domain/investigation/alertIocs";
import { checkIocValue } from "../src/application/investigation/iocValidation";

/** TC-05 (REAL_WAZUH, Windows 10 + Wazuh agent 4.9.2 + Sysmon 15.22).
 *  This is the REAL alert (rule 100300, id 1791021572.1652167, 2026-10-03 09:59:32Z) exactly as the Wazuh manager produced
 *  it and VIGIX stored it, for Sysmon event 22 (DnsQuery) raised by `powershell.exe` resolving a reserved-TLD lab name.
 *  NOTE: Wazuh's eventchannel decoder doubles the backslashes inside `image` and `user` (visible after JSON parsing);
 *  the extractor reports the values as stated and does not rewrite them. */
const IMAGE = "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe";
const USER = "DESKTOP-3MP7GB3\\\\kanoknipha";
const sysmonDns = {
  agent: { id: "010", name: "vigix-win10-ps", ip: "192.168.239.129" },
  rule: { id: "100300", level: 12, mitre: { id: ["T1059.001"] } },
  data: {
    win: {
      system: { eventID: "22", channel: "Microsoft-Windows-Sysmon/Operational", providerName: "Microsoft-Windows-Sysmon", computer: "DESKTOP-3MP7GB3" },
      eventdata: {
        ruleName: "ps-dns", utcTime: "2026-10-03 09:59:29.855", processGuid: "{74c33ace-d201-6ac0-b706-000000000200}",
        processId: "8040", queryName: "vigix-eval-ps-stager.test", queryStatus: "9003", image: IMAGE, user: USER,
      },
    },
  },
};

/** The real alert VIGIX stored for the PowerShell 4104 probe (rule 91822): only scriptBlockText / scriptBlockId. */
const real4104 = {
  agent: { id: "010", name: "vigix-win10-ps" },
  rule: { id: "91822", level: 12 },
  data: { win: { system: { eventID: "4104", channel: "Microsoft-Windows-PowerShell/Operational" }, eventdata: { messageNumber: "1", messageTotal: "1", scriptBlockId: "d10f316f-e1b0-4ddc-8586-108c966903c5", scriptBlockText: "Invoke-Command -ScriptBlock { Write-Output 'VIGIX-TC05-ingestion-probe-4' }" } } },
};

describe("extractAlertIocs - Sysmon event 22 (DnsQuery), real TC-05 alert", () => {
  const iocs = extractAlertIocs(sysmonDns);
  const find = (t: string) => iocs.filter((i) => i.iocType === t);

  it("extracts the queried name as a DOMAIN from data.win.eventdata.queryName", () => {
    expect(find("DOMAIN")).toEqual([{ iocType: "DOMAIN", value: "vigix-eval-ps-stager.test", path: "data.win.eventdata.queryName" }]);
  });
  it("accepts the extracted domain in the IOC value check", () => {
    expect(checkIocValue("DOMAIN", find("DOMAIN")[0].value)).toEqual({ ok: true, value: "vigix-eval-ps-stager.test" });
  });
  it("still extracts the process and the user as stated, and nothing else", () => {
    expect(find("PROCESS_NAME")).toEqual([{ iocType: "PROCESS_NAME", value: IMAGE, path: "data.win.eventdata.image" }]);
    expect(find("USERNAME")).toEqual([{ iocType: "USERNAME", value: USER, path: "data.win.eventdata.user" }]);
    expect(iocs).toHaveLength(3);
  });
  it("does not turn queryStatus / processId / utcTime into IOCs", () => {
    expect(iocs.some((i) => ["9003", "8040", "2026-10-03 09:59:29.855"].includes(i.value))).toBe(false);
  });
});

describe("extractAlertIocs - unchanged behaviour", () => {
  it("the real PowerShell 4104 alert (scriptBlockText only) still yields no IOC: nothing is parsed out of free text", () => {
    expect(extractAlertIocs(real4104)).toEqual([]);
  });
  it("a missing or blank queryName adds nothing", () => {
    expect(extractAlertIocs({ data: { win: { eventdata: { queryName: "  " } } } })).toEqual([]);
    expect(extractAlertIocs({ data: { win: { eventdata: {} } } })).toEqual([]);
  });
  it("the existing dns.question.name path is unchanged and de-duplicated with queryName", () => {
    const both = extractAlertIocs({ data: { dns: { question: { name: "a.example.net" } }, win: { eventdata: { queryName: "a.example.net" } } } });
    expect(both.filter((i) => i.iocType === "DOMAIN")).toHaveLength(1);
  });
});
