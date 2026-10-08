import { createHash } from "node:crypto";
import { Result } from "../../../shared/result/Result";
import { IocType } from "../Investigation.types";
import { classifyProvenance } from "./classifyProvenance";
import {
  AccountChangeEvidence, AuthenticationEvidence, CompletenessState, DetectionV2, EVIDENCE_CONTRACT_VERSION, EmailEvidence, EvidenceCategory,
  EvidenceV2, EvidenceV2Context, FileEvidence, HttpEvidence, IocRole, IocV2, MitreTechniqueV2, NetworkEvidence, PowerShellEvidence,
  ProcessEvidence, ProcessRef, SyscheckEvidence,
} from "./types";

/**
 * extractWazuhEvidenceV2 - pure, additive builder of the Evidence Contract v2 document for ONE stored Wazuh alert.
 * Reads only `rawPayload`; invents nothing: an absent field is null / []. It never changes the raw alert and never
 * replaces extractAlertIocs (the existing extractor stays authoritative until parity is proven - see the parity test).
 *
 * Wazuh quirks kept verbatim (values are not "fixed"): web-accesslog `data.protocol` is the HTTP method and `data.id` the
 * status code; Windows EventChannel paths can carry doubled backslashes; useradd `data.shell` can end with a comma.
 */

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : null);
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : typeof v === "number" && Number.isFinite(v) ? String(v) : null);
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.map(str).filter((s): s is string => !!s) : []);
const int = (v: unknown): number | null => {
  const s = str(v);
  return s !== null && /^-?\d+$/.test(s) ? Number(s) : null;
};
const port = (v: unknown): number | null => {
  const n = int(v);
  return n !== null && n >= 0 && n <= 65535 ? n : null;
};
function at(root: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Obj)[k] : undefined), root);
}
const present = (root: unknown, path: string) => str(at(root, path)) !== null || (Array.isArray(at(root, path)) && (at(root, path) as unknown[]).length > 0);

const isoOrNull = (s: string | null): string | null => {
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
};

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
/** Resolves a syslog "Oct  3 11:46:46" (no year, no zone) using the alert time's year and UTC offset. */
function resolveSyslogTime(raw: string | null, detectedIso: string, detectedRaw: string | null): string | null {
  const m = raw ? /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(raw.trim()) : null;
  const month = m ? MONTHS.indexOf(m[1]) : -1;
  if (!m || month < 0) return null;
  const off = detectedRaw ? /([+-])(\d{2}):?(\d{2})$/.exec(detectedRaw) : null;
  const offsetMs = off ? (off[1] === "-" ? -1 : 1) * (Number(off[2]) * 60 + Number(off[3])) * 60000 : 0;
  const detected = Date.parse(detectedIso);
  const build = (year: number) => Date.UTC(year, month, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])) - offsetMs;
  let t = build(new Date(detected).getUTCFullYear());
  if (t > detected + 24 * 3600 * 1000) t = build(new Date(detected).getUTCFullYear() - 1);
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}

function splitUser(raw: string | null): { domain: string | null; name: string | null; raw: string } | null {
  if (!raw) return null;
  const m = /^(.*?)\\{1,2}([^\\]+)$/.exec(raw);
  return m ? { domain: m[1] || null, name: m[2], raw } : { domain: null, name: raw, raw };
}

function parseHashes(raw: string | null): { alg: string; value: string }[] {
  if (!raw) return [];
  return raw.split(",").flatMap((part) => {
    const i = part.indexOf("=");
    const alg = i > 0 ? part.slice(0, i).trim() : "";
    const value = i > 0 ? part.slice(i + 1).trim() : "";
    return alg && value ? [{ alg, value }] : [];
  });
}

function hashIocType(value: string): IocType | null {
  if (!/^[a-f0-9]+$/i.test(value)) return null;
  return value.length === 32 ? "MD5" : value.length === 40 ? "SHA1" : value.length === 64 ? "SHA256" : null;
}

function hasData(v: unknown): boolean {
  if (v === null || v === undefined || v === false) return false;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.values(v as Obj).some(hasData);
  return true;
}

/** Expected Wazuh paths per (decoder / log source / Windows event / harness event type); "a|b" = either one. */
function expectedPaths(p: Obj): Partial<Record<EvidenceCategory, string[]>> {
  const decoder = str(at(p, "decoder.name")) ?? "";
  const parent = str(at(p, "decoder.parent")) ?? "";
  const location = str(p.location) ?? "";
  const eid = str(at(p, "data.win.system.eventID"));
  const channel = str(at(p, "data.win.system.channel")) ?? "";
  const eventType = str(at(p, "data.vigix.event_type"));
  const ed = "data.win.eventdata.";
  const out: Partial<Record<EvidenceCategory, string[]>> = {};
  if (decoder === "sshd" || parent === "sshd") out.authentication = ["data.srcip", "data.dstuser|data.srcuser"];
  if (decoder === "pam") out.authentication = ["data.srcip", "data.dstuser"];
  if (decoder === "web-accesslog") {
    out.http = ["data.url", "data.protocol", "data.id"];
    out.network = ["data.srcip"];
  }
  if (decoder.startsWith("syscheck") || location === "syscheck") out.syscheck = ["syscheck.path", "syscheck.event"];
  if (decoder === "windows_eventchannel" && (eid === "4624" || eid === "4625")) out.authentication = [ed + "targetUserName", ed + "logonType", ed + "ipAddress"];
  if (channel.includes("Sysmon") && eid === "1") out.process = [ed + "image", ed + "commandLine", ed + "processGuid"];
  if (channel.includes("Sysmon") && eid === "22") {
    out.network = [ed + "queryName"];
    out.process = [ed + "image"];
  }
  if (eid === "4104") out.powershell = [ed + "scriptBlockText"];
  if (decoder === "useradd" || parent === "useradd") out.account = ["data.dstuser"];
  if (decoder === "vigix-usermod") out.account = ["data.dstuser", "data.vigix_group"];
  if (eventType === "c2_beacon" || eventType === "data_exfiltration") out.network = ["data.srcip", "data.dstip", "data.url"];
  if (eventType === "phishing_url_delivered") {
    out.email = ["data.email.from", "data.email.to"];
    out.network = ["data.url"];
  }
  if (eventType === "suspicious_process") out.process = ["data.audit.exe"];
  return out;
}

/** Event identity for deduplication across rules: EventChannel record id, or agent + log time + log line. Otherwise null. */
function deriveEventKey(p: Obj, agentKey: string | null, fullLog: string | null): string | null {
  if (!agentKey) return null;
  const recordId = str(at(p, "data.win.system.eventRecordID"));
  const channel = str(at(p, "data.win.system.channel"));
  if (recordId && channel) return `win:${agentKey}:${channel}:${recordId}`;
  const logTime = str(at(p, "predecoder.timestamp"));
  if (logTime && fullLog) return "log:" + createHash("sha256").update(`${agentKey}
${str(p.location) ?? ""}
${logTime}
${fullLog}`).digest("hex");
  return null;
}

export function extractWazuhEvidenceV2(rawPayload: unknown, ctx: EvidenceV2Context): Result<EvidenceV2, string> {
  const p = obj(rawPayload);
  if (!p) return Result.fail("INVALID_WAZUH_PAYLOAD: payload is not an object");
  const rule = obj(p.rule);
  const ruleId = str(rule?.id);
  const level = typeof rule?.level === "number" ? rule.level : Number(rule?.level);
  const description = str(rule?.description);
  const alertId = str(p.id);
  const detectedRaw = str(p.timestamp);
  const detectedAt = isoOrNull(detectedRaw);
  const agent = obj(p.agent) ?? {};
  if (!ruleId || !Number.isFinite(level) || !description) return Result.fail("INVALID_WAZUH_PAYLOAD: rule.id, rule.level and rule.description are required");
  if (!alertId) return Result.fail("INVALID_WAZUH_PAYLOAD: id is required");
  if (!detectedAt) return Result.fail("INVALID_WAZUH_PAYLOAD: timestamp is required and must be a valid time");
  if (!str(agent.id) && !str(agent.name)) return Result.fail("INVALID_WAZUH_PAYLOAD: agent.id or agent.name is required");
  if (!(ctx.receivedAt instanceof Date) || Number.isNaN(ctx.receivedAt.getTime())) return Result.fail("INVALID_CONTEXT: receivedAt must be a valid Date");

  const data = obj(p.data) ?? {};
  const win = obj(obj(data.win)?.eventdata) ?? {};
  const winSys = obj(obj(data.win)?.system) ?? {};
  const audit = obj(data.audit) ?? {};
  const sc = obj(p.syscheck);
  const decoderName = str(at(p, "decoder.name"));
  const agentIp = str(agent.ip);
  const agentName = str(agent.name);
  const eid = str(winSys.eventID);
  const groups = strList(rule?.groups);
  const eventType = str(at(p, "data.vigix.event_type"));

  // ---- provenance
  const prov = classifyProvenance(p, ctx.externalAlertId ?? alertId, ctx.knownFixtureIds);
  const predRaw = str(at(p, "predecoder.timestamp"));
  const utcTime = str(win.utcTime);
  const eventAt = isoOrNull(utcTime ? utcTime.replace(" ", "T") + "Z" : null) ?? isoOrNull(str(winSys.systemTime));

  // ---- detection (metadata only)
  const mitre = obj(rule?.mitre) ?? {};
  const ids = strList(mitre.id);
  const names = strList(mitre.technique);
  const paired = ids.length > 0 && ids.length === names.length;
  const techniques: MitreTechniqueV2[] = ids.map((id, i) => ({ id, name: paired ? names[i] : null }));
  const detection: DetectionV2 = {
    rule: { id: ruleId, level, description, groups, firedTimes: int(rule?.firedtimes), frequency: int(rule?.frequency) },
    mitre: { techniques, tactics: [...new Set(strList(mitre.tactic))] },
  };

  // ---- evidence
  const webLog = decoderName === "web-accesslog";
  const srcIp = str(data.srcip) ?? str(win.sourceIp);
  const dstIp = str(data.dstip) ?? str(win.destinationIp);
  const network: NetworkEvidence = {
    src: { ip: srcIp, port: port(data.srcport) },
    dst: { ip: dstIp, port: port(data.dstport) },
    dnsQuery: str(at(data, "dns.question.name")) ?? str(win.queryName),
    dnsStatus: str(win.queryStatus),
    url: webLog ? null : str(data.url),
    bytesOut: int(data.bytes_out),
    durationSeconds: int(data.duration_seconds),
    direction: agentIp && srcIp === agentIp && dstIp && dstIp !== agentIp ? { value: "OUTBOUND", derivedFrom: "data.srcip equals agent.ip and data.dstip differs" } : null,
  };

  const parentUserRaw = str(win.parentUser);
  const procRef = (image: string | null, commandLine: string | null, pid: string | null, guid: string | null, user: string | null): ProcessRef => ({
    image, commandLine, pid, guid, user: splitUser(user),
  });
  const process: ProcessEvidence = {
    ...procRef(str(win.image) ?? str(audit.exe), str(win.commandLine) ?? str(audit.command) ?? str(data.command), str(win.processId) ?? str(audit.pid), str(win.processGuid), str(win.user) ?? str(audit.user)),
    startedAt: isoOrNull(utcTime ? utcTime.replace(" ", "T") + "Z" : null),
    integrityLevel: str(win.integrityLevel),
    hashes: parseHashes(str(win.hashes)),
    parent: { ...procRef(str(win.parentImage), str(win.parentCommandLine), str(win.parentProcessId) ?? str(audit.ppid), str(win.parentProcessGuid), parentUserRaw), name: str(audit.parent) },
    windowsEvent: { id: eid, channel: str(winSys.channel), provider: str(winSys.providerName) },
  };

  const file: FileEvidence = {
    path: str(data.file),
    hashes: { md5: str(data.md5)?.toLowerCase() ?? null, sha1: str(data.sha1)?.toLowerCase() ?? null, sha256: str(data.sha256)?.toLowerCase() ?? null },
  };

  const operation = str(sc?.event);
  const scOwner = (suffix: "after" | "before") => ({ uid: str(sc?.[`uid_${suffix}`]), gid: str(sc?.[`gid_${suffix}`]), uname: str(sc?.[`uname_${suffix}`]), gname: str(sc?.[`gname_${suffix}`]) });
  const syscheck: SyscheckEvidence = {
    path: str(sc?.path),
    operation,
    detectionMode: str(sc?.mode),
    hashes: {
      after: { md5: str(sc?.md5_after)?.toLowerCase() ?? null, sha1: str(sc?.sha1_after)?.toLowerCase() ?? null, sha256: str(sc?.sha256_after)?.toLowerCase() ?? null, lastKnown: operation === "deleted" },
      before: { md5: str(sc?.md5_before)?.toLowerCase() ?? null, sha1: str(sc?.sha1_before)?.toLowerCase() ?? null, sha256: str(sc?.sha256_before)?.toLowerCase() ?? null },
    },
    size: { after: int(sc?.size_after), before: int(sc?.size_before) },
    permissions: { after: str(sc?.perm_after), before: str(sc?.perm_before) },
    owner: { after: scOwner("after"), before: scOwner("before") },
    modifiedAt: { after: str(sc?.mtime_after), before: str(sc?.mtime_before) },
    inode: { after: str(sc?.inode_after), before: str(sc?.inode_before) },
    changedAttributes: strList(sc?.changed_attributes),
    diffPresent: sc ? sc.diff !== undefined && sc.diff !== null && sc.diff !== "" : false,
  };

  const authSource =
    decoderName === "sshd" || at(p, "decoder.parent") === "sshd" || decoderName === "pam" || eid === "4624" || eid === "4625" ||
    groups.some((g) => g === "authentication_failures" || g === "authentication_failed" || g === "authentication_success");
  const isWinLogon = eid === "4624" || eid === "4625";
  const failed = groups.some((g) => g === "authentication_failures" || g === "authentication_failed");
  const succeeded = groups.includes("authentication_success");
  const subject = str(win.subjectUserName);
  const authentication: AuthenticationEvidence = authSource
    ? {
        result: failed !== succeeded ? { value: failed ? "FAILURE" : "SUCCESS", derivedFrom: "rule.groups" } : null,
        remote: { ip: isWinLogon ? str(win.ipAddress) : str(data.srcip), port: isWinLogon ? port(win.ipPort) : port(data.srcport) },
        account: isWinLogon ? str(win.targetUserName) : str(data.dstuser),
        attemptedAccount: str(data.srcuser),
        accountDomain: str(win.targetDomainName),
        accountSid: str(win.targetUserSid),
        actor: { name: subject, domain: str(win.subjectDomainName), sid: str(win.subjectUserSid), isMachineAccount: subject ? subject.endsWith("$") : null },
        logon: { type: str(win.logonType), id: str(win.targetLogonId), process: str(win.logonProcessName), package: str(win.authenticationPackageName) },
      }
    : {
        result: null, remote: { ip: null, port: null }, account: null, attemptedAccount: null, accountDomain: null, accountSid: null,
        actor: { name: null, domain: null, sid: null, isMachineAccount: null }, logon: { type: null, id: null, process: null, package: null },
      };

  const emailBlock = obj(data.email) ?? {};
  const email: EmailEvidence = {
    sender: str(emailBlock.from),
    recipients: (str(emailBlock.to) ?? "").split(/[;,]/).map((s) => s.trim()).filter(Boolean),
    subject: str(emailBlock.subject),
  };

  const powershell: PowerShellEvidence = {
    scriptBlockText: str(win.scriptBlockText),
    scriptBlockId: str(win.scriptBlockId),
    part: int(win.messageNumber),
    totalParts: int(win.messageTotal),
  };

  const http: HttpEvidence = webLog
    ? { requestTarget: str(data.url), method: str(data.protocol), status: int(data.id) }
    : { requestTarget: null, method: null, status: null };

  const accountSource = decoderName === "useradd" || decoderName === "vigix-usermod" || decoderName === "open-userdel" || at(p, "decoder.parent") === "useradd" || str(data.vigix_group) !== null;
  const account: AccountChangeEvidence = accountSource
    ? { user: str(data.dstuser), group: str(data.vigix_group), uid: str(data.uid), gid: str(data.gid), home: str(data.home), shell: str(data.shell) }
    : { user: null, group: null, uid: null, gid: null, home: null, shell: null };

  const evidence: EvidenceV2["evidence"] = { network, process, file, syscheck, authentication, email, powershell, http, account };

  // ---- completeness: OBSERVED / INCOMPLETE only (NOT_AVAILABLE is a coverage-level fact, not an alert-level one)
  const expected = expectedPaths(p);
  const completeness: Partial<Record<EvidenceCategory, CompletenessState>> = {};
  const missing = new Set<string>();
  for (const cat of Object.keys(evidence) as EvidenceCategory[]) {
    const wanted = expected[cat];
    if (wanted) {
      const lacking = wanted.filter((w) => !w.split("|").some((alt) => present(p, alt)));
      lacking.forEach((l) => missing.add(l));
      completeness[cat] = lacking.length === 0 ? "OBSERVED" : "INCOMPLETE";
    } else if (hasData(evidence[cat])) {
      completeness[cat] = "OBSERVED";
    }
  }

  // ---- IOCs (every one carries the Wazuh path it was read from and a role assigned only by a stated rule)
  const iocs: IocV2[] = [];
  const seen = new Set<string>();
  const add = (type: IocType | null, raw: unknown, sourcePath: string, role: IocRole = "ARTIFACT", roleBasis: string | null = null, lastKnown = false) => {
    const value = str(raw);
    if (!type || !value) return;
    const key = `${type}|${value}|${sourcePath}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ type, value, role, sourcePath, roleBasis: role === "UNKNOWN" ? null : roleBasis, lastKnown });
  };
  const ipType = (v: string): IocType => (v.includes(":") ? "IPV6" : "IPV4");
  const SOURCE_DECODERS = ["sshd", "pam", "web-accesslog"];
  const ipRole = (value: string, path: string): { role: IocRole; basis: string | null } => {
    if (agentIp && value === agentIp) return { role: "ENDPOINT_SELF", basis: "value equals agent.ip (the reporting host, not an indicator)" };
    if (path === "data.srcip") {
      if (decoderName && (SOURCE_DECODERS.includes(decoderName) || at(p, "decoder.parent") === "sshd")) return { role: "SOURCE", basis: `data.srcip is the remote peer/client address parsed by decoder ${decoderName}` };
      if (eventType === "phishing_url_delivered") return { role: "SOURCE", basis: "harness event phishing_url_delivered: data.srcip is the sending MTA" };
    }
    if (path === "data.dstip" && (eventType === "c2_beacon" || eventType === "data_exfiltration")) return { role: "DESTINATION", basis: `harness event ${eventType}: data.dstip is the remote destination` };
    if (path === "data.win.eventdata.sourceIp") return { role: "SOURCE", basis: "Sysmon sourceIp field" };
    if (path === "data.win.eventdata.destinationIp") return { role: "DESTINATION", basis: "Sysmon destinationIp field" };
    if (path === "data.win.eventdata.ipAddress" && isWinLogon) return { role: "SOURCE", basis: "EID 4624/4625 ipAddress is the logon source address" };
    return { role: "UNKNOWN", basis: null };
  };
  const addIp = (raw: unknown, path: string) => {
    const v = str(raw);
    if (!v) return;
    const r = ipRole(v, path);
    add(ipType(v), v, path, r.role, r.basis);
  };
  for (const path of ["data.srcip", "data.dstip", "data.win.eventdata.sourceIp", "data.win.eventdata.destinationIp"]) addIp(at(p, path), path);
  if (isWinLogon) addIp(win.ipAddress, "data.win.eventdata.ipAddress");

  add("DOMAIN", at(data, "dns.question.name"), "data.dns.question.name");
  add("DOMAIN", win.queryName, "data.win.eventdata.queryName");
  const url = str(data.url);
  if (url) {
    if (/^(https?|ftp):\/\//i.test(url)) {
      add("URL", url, "data.url");
      try {
        const host = new URL(url).hostname;
        if (!/^[\d.]+$/.test(host) && !host.includes(":")) add("DOMAIN", host, "data.url");
      } catch {
        /* unparseable URL: the URL itself is still recorded */
      }
    } else {
      add("HTTP_REQUEST", url, "data.url");
    }
  }
  for (const key of ["md5", "sha1", "sha256", "hash"]) {
    const h = str(data[key]);
    if (h) add(hashIocType(h), h.toLowerCase(), `data.${key}`);
  }
  for (const h of process.hashes) {
    const t = h.alg.toUpperCase() === "MD5" ? "MD5" : h.alg.toUpperCase() === "SHA1" ? "SHA1" : h.alg.toUpperCase() === "SHA256" ? "SHA256" : null;
    if (t && hashIocType(h.value) === t) add(t, h.value.toLowerCase(), "data.win.eventdata.hashes");
  }

  add("FILE_PATH", data.file, "data.file");
  add("FILE_PATH", win.targetFilename, "data.win.eventdata.targetFilename");
  const lastKnown = operation === "deleted";
  add("FILE_PATH", sc?.path, "syscheck.path", "ARTIFACT", null, lastKnown);
  if (operation === "added" || operation === "modified" || lastKnown) {
    for (const [suffix, t] of [["md5_after", "MD5"], ["sha1_after", "SHA1"], ["sha256_after", "SHA256"]] as const) {
      const h = str(sc?.[suffix]);
      if (h && hashIocType(h) === t) add(t, h.toLowerCase(), `syscheck.${suffix}`, "ARTIFACT", null, lastKnown);
    }
  }

  add("PROCESS_NAME", win.image, "data.win.eventdata.image");
  add("PROCESS_NAME", win.parentImage, "data.win.eventdata.parentImage");
  add("PROCESS_NAME", data.process, "data.process");
  add("PROCESS_NAME", audit.exe, "data.audit.exe");
  add("COMMAND_LINE", win.commandLine, "data.win.eventdata.commandLine");
  add("COMMAND_LINE", data.command, "data.command");
  add("COMMAND_LINE", audit.command, "data.audit.command");
  add("REGISTRY_KEY", win.targetObject, "data.win.eventdata.targetObject");
  if (str(win.targetObject)) add("REGISTRY_VALUE", win.details, "data.win.eventdata.details");

  add("USERNAME", data.srcuser, "data.srcuser", "ACTOR", "data.srcuser is the account the remote party tried to use");
  add("USERNAME", data.dstuser, "data.dstuser", "TARGET", "data.dstuser is the account named by the log line");
  add("USERNAME", win.subjectUserName, "data.win.eventdata.subjectUserName", "ACTOR", "Windows subjectUserName is the account that performed the action");
  add("USERNAME", win.user, "data.win.eventdata.user", "ACTOR", "Sysmon user is the account the process ran as");
  // On group-membership events (4728/4732...) targetUserName is the GROUP, not an account.
  if (!str(win.memberName)) add("USERNAME", win.targetUserName, "data.win.eventdata.targetUserName", "TARGET", "Windows targetUserName is the account acted upon");
  add("EMAIL", email.sender, "data.email.from", "SOURCE", "data.email.from is the sender");
  email.recipients.forEach((r) => add("EMAIL", r, "data.email.to", "TARGET", "data.email.to is a recipient"));

  const evidenceDoc: EvidenceV2 = {
    contractVersion: EVIDENCE_CONTRACT_VERSION,
    provenance: {
      class: prov.class,
      classBasis: prov.basis,
      source: {
        siem: "wazuh",
        alertId,
        alertRowId: ctx.alertRowId ?? null,
        indexerRef: ctx.indexerRef ?? null,
        eventKey: deriveEventKey(p, str(agent.id) ?? agentName, typeof p.full_log === "string" && p.full_log.length ? p.full_log : null),
        manager: str(at(p, "manager.name")),
        decoder: { name: decoderName, parent: str(at(p, "decoder.parent")) },
        location: str(p.location),
        inputType: str(at(p, "input.type")),
      },
      agent: { id: str(agent.id), name: agentName, ip: agentIp },
      time: {
        detectedAt,
        reportedAt: resolveSyslogTime(predRaw, detectedAt, detectedRaw),
        reportedAtRaw: predRaw,
        eventAt,
        receivedAt: ctx.receivedAt.toISOString(),
      },
      completeness,
      missing: [...missing],
    },
    detection,
    evidence,
    iocs,
    fullLog: typeof p.full_log === "string" && p.full_log.length ? p.full_log : null,
  };
  return Result.ok(evidenceDoc);
}
