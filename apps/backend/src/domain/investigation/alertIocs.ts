import { IocType } from "./Investigation.types";

/** One indicator observed directly in an alert payload. `path` is the payload field it was read from. */
export interface AlertIoc {
  iocType: IocType;
  value: string;
  path: string;
}

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v.trim() : null;
}

function hashType(value: string): IocType | null {
  if (!/^[a-f0-9]+$/i.test(value)) return null;
  return value.length === 32 ? "MD5" : value.length === 40 ? "SHA1" : value.length === 64 ? "SHA256" : null;
}

/**
 * Deterministically lists the indicators a Wazuh alert states explicitly - network (srcip/dstip/url/dns),
 * file (path, hashes), host (process, command line, registry) and identity (user) fields. Nothing is inferred:
 * a value is returned only when it sits in one of the fields below. Values are NOT validated here; callers run
 * them through checkIocValue. The agent (host) itself is not an indicator and is not returned.
 */
export function extractAlertIocs(rawPayload: unknown): AlertIoc[] {
  const payload = asObject(rawPayload) ?? {};
  const data = asObject(payload.data) ?? {};
  const win = asObject(asObject(data.win)?.eventdata) ?? {};
  const audit = asObject(data.audit) ?? {};
  const out: AlertIoc[] = [];
  const add = (iocType: IocType | null, raw: unknown, path: string) => {
    const value = str(raw);
    if (iocType && value) out.push({ iocType, value, path });
  };

  for (const key of ["srcip", "dstip"]) {
    const ip = str(data[key]);
    add(ip && ip.includes(":") ? "IPV6" : "IPV4", ip, `data.${key}`);
  }
  add("DOMAIN", asObject(asObject(data.dns)?.question)?.name, "data.dns.question.name");
  // Sysmon event 22 (DnsQuery): the name the process asked the resolver for - stated explicitly in the event, and the same
  // field the Wazuh re-hunt adapter searches for DOMAIN IOCs (WazuhRehuntAdapter: data.win.eventdata.queryName).
  add("DOMAIN", win.queryName, "data.win.eventdata.queryName");

  const url = str(data.url);
  if (url) {
    if (/^(https?|ftp):\/\//i.test(url)) {
      add("URL", url, "data.url");
      try {
        const host = new URL(url).hostname;
        if (!/^[\d.]+$/.test(host) && !host.includes(":")) add("DOMAIN", host, "data.url");
      } catch {
        /* not a parseable URL - the URL itself is still recorded */
      }
    } else {
      add("HTTP_REQUEST", url, "data.url");
    }
  }

  for (const key of ["md5", "sha1", "sha256", "hash"]) {
    const h = str(data[key]);
    if (h) add(hashType(h), h.toLowerCase(), `data.${key}`);
  }

  add("FILE_PATH", data.file, "data.file");
  add("FILE_PATH", win.targetFilename, "data.win.eventdata.targetFilename");
  add("PROCESS_NAME", win.image, "data.win.eventdata.image");
  add("PROCESS_NAME", win.parentImage, "data.win.eventdata.parentImage");
  add("PROCESS_NAME", data.process, "data.process");
  // auditd-style layout: the executable of the audited process. A scalar data.process cannot be indexed by Wazuh (the
  // index template maps data.process as an object), so process alerts from the Wazuh Indexer carry it here.
  add("PROCESS_NAME", audit.exe, "data.audit.exe");
  add("COMMAND_LINE", win.commandLine, "data.win.eventdata.commandLine");
  add("COMMAND_LINE", data.command, "data.command");
  add("REGISTRY_KEY", win.targetObject, "data.win.eventdata.targetObject");
  if (str(win.targetObject)) add("REGISTRY_VALUE", win.details, "data.win.eventdata.details");

  add("USERNAME", data.srcuser, "data.srcuser");
  add("USERNAME", data.dstuser, "data.dstuser");
  add("USERNAME", win.subjectUserName, "data.win.eventdata.subjectUserName");
  add("USERNAME", win.user, "data.win.eventdata.user");
  // On group-membership events (4728/4732...) targetUserName is the GROUP, not an account.
  if (!str(win.memberName)) add("USERNAME", win.targetUserName, "data.win.eventdata.targetUserName");

  const seen = new Set<string>();
  return out.filter((i) => {
    const key = `${i.iocType}|${i.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** IOC types that identify something searchable across the environment (network / file hash), incl. the
 *  generic IP / HASH spellings older rows and the re-hunt target use. Compared upper-cased. */
export const REHUNT_IOC_TYPES: readonly string[] = ["IP", "IPV4", "IPV6", "DOMAIN", "URL", "HASH", "MD5", "SHA1", "SHA256"];
