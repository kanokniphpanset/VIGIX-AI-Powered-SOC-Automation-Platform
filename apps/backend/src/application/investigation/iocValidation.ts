import { isIP } from "node:net";
import { IocType } from "../../domain/investigation/Investigation.types";

const HEX = (len: number) => new RegExp(`^[a-f0-9]{${len}}$`, "i");
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
const CVE = /^CVE-\d{4}-\d{4,}$/i;
const CERT_FP = /^([0-9a-f]{2}:){19,63}[0-9a-f]{2}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;

export type IocValueCheck = { ok: true; value: string } | { ok: false; reason: string };

/** Checks an IOC value against its declared type and returns the canonical form (hashes/domains lower-cased). */
export function checkIocValue(type: IocType, raw: string): IocValueCheck {
  const value = raw.trim();
  if (!value) return { ok: false, reason: "value is empty" };
  const bad = (reason: string): IocValueCheck => ({ ok: false, reason });

  switch (type) {
    case "IPV4":
      return isIP(value) === 4 ? { ok: true, value } : bad("not a valid IPv4 address");
    case "IPV6":
      return isIP(value) === 6 ? { ok: true, value: value.toLowerCase() } : bad("not a valid IPv6 address");
    case "DOMAIN":
      return DOMAIN.test(value) ? { ok: true, value: value.toLowerCase() } : bad("not a valid domain name");
    case "URL":
      try {
        const u = new URL(value);
        return u.protocol === "http:" || u.protocol === "https:" || u.protocol === "ftp:" ? { ok: true, value } : bad("URL must be http, https or ftp");
      } catch {
        return bad("not a valid URL");
      }
    case "MD5":
      return HEX(32).test(value) ? { ok: true, value: value.toLowerCase() } : bad("MD5 must be 32 hex characters");
    case "SHA1":
      return HEX(40).test(value) ? { ok: true, value: value.toLowerCase() } : bad("SHA1 must be 40 hex characters");
    case "SHA256":
      return HEX(64).test(value) ? { ok: true, value: value.toLowerCase() } : bad("SHA256 must be 64 hex characters");
    case "EMAIL":
      return EMAIL.test(value) ? { ok: true, value: value.toLowerCase() } : bad("not a valid email address");
    case "MAC":
      return MAC.test(value) ? { ok: true, value: value.toLowerCase().replace(/-/g, ":") } : bad("not a valid MAC address");
    case "CVE":
      return CVE.test(value) ? { ok: true, value: value.toUpperCase() } : bad("CVE must look like CVE-2024-12345");
    case "CERT_FINGERPRINT":
      return CERT_FP.test(value) ? { ok: true, value: value.toLowerCase() } : bad("not a valid certificate fingerprint");
    case "PROCESS_ID":
      return /^\d{1,10}$/.test(value) ? { ok: true, value } : bad("process id must be a number");
    default:
      // FILE_NAME, FILE_PATH, REGISTRY_KEY, REGISTRY_VALUE, USERNAME, PROCESS_NAME, HOSTNAME, COMMAND_LINE, HTTP_REQUEST, OTHER: free text.
      return value.length <= 2048 ? { ok: true, value } : bad("value is too long");
  }
}
