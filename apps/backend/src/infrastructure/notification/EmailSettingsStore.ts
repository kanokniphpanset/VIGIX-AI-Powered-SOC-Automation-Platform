import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { resolve } from "path";
import { randomUUID } from "crypto";
import { spawnSync } from "child_process";

export interface EmailSettings { user: string; password: string }
// Server-wide configuration: only administrators can edit. Windows DPAPI
// binds the encrypted credential to the backend's Windows account.
const directory = resolve(__dirname, "../../../.local-settings");
const file = resolve(directory, "email.json");
function protect(value: string, decrypt = false): string {
  if (process.platform !== "win32") throw new Error("EMAIL_SETTINGS_WINDOWS_REQUIRED");
  const script = decrypt
    ? '$v=[Console]::In.ReadToEnd(); $s=ConvertTo-SecureString $v; $p=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }'
    : '$v=[Console]::In.ReadToEnd(); $s=ConvertTo-SecureString $v -AsPlainText -Force; [Console]::Out.Write((ConvertFrom-SecureString $s))';
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")], { input: value, encoding: "utf8", windowsHide: true, timeout: 10000 });
  if (result.error || result.status !== 0 || !result.stdout) throw new Error("EMAIL_SETTINGS_CREDENTIAL_UNAVAILABLE");
  return result.stdout;
}
export function readEmailSettings(): EmailSettings | null {
  if (!existsSync(file)) return null;
  const data = JSON.parse(readFileSync(file, "utf8"));
  return { user: data.user, password: protect(data.protectedPassword, true) };
}
export function emailSettingsStatus(): { configured: boolean; user: string; source: string } {
  if (!existsSync(file)) return { configured: !!(process.env.EMAIL_HOST && process.env.EMAIL_FROM && process.env.EMAIL_PASSWORD), user: process.env.EMAIL_USER ?? "", source: "environment" };
  const data = JSON.parse(readFileSync(file, "utf8"));
  return { configured: !!(data.user && data.protectedPassword), user: data.user, source: "settings" };
}
export function saveEmailSettings(user: string, password?: string): void {
  const existing = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : null;
  if (!password && (!existing || existing.user !== user)) throw new Error("EMAIL_PASSWORD_REQUIRED");
  const protectedPassword = password ? protect(password) : existing.protectedPassword;
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = resolve(directory, `email-${randomUUID()}.tmp`);
  writeFileSync(temporary, JSON.stringify({ user, protectedPassword }), { mode: 0o600 });
  renameSync(temporary, file);
}
