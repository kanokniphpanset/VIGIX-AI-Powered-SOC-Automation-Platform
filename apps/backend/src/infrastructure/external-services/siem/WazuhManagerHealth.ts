import https from "https";
import { readFileSync } from "fs";

export interface WazuhManagerApiConfig {
  /** https://host:55000 */
  url: string;
  username: string;
  password: string;
  /** PEM that signed (or is) the API certificate; the API's default one is self-signed. */
  caPath?: string;
  /** Dev only: skip TLS verification. Prefer caPath. */
  insecureTls?: boolean;
  timeoutMs?: number;
}

export type ManagerHealth = { status: "UP" | "DEGRADED" | "DOWN" | "NOT_CONFIGURED"; detail: string; latencyMs: number | null };

/** Daemons VIGIX depends on: rules (analysisd), agents (remoted), log files (logcollector), the VIGIX forwarder (integratord). */
export const REQUIRED_DAEMONS = ["wazuh-analysisd", "wazuh-remoted", "wazuh-logcollector", "wazuh-integratord"] as const;

export function wazuhManagerConfigFromEnv(env: NodeJS.ProcessEnv): WazuhManagerApiConfig | null {
  if (!env.WAZUH_API_URL || !env.WAZUH_API_USERNAME || !env.WAZUH_API_PASSWORD) return null;
  return {
    url: env.WAZUH_API_URL,
    username: env.WAZUH_API_USERNAME,
    password: env.WAZUH_API_PASSWORD,
    caPath: env.WAZUH_API_CA_PATH || undefined,
    insecureTls: env.WAZUH_API_INSECURE_TLS === "true",
  };
}

/** Pure: daemon status + agent summary -> health. A stopped required daemon is DEGRADED (VIGIX may miss alerts). */
export function assessManager(daemons: Record<string, string>, agents: { active: number; disconnected: number; total: number } | null): Omit<ManagerHealth, "latencyMs"> {
  const stopped = REQUIRED_DAEMONS.filter((d) => daemons[d] !== "running");
  const agentText = agents ? `agents ${agents.active} active / ${agents.total} total${agents.disconnected ? ` (${agents.disconnected} disconnected)` : ""}` : "agents unknown";
  if (stopped.length) return { status: "DEGRADED", detail: `Stopped: ${stopped.join(", ")} · ${agentText}` };
  return { status: "UP", detail: `analysisd, remoted, logcollector, integratord running · ${agentText}` };
}

type Json = Record<string, unknown>;

/**
 * Read-only health of the Wazuh manager through its REST API: authenticate, read the daemon status and the agent
 * summary. Never changes anything on the manager. Not configured -> NOT_CONFIGURED; unreachable / auth error -> DOWN.
 */
export async function probeWazuhManagerApi(config: WazuhManagerApiConfig | null): Promise<ManagerHealth> {
  if (!config) return { status: "NOT_CONFIGURED", detail: "Set WAZUH_API_URL / WAZUH_API_USERNAME / WAZUH_API_PASSWORD to check the Wazuh manager (alerts still arrive by webhook).", latencyMs: null };
  const started = Date.now();
  const base = new URL(config.url);
  const ca = config.caPath ? readFileSync(config.caPath) : undefined;
  const call = (method: string, path: string, headers: Record<string, string>) =>
    new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = https.request(
        { host: base.hostname, port: base.port || 55000, path, method, headers, ca, rejectUnauthorized: !config.insecureTls, agent: false, timeout: config.timeoutMs ?? 5000 },
        (res) => {
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (c) => (body += c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
        }
      );
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", reject);
      req.end();
    });
  try {
    const basic = Buffer.from(`${config.username}:${config.password}`).toString("base64");
    const auth = await call("POST", "/security/user/authenticate?raw=true", { Authorization: `Basic ${basic}` });
    if (auth.status !== 200 || !auth.body) return { status: "DOWN", detail: `Wazuh API authentication failed (HTTP ${auth.status})`, latencyMs: Date.now() - started };
    const bearer = { Authorization: `Bearer ${auth.body.trim()}` };
    const [status, agents] = await Promise.all([call("GET", "/manager/status", bearer), call("GET", "/agents/summary/status", bearer)]);
    if (status.status !== 200) return { status: "DOWN", detail: `Wazuh API /manager/status answered HTTP ${status.status}`, latencyMs: Date.now() - started };
    const daemons = (((JSON.parse(status.body) as Json).data as Json)?.affected_items as Json[] | undefined)?.[0] as Record<string, string> | undefined;
    const conn = agents.status === 200 ? (((JSON.parse(agents.body) as Json).data as Json)?.connection as { active: number; disconnected: number; total: number } | undefined) ?? null : null;
    return { ...assessManager(daemons ?? {}, conn), latencyMs: Date.now() - started };
  } catch (e) {
    return { status: "DOWN", detail: `Wazuh API unreachable: ${e instanceof Error ? e.message : String(e)}`, latencyMs: null };
  }
}
