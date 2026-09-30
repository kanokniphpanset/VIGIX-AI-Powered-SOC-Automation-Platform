import { assessManager, probeWazuhManagerApi, wazuhManagerConfigFromEnv, REQUIRED_DAEMONS } from "../src/infrastructure/external-services/siem/WazuhManagerHealth";

/** Dashboard health of the Wazuh manager (read-only REST API). The network call itself is not exercised here. */
const running = Object.fromEntries(REQUIRED_DAEMONS.map((d) => [d, "running"]));

describe("Wazuh manager health", () => {
  it("all required daemons running -> UP, with the agent summary", () => {
    expect(assessManager({ ...running, "wazuh-maild": "stopped" }, { active: 2, disconnected: 1, total: 3 })).toEqual({
      status: "UP",
      detail: "analysisd, remoted, logcollector, integratord running · agents 2 active / 3 total (1 disconnected)",
    });
  });

  it("a stopped required daemon -> DEGRADED and named (e.g. integratord = alerts no longer reach VIGIX)", () => {
    expect(assessManager({ ...running, "wazuh-integratord": "stopped" }, null)).toEqual({ status: "DEGRADED", detail: "Stopped: wazuh-integratord · agents unknown" });
    expect(assessManager({}, null).status).toBe("DEGRADED");
  });

  it("not configured -> NOT_CONFIGURED (never reported as UP); config read from env", async () => {
    expect(wazuhManagerConfigFromEnv({})).toBeNull();
    expect((await probeWazuhManagerApi(null)).status).toBe("NOT_CONFIGURED");
    expect(wazuhManagerConfigFromEnv({ WAZUH_API_URL: "https://localhost:55000", WAZUH_API_USERNAME: "u", WAZUH_API_PASSWORD: "p", WAZUH_API_CA_PATH: "/ca.pem" })).toEqual({
      url: "https://localhost:55000", username: "u", password: "p", caPath: "/ca.pem", insecureTls: false,
    });
  });

  it("unreachable API -> DOWN (not an exception)", async () => {
    const r = await probeWazuhManagerApi({ url: "https://127.0.0.1:1", username: "u", password: "p", timeoutMs: 1000 });
    expect(r.status).toBe("DOWN");
    expect(r.detail).toMatch(/unreachable/);
  });
});
