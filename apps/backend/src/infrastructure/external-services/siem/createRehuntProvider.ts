import { ISiemRehuntPort } from "../../../application/verification/ports/ISiemRehuntPort";
import { MockRehuntAdapter, MOCK_REHUNT_MODES, MockRehuntMode } from "./MockRehuntAdapter";
import { parseIocFields } from "./WazuhRehuntAdapter";
import { CorrelatedWazuhRehuntAdapter } from "./CorrelatedWazuhRehuntAdapter";

/** Pure configuration boundary: mock never needs live credentials or indexer settings. */
export function createRehuntProvider(env: NodeJS.ProcessEnv): ISiemRehuntPort {
  const provider = env.REHUNT_PROVIDER || "wazuh"; // Preserve the existing unset default.
  if (provider === "mock") {
    const mode = (env.REHUNT_MOCK_MODE || "FIXTURE").toUpperCase() as MockRehuntMode;
    return new MockRehuntAdapter(MOCK_REHUNT_MODES.includes(mode) ? mode : "ERROR");
  }
  if (provider !== "wazuh") throw new Error("REHUNT_PROVIDER must be mock or wazuh.");
  // The correlating adapter: same validated IOC search, plus corroboration, cleanup/activity split, pagination and coverage (Phase 2D).
  return new CorrelatedWazuhRehuntAdapter({
    url: env.WAZUH_INDEXER_URL, username: env.WAZUH_INDEXER_USERNAME, password: env.WAZUH_INDEXER_PASSWORD,
    caPath: env.WAZUH_INDEXER_CA_PATH || undefined, tlsServername: env.WAZUH_INDEXER_TLS_SERVERNAME || undefined,
    insecureTls: env.WAZUH_INDEXER_INSECURE_TLS === "true",
    indexPattern: env.WAZUH_INDEXER_INDEX_PATTERN || env.WAZUH_INDEX_PATTERN || undefined,
    timeoutMs: env.WAZUH_REHUNT_TIMEOUT_MS ? Number(env.WAZUH_REHUNT_TIMEOUT_MS) : undefined,
    timestampField: env.WAZUH_REHUNT_TIMESTAMP_FIELD || undefined,
    fields: parseIocFields(env.WAZUH_REHUNT_IOC_FIELDS),
    monitoringIndexPattern: env.WAZUH_MONITORING_INDEX_PATTERN || undefined,
    archivesIndexPattern: env.WAZUH_ARCHIVES_INDEX_PATTERN || undefined,
    pageSize: env.WAZUH_REHUNT_PAGE_SIZE ? Number(env.WAZUH_REHUNT_PAGE_SIZE) : undefined,
    resultCap: env.WAZUH_REHUNT_RESULT_CAP ? Number(env.WAZUH_REHUNT_RESULT_CAP) : undefined,
    requireAgentCoverage: env.WAZUH_REHUNT_REQUIRE_AGENT_COVERAGE !== "false",
  });
}
