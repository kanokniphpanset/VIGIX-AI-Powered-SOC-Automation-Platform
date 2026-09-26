/** Read-only probe. Run from apps/backend so dotenv uses the same file as main.ts.
 * No arguments: health/auth/query probe. Optional: TYPE VALUE START_ISO END_ISO.
 * Supply an existing IOC and explicit window; this script never seeds Wazuh data.
 */
import "dotenv/config";
import { createRehuntProvider } from "../src/infrastructure/external-services/siem/createRehuntProvider";
import { RehuntError } from "../src/application/verification/ports/ISiemRehuntPort";

async function main() {
  // Process-local override only. Never edits .env or selects mock for a live probe.
  const adapter = createRehuntProvider({ ...process.env, REHUNT_PROVIDER: "wazuh" });
  const health = await adapter.health();
  console.log(JSON.stringify({ probe: "WazuhRehuntAdapter", health }, null, 2));
  if (!health.reachable) { process.exitCode = 1; return; }
  const [type, value, start, end] = process.argv.slice(2);
  if (!type && !value && !start && !end) return;
  if (!type || !value || !start || !end) throw new Error("Supply TYPE VALUE START_ISO END_ISO together.");
  const result = await adapter.rehunt({ incidentId: "read-only-probe", responseId: "read-only-probe", investigationNumber: 1,
    hosts: [], iocs: [{ type, value }], timeRange: { start: new Date(start), end: new Date(end) } });
  console.log(JSON.stringify({ source: result.source, matchingEvents: result.matchingEvents,
    status: result.matchingEvents ? "MATCH" : "NO_MATCH", timeRange: result.timeRange,
    matchedEventIds: result.events.map(e => e.id), truncated: result.truncated }, null, 2));
}
main().catch(error => {
  console.error(error instanceof RehuntError ? { code: error.code, message: error.message } : "Wazuh probe failed; check configuration and arguments.");
  process.exitCode = 1;
});
