import { ProvenanceClass } from "./types";

export const HARNESS_LOCATION = "/var/log/vigix-eval/events.json";
/** Native Wazuh alert ids are "<epoch>.<sequence>" (1-7 digit sequence observed). Hand-written fixtures can copy the same shape. */
const NATIVE_WAZUH_ID = /^\d{10}\.\d+$/;

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/**
 * Deterministic provenance class from markers the stored alert carries - nothing is guessed:
 *   MOCK_FIXTURE       "mock-" external id, the fixture rule group "vigix_custom", or an id the caller lists as a known fixture
 *   HARNESS_GENERATED  real Wazuh pipeline, but the log line was written by the evaluation harness
 *                      (rule group "vigix_eval", the harness events file, or a data.vigix block)
 *   REAL_TELEMETRY     native Wazuh id and none of the markers above
 *   UNKNOWN_ORIGIN     no marker, but the id is not a native Wazuh id - never claimed as real
 */
export function classifyProvenance(
  payload: Record<string, unknown>,
  externalAlertId: string | null,
  knownFixtureIds?: ReadonlySet<string>
): { class: ProvenanceClass; basis: string[] } {
  const rule = asObject(payload.rule) ?? {};
  const groups = Array.isArray(rule.groups) ? rule.groups.map((g) => String(g).trim()) : [];
  const data = asObject(payload.data) ?? {};
  const id = externalAlertId ?? (typeof payload.id === "string" ? payload.id : null);

  const mock: string[] = [];
  if (id?.startsWith("mock-")) mock.push("external alert id has the mock- prefix");
  if (groups.includes("vigix_custom")) mock.push("rule.groups contains vigix_custom (fixture rule group)");
  if (id && knownFixtureIds?.has(id)) mock.push("alert id is listed as a known fixture id");
  if (mock.length) return { class: "MOCK_FIXTURE", basis: mock };

  const harness: string[] = [];
  if (groups.includes("vigix_eval")) harness.push("rule.groups contains vigix_eval");
  if (payload.location === HARNESS_LOCATION) harness.push(`location is ${HARNESS_LOCATION}`);
  if (asObject(data.vigix)) harness.push("data.vigix block present");
  if (harness.length) return { class: "HARNESS_GENERATED", basis: harness };

  if (id && NATIVE_WAZUH_ID.test(id)) return { class: "REAL_TELEMETRY", basis: ["native-format Wazuh alert id; no mock or harness marker present (a hand-written fixture that copies this id format is only caught via knownFixtureIds)"] };
  return { class: "UNKNOWN_ORIGIN", basis: ["no mock or harness marker, but the alert id is not a native Wazuh id"] };
}
