/**
 * Mock alert fixtures (lab / test data, never trusted input) — pure helpers, no I/O.
 *
 * Two fixture sets live in the repo's resources/ folder:
 *   TC        resources/mock-attacks-tc/TC-01…TC-10.json   evaluation cases (raw Wazuh alerts)       key "TC-01"
 *   MOCK_ATK  resources/mock-attacks/<type>/case-*.json    E2E cases ({ id: "ATK-01", alert, … })    key "MOCK-ATK-01"
 * The E2E files call themselves ATK-01…ATK-10, but that is a different set from the lab scenario catalog
 * (attackScenarios.ts, also ATK-01…ATK-10), so their key is prefixed MOCK- to keep the two apart.
 *
 * Sending a fixture creates a NEW alert through the normal Wazuh ingestion path. Its external alert id is
 * "mock-<key>-<epoch ms>-<rand>", so a mock alert is always recognisable (and filterable) by its id alone, and the
 * per-source de-duplication never swallows a resend. The raw payload is otherwise the fixture as written.
 */
export type MockAlertSet = "TC" | "MOCK_ATK";

export interface MockAlertCase {
  key: string;
  set: MockAlertSet;
  title: string;
  attackType: string;
  /** Path relative to resources/, for the analyst to find the file. */
  file: string;
  /** The id written inside the fixture's alert (alerts sent before mock ids existed carry it as their external id). */
  fixtureAlertId: string | null;
  ruleId: string | null;
  ruleLevel: number | null;
  ruleDescription: string | null;
  host: string | null;
}

export const MOCK_EXTERNAL_ID_PREFIX = "mock-";
const KEY_RE = /^(?:TC-\d{2}|MOCK-ATK-\d{2})$/;
export const isMockAlertKey = (v: unknown): v is string => typeof v === "string" && KEY_RE.test(v);

/** External alert id for a newly sent mock alert: unique per send, carries the case key. */
export function mockExternalAlertId(key: string, now: Date, rand: string): string {
  return `${MOCK_EXTERNAL_ID_PREFIX}${key}-${now.getTime()}-${rand}`;
}

/** The case key a mock external id was created for, or null for any other alert. */
export function mockKeyOfExternalId(externalAlertId: string): string | null {
  const m = /^mock-((?:TC|MOCK-ATK)-\d{2})-\d+-[a-z0-9]+$/i.exec(externalAlertId);
  return m ? m[1].toUpperCase() : null;
}

/**
 * Inbox filter → which external ids belong to it. `filter` is a case key, "all" (every mock alert), or anything else
 * (no mock filter → null). Alerts sent before mock ids existed are matched by the fixture's own alert id.
 */
export function mockExternalIdMatch(filter: string | undefined, cases: readonly MockAlertCase[]): { prefixes: string[]; exact: string[] } | null {
  if (!filter) return null;
  const chosen = filter === "all" ? cases : cases.filter((c) => c.key === filter.toUpperCase());
  if (filter !== "all" && !chosen.length) return { prefixes: [], exact: [] }; // unknown key → nothing matches
  return {
    prefixes: filter === "all" ? [MOCK_EXTERNAL_ID_PREFIX] : chosen.map((c) => `${MOCK_EXTERNAL_ID_PREFIX}${c.key}-`),
    exact: chosen.map((c) => c.fixtureAlertId).filter((v): v is string => !!v),
  };
}

/** The case an ingested alert came from: a mock id, or (legacy) an external id equal to a fixture's own alert id. */
export function mockCaseOf(externalAlertId: string, cases: readonly MockAlertCase[]): MockAlertCase | null {
  const key = mockKeyOfExternalId(externalAlertId);
  if (key) return cases.find((c) => c.key === key) ?? null;
  return cases.find((c) => c.fixtureAlertId === externalAlertId) ?? null;
}
