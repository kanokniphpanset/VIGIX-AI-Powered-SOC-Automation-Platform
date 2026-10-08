/**
 * buildRealShapeMocks.ts - regenerates resources/mock-attacks-tc-realshape/TC-01..TC-10.json from the real Wazuh alerts in
 * apps/backend/test/fixtures/wazuh-real. Each mock is the real alert, field for field, with exactly two changes that mark it as a
 * MOCK_FIXTURE: a fresh fixture-style `id` and the rule group `vigix_custom` appended. Nothing else is added or removed, so a
 * mock built here cannot carry a field (or lack one) that the real alert does not. Offline, deterministic, no network.
 */
import fs from "node:fs";
import path from "node:path";

const REAL = path.resolve(__dirname, "../test/fixtures/wazuh-real");
const OUT = path.resolve(__dirname, "../../../resources/mock-attacks-tc-realshape");
const CASES: { tc: string; slug: string; rule: string }[] = [
  { tc: "TC-01", slug: "brute-force", rule: "5712" },
  { tc: "TC-02", slug: "malware", rule: "100301" },
  { tc: "TC-03", slug: "phishing", rule: "100310" },
  { tc: "TC-04", slug: "account-compromise", rule: "40112" },
  { tc: "TC-05", slug: "powershell", rule: "100300" },
  { tc: "TC-06", slug: "sql-injection", rule: "31103" },
  { tc: "TC-07", slug: "command-and-control", rule: "100320" },
  { tc: "TC-08", slug: "suspicious-process", rule: "100330" },
  { tc: "TC-09", slug: "data-exfiltration", rule: "100340" },
  { tc: "TC-10", slug: "privilege-escalation", rule: "100350" },
];

fs.mkdirSync(OUT, { recursive: true });
CASES.forEach(({ tc, slug, rule }, i) => {
  const file = fs.readdirSync(REAL).find((f) => f.startsWith(`${rule}-`) && f.endsWith(".json") && !f.includes(".v2."))!;
  const alert = JSON.parse(fs.readFileSync(path.join(REAL, file), "utf8"));
  alert.id = `1790000000.${910000 + i + 1}`;
  alert.rule.groups = [...(alert.rule.groups ?? []), "vigix_custom"];
  fs.writeFileSync(path.join(OUT, `${tc}-${slug}.json`), JSON.stringify(alert, null, 2) + "\n");
});
console.log(`wrote ${CASES.length} files to ${OUT}`);
