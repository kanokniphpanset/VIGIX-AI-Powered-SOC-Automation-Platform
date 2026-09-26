/**
 * Catalog of the lab attack-test scenarios an analyst can label an alert with (ATK-01..ATK-10). A label is VIGIX-layer
 * metadata on a real ingested alert — it never creates an alert and never changes the raw SIEM payload.
 */
export interface AttackScenario {
  id: string;
  attackType: string;
  caseName: string;
  description: string;
}

export const ATTACK_SCENARIOS: readonly AttackScenario[] = [
  { id: "ATK-01", attackType: "SSH Brute Force", caseName: "Repeated Failed Login", description: "Repeated failed SSH authentication against one account." },
  { id: "ATK-02", attackType: "SSH Brute Force", caseName: "Brute Force + Multiple Accounts", description: "Repeated failed SSH authentication across several usernames." },
  { id: "ATK-03", attackType: "SQL Injection", caseName: "Basic SQLi Probe", description: "HTTP request with a basic SQL-injection pattern against a lab web service." },
  { id: "ATK-04", attackType: "SQL Injection", caseName: "Union / Authentication Bypass Probe", description: "HTTP request with a UNION or authentication-bypass SQL pattern." },
  { id: "ATK-05", attackType: "Privilege / Sudo Abuse", caseName: "Unauthorized Sudo Attempt", description: "A user tries sudo without being allowed to." },
  { id: "ATK-06", attackType: "Privilege / Sudo Abuse", caseName: "Privilege Escalation After Login", description: "Privileged activity by a lab user after logging in." },
  { id: "ATK-07", attackType: "Persistence / Cron", caseName: "Create Cron Persistence", description: "A new harmless cron entry is created on the endpoint." },
  { id: "ATK-08", attackType: "Persistence / Cron", caseName: "Modify Existing Cron Persistence", description: "An existing harmless cron entry is changed." },
  { id: "ATK-09", attackType: "Malware-like Download / Execution", caseName: "Download Only", description: "A harmless test artifact is downloaded inside the lab, not executed." },
  { id: "ATK-10", attackType: "Malware-like Download / Execution", caseName: "Download + Execute", description: "A harmless test artifact is downloaded and a harmless command runs." },
];

export const findAttackScenario = (id: string | null | undefined): AttackScenario | null => ATTACK_SCENARIOS.find((s) => s.id === id) ?? null;
