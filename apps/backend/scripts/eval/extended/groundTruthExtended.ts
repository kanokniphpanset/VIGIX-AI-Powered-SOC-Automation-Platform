/**
 * groundTruthExtended.ts — Ground Truth of the EXTENDED evaluation (LOW severity, False Positive, ESCALATED path, RAG).
 * Written and hashed BEFORE any extended run and before any AI output exists; the runner records the SHA-256 of this
 * object in every run.json and refuses to run when the hash differs from the one in `ground-truth.sha256`.
 *
 * Rule-id/level facts below come from a CALIBRATION of stock Wazuh 4.9.2 rules in the isolated lab (calibrate.ts,
 * 2026-10-01): which rule fires is environment knowledge, not an AI result. Severity is the deterministic Wazuh-level
 * mapping of WazuhAdapter (>=14 critical, >=11 high, >=7 medium, else low); the AI never sets it.
 *
 * Benign labels are the scenario author's: VIGIX has no automatic false-positive verdict (the AI emits none); a false
 * positive is a HUMAN decision (SOC triage for MEDIUM) or an IR decision (reject) for HIGH/CRITICAL.
 */
export type ExtKind = "LOW" | "FP_MEDIUM" | "FP_HIGH";

export interface ExtCase {
  id: string;
  kind: ExtKind;
  title: string;
  benignReason: string;
  /** Lab action that produces the alert (see simulateExt in run-low-fp.ts). */
  trigger: string;
  expected: { ruleId: string; level: number; severity: "low" | "medium" | "high" | "critical"; stockRule: boolean };
  /** What VIGIX must do (checked from the database). */
  expectedHandling: string[];
}

export const EXTENDED_GROUND_TRUTH: ExtCase[] = [
  {
    id: "LOW-01", kind: "LOW", title: "Successful SSH login by a valid user",
    benignReason: "valid account, correct password, normal administrative login",
    trigger: "ssh victim@endpoint with the correct password, run `id`",
    expected: { ruleId: "5715", level: 3, severity: "low", stockRule: true },
    expectedHandling: ["alert stored with severity low", "audit ALERT_OUTSIDE_SOC_WORKFLOW", "no incident", "no investigation / AI analysis / recommendation / response", "SOC triage attempt refused (NOT_IN_SOC_WORKFLOW)"],
  },
  {
    id: "LOW-02", kind: "LOW", title: "Single failed SSH login (typo)",
    benignReason: "one mistyped password by a legitimate user",
    trigger: "one ssh attempt for user victim with a wrong password",
    expected: { ruleId: "5760", level: 5, severity: "low", stockRule: true },
    expectedHandling: ["alert stored with severity low", "audit ALERT_OUTSIDE_SOC_WORKFLOW", "no incident", "no investigation / AI analysis / recommendation / response", "SOC triage attempt refused (NOT_IN_SOC_WORKFLOW)"],
  },
  {
    id: "LOW-03", kind: "LOW", title: "Web request for a missing page (404)",
    benignReason: "ordinary broken link / bookmark",
    trigger: "one HTTP GET for /does-not-exist.html",
    expected: { ruleId: "31101", level: 5, severity: "low", stockRule: true },
    expectedHandling: ["alert stored with severity low", "audit ALERT_OUTSIDE_SOC_WORKFLOW", "no incident", "no investigation / AI analysis / recommendation / response", "SOC triage attempt refused (NOT_IN_SOC_WORKFLOW)"],
  },
  {
    id: "LOW-04", kind: "LOW", title: "Boundary: level 6 (just below MEDIUM)",
    benignReason: "single XSS-looking string from an authorised web-application test",
    trigger: "one HTTP GET with <script>alert(1)</script> in the query string",
    expected: { ruleId: "31105", level: 6, severity: "low", stockRule: true },
    expectedHandling: ["alert stored with severity low (level 6 < 7)", "audit ALERT_OUTSIDE_SOC_WORKFLOW", "no incident", "no AI / recommendation / response", "SOC triage attempt refused (NOT_IN_SOC_WORKFLOW)"],
  },
  {
    id: "FP-01", kind: "FP_MEDIUM", title: "Authorised vulnerability scan — one SQL-injection-looking request (MEDIUM, boundary level 7)",
    benignReason: "authorised Nessus-style scan of the lab web server (change ticket CHG-EVAL-0101)",
    trigger: "one HTTP GET with `union select` in the query string, User-Agent Nessus",
    expected: { ruleId: "31103", level: 7, severity: "medium", stockRule: true },
    expectedHandling: [
      "alert stored with severity medium; audit ALERT_ROUTED_TO_TRIAGE; NO automatic incident",
      "SOC triage FALSE_POSITIVE with a reason: alert TRIAGED/closed, audit ALERT_TRIAGED, no incident",
      "no investigation / AI analysis / recommendation / response is created",
      "a second decision on the closed alert is refused (ALERT_ALREADY_DECIDED)",
    ],
  },
  {
    id: "FP-02", kind: "FP_MEDIUM", title: "Authorised site crawler — burst of 4xx responses (MEDIUM, level 10)",
    benignReason: "approved site-crawler / link checker run by the web team",
    trigger: "25 HTTP GETs for non-existent pages from one source, User-Agent SiteCrawler",
    expected: { ruleId: "31151", level: 10, severity: "medium", stockRule: true },
    expectedHandling: [
      "alert stored with severity medium; audit ALERT_ROUTED_TO_TRIAGE; NO automatic incident",
      "SOC triage FALSE_POSITIVE with a reason: alert TRIAGED/closed, audit ALERT_TRIAGED, no incident",
      "no investigation / AI analysis / recommendation / response is created",
      "a second decision on the closed alert is refused (ALERT_ALREADY_DECIDED)",
    ],
  },
  {
    id: "FP-03", kind: "FP_HIGH", title: "Approved change — a new operations engineer is added to the sudo group (CRITICAL, level 14)",
    benignReason: "approved change CHG-EVAL-0103: account opsadmin created and added to sudo by the platform team",
    trigger: "useradd opsadmin; usermod -aG sudo opsadmin (identical telemetry to TC-10: VIGIX cannot tell it apart by rule)",
    expected: { ruleId: "100350", level: 14, severity: "critical", stockRule: false },
    expectedHandling: [
      "CRITICAL: an incident is opened AUTOMATICALLY (Policy intake) — a HIGH/CRITICAL alert cannot be closed as false positive from the inbox",
      "closing the alert as FALSE_POSITIVE is refused (alert already in an incident)",
      "AI analysis and a recommendation may be produced (cost of the false positive); the AI emits no false-positive verdict and does not close anything",
      "SOC hands the step to IR; IR_TEAM REJECTS it (authorised change): nothing is executed, ticket PENDING_MANUAL_DECISION, no automatic regeneration",
      "the incident is not closed by the reject; a human sets it to dismissed; 'resolved' is refused without a verification",
      "0 step executions; no response executed",
    ],
  },
];

/** Escalation case: TC-07 telemetry (searchable IP/domain/URL IOCs, four distinct playbook steps) with the attack repeated after every response. */
export const ESCALATION_GROUND_TRUTH = {
  id: "ESC-01", basedOn: "TC-07 Command & Control (rule 100320, level 13, high)",
  rounds: 3,
  expected: [
    "after each completed response the same C2 beacon repeats, so the REAL_WAZUH re-hunt finds the IOCs again -> NOT_RESOLVED",
    "round 1 and 2 NOT_RESOLVED: the investigation is reopened (investigation_number +1) and the AI generates a new recommendation for the next round (an IR decision is still required; nothing executes automatically)",
    "round 3 NOT_RESOLVED: no new investigation, no new recommendation, incident status 'escalated' (never resolved/closed), audit INVESTIGATION_ESCALATED and INCIDENT_ESCALATED with reason MAX_INVESTIGATION_ROUNDS_REACHED",
    "nothing executes after the escalation; 'resolved' is refused for the escalated incident; a human decision (manual) is the only way forward",
  ],
  maxInvestigationRounds: 3,
};

/** RAG: which runbook(s) of the 17 in the Knowledge Base are relevant to each case (author-defined BEFORE any retrieval). */
export const RAG_GROUND_TRUTH_NOTE =
  "Relevance is defined in rag/ragGroundTruth.ts (runbook codes per case) and frozen with its own hash before any retrieval.";
