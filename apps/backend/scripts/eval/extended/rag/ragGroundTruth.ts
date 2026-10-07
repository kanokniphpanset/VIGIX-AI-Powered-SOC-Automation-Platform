/**
 * ragGroundTruth.ts — which of the 17 Knowledge-Base runbooks are relevant to each test case. Written and hashed BEFORE
 * any retrieval (pinned in results/extended-evaluation/ground-truth.sha256). The author defines relevance from the
 * runbook titles/triggers in the Knowledge Base and the attack of each case; it is NOT derived from what the retriever
 * returns. Two grades: PRIMARY = the runbook that describes this attack's response as a whole or the response to the
 * case's main indicator; RELEVANT = an action-level runbook that the case's playbook may call.
 * Corpus = the 17 ACTIVE `runbooks` rows (the project's own indexer, scripts/indexRunbooksToQdrant.ts); no KNOWLEDGE-type
 * documents exist in the project, so the KNOWLEDGE side of the dual retrieval has an empty corpus by construction.
 */
export interface RagCase { caseId: string; attack: string; primary: string[]; relevant: string[] }

export const RAG_GROUND_TRUTH: RagCase[] = [
  { caseId: "TC-01", attack: "Brute Force", primary: ["RB-BRUTEFORCE-001"], relevant: ["RB-BLOCK-SOURCE-IP", "RB-DISABLE-ACCOUNT"] },
  { caseId: "TC-02", attack: "Malware", primary: ["RB-MALWARE-001"], relevant: ["RB-QUARANTINE-FILE", "RB-BLOCK-HASH", "RB-ISOLATE-ENDPOINT"] },
  { caseId: "TC-03", attack: "Phishing", primary: ["RB-PHISHING-001"], relevant: ["RB-QUARANTINE-EMAIL", "RB-BLOCK-URL", "RB-BLOCK-DOMAIN"] },
  { caseId: "TC-04", attack: "Account Compromise", primary: ["RB-DISABLE-ACCOUNT"], relevant: ["RB-RESET-CREDENTIAL", "RB-REVOKE-SESSION", "RB-BLOCK-SOURCE-IP"] },
  { caseId: "TC-06", attack: "SQL Injection", primary: ["RB-BLOCK-SOURCE-IP"], relevant: [] },
  { caseId: "TC-07", attack: "Command & Control", primary: ["RB-C2-CONTAINMENT", "RB-NETWORK-001"], relevant: ["RB-BLOCK-DOMAIN", "RB-BLOCK-URL", "RB-ISOLATE-ENDPOINT"] },
  { caseId: "TC-08", attack: "Suspicious Process", primary: ["RB-KILL-MALICIOUS-PROCESS"], relevant: ["RB-QUARANTINE-FILE", "RB-ISOLATE-ENDPOINT"] },
  { caseId: "TC-09", attack: "Data Exfiltration", primary: ["RB-C2-CONTAINMENT", "RB-NETWORK-001"], relevant: ["RB-BLOCK-DOMAIN", "RB-BLOCK-URL", "RB-ISOLATE-ENDPOINT"] },
  { caseId: "TC-10", attack: "Privilege Escalation", primary: ["RB-DISABLE-ACCOUNT"], relevant: ["RB-RESET-CREDENTIAL", "RB-REVOKE-SESSION"] },
];
