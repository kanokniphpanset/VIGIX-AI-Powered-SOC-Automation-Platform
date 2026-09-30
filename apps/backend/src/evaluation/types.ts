/** types.ts — the Master Evaluation Record (§11). A derived, read-only view over the real workflow entities;
 * it is not persisted as its own table (no equivalent existed and the source entities already hold the data). */

export interface ComplianceChecks {
  attackAlignment: boolean;   // recommended actions ⊆ allowed actions for the attack type
  evidenceSupport: boolean;   // every step target is an evidence-linked / analyst-added IOC or affected host
  knowledgeValidity: boolean; // every recommended action exists (enabled) in the Action Catalog
  policyCompliance: boolean;  // step.requiresApproval matches the Policy snapshot; responsible role present
  playbookAlignment: boolean; // snapshot playbook == expected, and every action is in that playbook's allowed set
  approvalCorrectness: boolean; // the created approval's role matches Policy when approval is required
  compliant: boolean;         // AND of the six mandatory criteria
  failedChecks: string[];     // traceable reasons
}

export type VerificationMode = "MOCK" | "REAL_WAZUH" | "NONE";

export interface EvaluationCase {
  // identity / relationships (§11 — references, not duplicated data)
  caseId: string;
  attackType: string;
  attackName: string;
  severity: string | null;
  risk: number | null;
  incidentId: string | null;
  alertId: string | null;
  investigationId: string | null;
  recommendationId: string | null;
  playbookCode: string | null;     // playbook recorded on the recommendation snapshot
  decisionId: string | null;       // Approval id (the human decision)
  responseTicketId: string | null; // ResponsePlan id
  verificationId: string | null;

  // KPI #1 — recommendation compliance
  recommendationStatus: string | null;
  compliance: ComplianceChecks | null;
  recommendationCompliance: "COMPLIANT" | "NON_COMPLIANT" | "NOT_EVALUATED";

  // KPI #2/#3 — timing (from real DB timestamps)
  investigationStartAt: string | null;
  recommendationAt: string | null;
  decisionAt: string | null;
  investigationTimeSeconds: number | null;
  timeToDecisionSeconds: number | null;

  // workflow outcome (verified per step, not by existence of the next)
  workflow: {
    alertIngested: boolean;
    incidentCreated: boolean;
    aiAnalysisCompleted: boolean;
    investigationCompleted: boolean;
    recommendationCreated: boolean;
    recommendationValidated: boolean;
    policyEvaluated: boolean;
    decisionCompleted: boolean;
    responseCompleted: boolean;
    verificationCompleted: boolean;
    rehuntExecuted: boolean;
  };
  workflowCompleted: boolean;
  finalStatus: string | null;

  // verification
  verificationMode: VerificationMode;
  verificationResult: string | null;
  rehuntRound: number | null;

  // retry / reliability (§10)
  recommendationAttemptCount: number;
  invalidOutputCount: number;

  // findings / intervention (§9)
  interventionRequired: boolean;
  interventionType: string[];
  findings: string[];
  notes: string;
}

export interface EvaluationSummary {
  totalCases: number;
  evaluatedCases: number;
  compliantRecommendations: number;
  nonCompliantRecommendations: number;
  recommendationComplianceRate: number; // %
  investigationTimeMin: number | null;
  investigationTimeMax: number | null;
  investigationTimeAverage: number | null;
  decisionTimeMin: number | null;
  decisionTimeMax: number | null;
  decisionTimeAverage: number | null;
  workflowCompletedCases: number;
  interventionCases: number;
  mockVerificationCases: number;
  realWazuhVerificationCases: number;
}
