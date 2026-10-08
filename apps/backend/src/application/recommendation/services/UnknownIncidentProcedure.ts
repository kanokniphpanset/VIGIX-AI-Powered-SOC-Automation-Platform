import { RecommendationContextContainmentProcedure, RecommendationContextProcedureStep } from "../dto/RecommendationContextDto";

export const UNKNOWN_INCIDENT = "UNKNOWN_INCIDENT";

const check = (stepOrder: number, phase: string, title: string, objective: string, instruction: string, reason: string, expectedResult: string): RecommendationContextProcedureStep => ({
  stepOrder,
  phase,
  title,
  objective,
  items: [{ type: "CHECK", text: instruction, actionCode: null, condition: null, requiresApproval: false, approver: null }],
  reason,
  expectedResult,
  decisionRef: null,
  responsibleRole: "IR_TEAM",
  approvalRequired: false,
});

/**
 * Built-in, investigation-only procedure for an incident no attack-specific playbook covers. It deliberately holds
 * no ACTION and no MANUAL item: with this little knowledge the honest response is to validate the behaviour, collect
 * the missing evidence and reassess — not to invent containment, remediation or recovery. A dynamic response beyond
 * this needs retrieved knowledge (context.retrievedKnowledge), which the validator also requires the model to cite.
 */
export const UNKNOWN_INCIDENT_PROCEDURE: RecommendationContextContainmentProcedure = {
  procedureCode: UNKNOWN_INCIDENT,
  version: "1",
  objective: "Understand what the observed behaviour is before any containment is chosen.",
  strategy: "No attack-specific playbook matches this incident, so the response is investigation-first: validate the behaviour, collect the missing evidence, determine the affected asset and reassess the classification.",
  steps: [
    check(1, "VALIDATE", "Validate the Observed Behaviour", "Establish from the alert and its logs what actually happened.", "Review the alert, its raw log and the recorded evidence to describe the observed behaviour and decide whether it is malicious, suspicious or benign", "Without a matching playbook, containment must not be guessed from the alert title.", "The observed behaviour is described and classified as malicious, suspicious or benign."),
    check(2, "ASSESS", "Collect Missing Evidence", "Gather what is needed to classify the incident and find the affected asset.", "Collect the missing evidence (affected asset, account, process, network connections and surrounding events) and note which facts are still unknown", "The affected asset and the attacker's behaviour must be known before a response is chosen.", "The affected asset is identified and the missing evidence is listed."),
    check(3, "ASSESS", "Reassess Classification", "Re-evaluate the incident with the collected evidence.", "Reassess the incident type, severity and MITRE mapping with the collected evidence and, if an attack-specific playbook now applies, regenerate the recommendation", "A recommendation is only as specific as the classification it rests on.", "The incident is reclassified or kept unknown with a stated reason."),
  ],
  decisions: [],
  candidateActions: [],
  verification: { type: "NONE", queryTemplate: null, successCriteria: ["The behaviour is classified from evidence"], additionalChecks: [] },
};
