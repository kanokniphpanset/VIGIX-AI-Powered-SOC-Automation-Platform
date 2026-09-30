import { RecommendationContextDto, newStepOptions, targetableIocValues } from "../../application/recommendation/dto/RecommendationContextDto";

/**
 * RecommendationPromptBuilder — pure, deterministic serialization of a
 * RecommendationContextDto into a prompt string. Used only by
 * LlmRecommendationAgent. Does not call an LLM and does no reasoning of its
 * own — it only formats facts the backend already assembled. The prompt is a
 * guardrail aid; RecommendationValidator is the enforcement point.
 *
 * Response Process Recommendation v2 (Task 10.3): the model is told the
 * incident-level playbook the BACKEND selected, and for each Action that
 * playbook allows: the Action's own runbook procedure and the Policy result
 * (responsible role, approval). The model only expands the selected
 * Action(s) into concrete operational instructions — it never restates the
 * VIGIX Core Flow, never picks the playbook, role or approval requirement.
 */
export class RecommendationPromptBuilder {
  build(context: RecommendationContextDto): string {
    const lines: string[] = [];
    const playbook = context.playbook ?? null;
    const procedures = context.actionProcedures ?? [];

    lines.push("You are the VIGIX Incident Response Recommendation Agent.");
    lines.push("DO NOT repeat the VIGIX Core Flow.");
    lines.push("Expand only the selected response Action into concrete operational instructions for the responsible role.");
    lines.push(
      "Ground every instruction in the incident Evidence, the incident type, the severity and risk, the responsible role, the Action Catalog, the selected Playbook, the action-level Runbook and the Policy constraints given below."
    );
    lines.push("AI does not authorize, approve, execute, or bypass Policy.");
    lines.push("");
    lines.push("The VIGIX Core Flow (validate incident → assess containment need → select action → prepare response plan → approval → human execution → re-hunt/verification) is run by the platform itself.");
    lines.push("Never write steps or instructions for those phases: no \"validate the incident\", no \"monitor\", no \"re-hunt\", no \"request approval\", no \"close the incident\", no \"collect evidence\".");
    lines.push("");
    lines.push("Rules:");
    lines.push("1. One step = one Action from the Allowed Actions below, applied to ONE target.");
    lines.push("2. action, playbook and runbook must be copied exactly from the Allowed Actions block; never use any other code.");
    lines.push("3. target must be copied verbatim from the \"Targetable values\" list below, and must be the kind the Action operates on. Other IOCs are context only — never a target.");
    lines.push("4. Never invent an IOC, IP, domain, URL, hash, host, account, port, command, action, target or authorization. Do not write vendor-specific commands.");
    lines.push("5. responsibleRole must be exactly the Policy responsibleRole of that Action.");
    lines.push("6. Do not state that approval is waived, skipped, granted or automatic. Policy alone decides approval.");
    lines.push("7. instructions are the concrete, ordered operational steps for the responsible role, derived from the Action's runbook procedure and applied to THIS target and evidence. order starts at 1. At most 6 instructions per step, one short sentence each; expectedResult is a few words.");
    lines.push("8. verificationCriteria states how the responsible role confirms THIS action took effect on THIS target.");
    lines.push("9. evidenceRefs contains ONLY evidence ids shown below in square brackets — E<n> (evidence), I<n> (IOC) — or a listed MITRE technique id. Never write titles or values in evidenceRefs. Copy IOC values in text character for character — a changed digit is an invented IOC.");
    lines.push("10. Recommend only the Action(s) the evidence supports; several Actions are allowed when the evidence supports each of them.");
    lines.push("11. For a second or later investigation cycle, use only the latest investigation evidence.");
    lines.push("");

    lines.push(`Incident: ${context.incidentTitle} (status=${context.incidentStatus}, alertSeverity=${context.alertSeverity})`);
    lines.push(`Incident severity (analyst-validated classification; Policy decided roles/approval from it): ${context.severity}`);
    lines.push(`Incident type: ${context.incidentType ?? "(no incident-level playbook matched)"}`);
    lines.push(`Investigation number: ${context.investigationNumber}`);
    lines.push("");

    const linkedIocs = targetableIocValues(context);
    lines.push("IOCs:");
    if (context.iocs.length === 0) lines.push("  (none recorded)");
    for (const ioc of context.iocs) {
      const note = linkedIocs.has(ioc.iocValue)
        ? ioc.manual ? "added by an analyst" : "linked to evidence"
        : "CONTEXT ONLY — not linked to any evidence (e.g. the reporting agent's own address); NEVER a target, never block it";
      lines.push(`  - [${ioc.ref}] type=${ioc.iocType} value=${ioc.iocValue} source=${ioc.source} reputationScore=${ioc.reputationScore ?? "unknown"} (${note})`);
    }
    lines.push("");

    lines.push("MITRE mappings:");
    if (context.mitreMappings.length === 0) lines.push("  (none recorded)");
    for (const m of context.mitreMappings) {
      lines.push(`  - technique=${m.techniqueId} tactic=${m.tactic} confidence=${m.confidence ?? "unknown"}`);
    }
    lines.push("");

    lines.push(`Evidence (investigation #${context.investigationNumber}):`);
    if (context.evidence.length === 0) lines.push("  (none recorded)");
    for (const e of context.evidence) {
      const parts = [`type=${e.type}`, `source=${e.source}`, `origin=${e.origin}`, `time=${e.timestamp}`];
      if (e.host) parts.push(`host=${e.host}`);
      if (e.ruleId) parts.push(`rule=${e.ruleId}`);
      lines.push(`  - [${e.ref}] ${e.title} (${parts.join(", ")})${e.iocValues.length ? ` iocs=[${e.iocValues.join(", ")}]` : ""}`);
    }
    lines.push("");

    lines.push(`Affected hosts: ${context.affectedHosts.length ? context.affectedHosts.join(", ") : "(none recorded)"}`);
    lines.push("");

    // Only evidence-linked or analyst-added IOCs (and the affected hosts) may be contained.
    lines.push("Targetable values (the ONLY allowed step targets):");
    const targetable = context.iocs.filter((i) => linkedIocs.has(i.iocValue));
    if (targetable.length === 0 && context.affectedHosts.length === 0) lines.push("  (none)");
    for (const i of targetable) lines.push(`  - ${JSON.stringify(i.iocValue)} (${i.iocType})`);
    for (const h of context.affectedHosts) lines.push(`  - ${JSON.stringify(h)} (affected host)`);
    lines.push("");

    lines.push("AI analysis (automated interpretation — NOT evidence; never cite it in evidenceRefs):");
    if (!context.aiAnalysis) {
      lines.push("  (none recorded)");
    } else {
      lines.push(`  ${context.aiAnalysis.summary}`);
      for (const f of context.aiAnalysis.keyFindings) lines.push(`  - ${f}`);
    }
    lines.push("");

    if (playbook) {
      lines.push(`Selected Playbook (chosen by the backend — use exactly this code): ${playbook.code} "${playbook.name}" for incident type ${playbook.incidentType} (matched ${playbook.matchedTechniques.join(", ")})`);
      lines.push("  Response strategy:");
      for (const s of playbook.strategy) lines.push(`  ${s.stepOrder}. ${s.title}: ${s.description ?? ""}`);
    } else {
      lines.push("Selected Playbook: NONE — no incident-level playbook matches this incident; no response Action can be recommended.");
    }
    lines.push("");

    lines.push("Allowed Actions (the ONLY actions you may expand):");
    if (procedures.length === 0) lines.push("  (none)");
    for (const p of procedures) {
      lines.push(`  - action=${p.actionCode} (${p.actionName}, impact=${p.impactLevel}) playbook=${playbook?.code ?? "none"} runbook=${p.runbookCode ?? "none"}`);
      lines.push(
        `    Policy: responsibleRole=${p.policy.responsibleRole ?? "unknown"}, approvalRequired=${p.policy.approvalRequired}${p.policy.approvalRequired ? ` (approvalRole=${p.policy.approvalRole})` : ""}, reviewRequired=${p.policy.reviewRequired}${p.policy.reviewRole ? ` (reviewRole=${p.policy.reviewRole})` : ""}`
      );
      if (p.runbookObjective) lines.push(`    Runbook objective: ${p.runbookObjective}`);
      p.procedure.forEach((step, i) => lines.push(`    Runbook procedure ${i + 1}. ${step}`));
      for (const v of p.verificationCriteria) lines.push(`    Runbook verification: ${v}`);
    }
    lines.push("");

    // SOC guidance set before this Recommendation (case > group policy). The allowed list above already reflects it.
    const guidance = context.socGuidance;
    if (guidance && guidance.source !== "PLAYBOOK") {
      lines.push(`SOC response guidance (${guidance.source === "CASE" ? "set by the SOC for this incident" : "group policy for this incident type and severity"}) — follow it:`);
      lines.push(`  Only these actions were chosen by the SOC: ${guidance.allowedActions.join(", ") || "(none)"}`);
      if (guidance.instructions) for (const l of guidance.instructions.split("\n").filter((x) => x.trim())) lines.push(`  Instruction: ${l.trim()}`);
      lines.push("  The guidance narrows what to recommend; it never overrides the evidence rules or the Policy values above.");
      lines.push("");
    }

    // Earlier Recommendations of this incident: the new one must not be a repeat (RecommendationValidator NO_NEW_STEP).
    const previous = context.previousSteps ?? [];
    if (previous.length) {
      lines.push("Earlier Recommendations of this incident already proposed these Action + target pairs:");
      for (const s of previous) lines.push(`  - Recommendation #${s.recommendationNumber} (investigation #${s.investigationNumber}): ${s.actionCode} -> ${JSON.stringify(s.target)}`);
      lines.push("  This Recommendation MUST include at least one step whose Action + target pair is NOT in that list. The same Action on a different target counts as new; an earlier pair may be repeated only alongside a new one.");
      const options = newStepOptions(context);
      if (options?.length) lines.push(`  Pairs not proposed before that the evidence supports: ${options.map((o) => `${o.actionCode} -> ${JSON.stringify(o.target)}`).join(", ")}`);
      lines.push("");
    }

    lines.push(
      "Respond with ONE JSON object: { summary: string, steps: [{ stepOrder, action, objective, responsibleRole, target, reason, evidenceRefs, instructions: [{ order, instruction, target, expectedResult }], playbook, runbook, verificationCriteria, expectedResult, missingEvidence, confidence, requiresApprovalSuggested }] }"
    );
    lines.push("summary describes the selected Action(s) and why, in one or two sentences — not the Core Flow.");
    lines.push("requiresApprovalSuggested must equal the Policy approvalRequired value of that Action. confidence is 0-1.");

    return lines.join("\n");
  }
}
