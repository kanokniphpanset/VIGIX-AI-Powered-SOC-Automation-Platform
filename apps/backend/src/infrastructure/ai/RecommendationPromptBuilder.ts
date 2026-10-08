import { RecommendationContextDto, isRecommendable, newStepOptions, noveltyHistory, targetableIocValues } from "../../application/recommendation/dto/RecommendationContextDto";

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
 *
 * Attack-specific containment procedure: when the context carries one (YAML knowledge), it is the primary strategy
 * source and the model returns ordered CHECK / ACTION / MANUAL steps derived from it, preserving every condition.
 * Without a procedure the v2 action-only rules apply unchanged.
 */
export class RecommendationPromptBuilder {
  /** Narration-only prompt for an APPROVED subtype plan: the model may phrase a summary, never choose or change anything. */
  private narration(context: RecommendationContextDto): string {
    const plan = context.subtypePlan!;
    return [
      "You are the VIGIX Incident Response Recommendation Agent. The response plan below was ALREADY decided by deterministic backend checks (evidence, targets, policy, authority).",
      "Your only task: write ONE short Thai sentence in the JSON field `summary` describing what the plan asks the responders to do. Do not add, remove, reorder or change any action, target, host, IP, hash, account or scope. Do not claim anything was executed or contained. Do not mention identifiers, scores or confidence.",
      "Return JSON {\"summary\": string, \"steps\": []}. Do not output any step.",
      `Incident: ${context.incidentTitle}`,
      "Approved plan:",
      ...plan.steps.map((s, i) => `${i + 1}. ${s.title}${s.target ? ` [target: ${s.target}]` : ""}`),
      ...(plan.missingInfo.length ? ["Still missing (do not guess):", ...plan.missingInfo.map((m) => `- ${m}`)] : []),
    ].join("\n");
  }

  build(context: RecommendationContextDto): string {
    if (context.subtypePlan) return this.narration(context);
    const lines: string[] = [];
    const playbook = context.playbook ?? null;
    const procedures = context.actionProcedures ?? [];

    const procedure = context.containmentProcedure ?? null;
    lines.push("You are the VIGIX Incident Response Recommendation Agent.");
    if (procedure) {
      lines.push("Act as an IR analyst designing the containment strategy for THIS incident: what to check, which actions to take in which order, under which conditions, and how containment is verified.");
      lines.push("Use the attack-specific containment procedure below as the primary strategy source.");
      lines.push("Do not invent containment steps that are not supported by the provided Knowledge.");
      lines.push("A recommendation may contain CHECK, ACTION, and MANUAL steps.");
      lines.push("ACTION steps must use an available catalog action.");
      lines.push("CHECK steps are investigation/decision steps and must not be represented as executable actions.");
      lines.push("MANUAL steps represent controls that are not currently executable by VIGIX.");
      lines.push("Preserve conditions from the procedure and policy.");
      lines.push("Do not execute or approve actions automatically.");
    } else {
      lines.push("DO NOT repeat the VIGIX Core Flow.");
      lines.push("Expand only the selected response Action into concrete operational instructions for the responsible role.");
    }
    lines.push(
      "Ground every instruction in the incident Evidence, the incident type, the severity and risk, the responsible role, the Action Catalog, the selected Playbook, the action-level Runbook and the Policy constraints given below."
    );
    lines.push("AI does not authorize, approve, execute, or bypass Policy.");
    lines.push("");
    if (procedure) {
      lines.push("The platform itself creates Response Tickets, requests approval and closes the incident — never write steps for those. Checking, monitoring and verifying ARE part of a containment procedure and belong in CHECK steps.");
    } else {
      lines.push("The VIGIX Core Flow (validate incident → assess containment need → select action → prepare response plan → approval → human execution → re-hunt/verification) is run by the platform itself.");
      lines.push("Never write steps or instructions for those phases: no \"validate the incident\", no \"monitor\", no \"re-hunt\", no \"request approval\", no \"close the incident\", no \"collect evidence\".");
    }
    lines.push("");
    lines.push("Rules:");
    lines.push("Do not infer SOURCE from an IP merely because it is an IP. ACT-BLOCK-SOURCE-IP and ACT-RATE-LIMIT-SOURCE require an explicit source role; ACT-BLOCK-DESTINATION-IP requires an explicit destination role. Unknown or conflicting IP roles are not executable targets. Preserve exact URL/domain/IP/hash/account/host types and evidence linkage; do not extract a domain from a URL unless a separate domain IOC is supplied. Use only available catalog/playbook/policy-compatible Actions. Use CHECK to obtain missing evidence, MANUAL only for knowledge-defined non-executable controls with their conditions/approval, and ACTION only with a compatible recorded target. A CHECK does not confirm its own result: preserve the human-confirmed condition. Never claim containment has succeeded before verification/re-hunt.");
    if (procedure) {
      lines.push("0. Follow the procedure's step order. Choose the steps the evidence supports — do NOT output every possible action. An ACTION whose condition the evidence does not support yet stays out, or comes after the CHECK step that decides it.");
      lines.push("0a. type=CHECK: an investigation / decision step from a procedure CHECK item. action=null, runbook=null, procedureStep = the procedure step number it comes from. Never phrase a catalog Action as a CHECK.");
      lines.push("0b. type=MANUAL: a procedure MANUAL item only (a control VIGIX cannot execute). action=null, runbook=null, procedureStep required. When the item says \"requires <who> approval\", requiresApprovalSuggested=true and say who approves.");
      lines.push("0c. type=ACTION: rules 1-10 below apply. Copy the Action's condition from the procedure into condition (you may make it specific to this evidence, never drop it). procedureStep = the procedure step that lists the Action.");
      const hasActions = procedure.steps.some((s) => s.items.some((i) => i.type === "ACTION"));
      lines.push(hasActions
        ? "0d. At least one ACTION step. CHECK / MANUAL steps may have target=null; when they name a target it must be a recorded IOC or affected host."
        : "0d. No ACTION step is offered for this incident (the evidence does not support one yet): the response is investigation-first. CHECK / MANUAL steps may have target=null; when they name a target it must be a recorded IOC or affected host.");
      lines.push("0g. The response must be specific to THIS attack and THIS evidence. The response phases (validate, contain, investigate, remediate, recover, monitor) are a reasoning framework, not a checklist: never add a step, phase or control that belongs to another attack type, never force a fixed number or order of steps, and never state as fact something the evidence has not established (a compromised account, a data breach, a successful injection, malicious execution). Use \"if / when / whether\" for what is still to be confirmed.");
      lines.push("0h. Optional per step: phase (the phase of the procedure step it comes from), status (CONFIRMED only with cited evidence and no open condition; CONDITIONAL needs condition; otherwise SUPPORTED or POSSIBLE), priority, knowledgeRefs (retrieved knowledge ids).");
      if (context.investigationOnly) {
        lines.push("0i. NO attack-specific playbook applies (UNKNOWN_INCIDENT). Use only the investigation steps below and, if listed, the retrieved knowledge items (cite their ids in knowledgeRefs; knowledgeRefs-grounded steps have procedureStep=null). Never output an ACTION and never invent containment, remediation, credential rotation or recovery.");
      }
      lines.push("0e. CHECK / MANUAL steps: playbook = the selected playbook code; responsibleRole = the procedure step's role; evidenceRefs may be empty; instructions are the concrete checks / manual tasks for THIS incident; verificationCriteria states what result completes the step.");
      const verify = procedure.steps.find((s) => s.phase === "VERIFY");
      if (verify) lines.push(`0f. The LAST step is a CHECK from procedure step ${verify.stepOrder} (${verify.title}); its verificationCriteria lists the success criteria below — containment is not complete without it.`);
    }
    lines.push("1. One ACTION step = one Action from the Allowed Actions below, applied to ONE target.");
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
    if (context.rehunt) {
      lines.push(`Post-response re-hunt: verification=${context.rehunt.verificationId}, source=${context.rehunt.source}, previous investigation=${context.rehunt.verifiedInvestigationNumber}, result=${context.rehunt.result}, spreadDetected=${context.rehunt.spreadDetected}, matchingEvents=${context.rehunt.matchingEvents}, truncated=${context.rehunt.truncated}`);
      lines.push(`Original hosts: ${JSON.stringify(context.rehunt.originalHosts)}; newly affected hosts: ${JSON.stringify(context.rehunt.newHosts)}`);
    }
    if (context.spreadResponse) {
      lines.push(`SPREAD RESPONSE policies: ${context.spreadResponse.policies.join(", ")}`);
      for (const note of context.spreadResponse.instructions) lines.push(`  - ${note}`);
      lines.push("For EVERY newly affected host with an eligible action, include an ACTION on that host or on a recorded IOC linked to that host's current-cycle evidence. Do not respond only to the original host. Every action still needs its runbook, evidence, conditions and IR decision.");
      lines.push("When using a shared IOC rather than the host as target, the instructions must explicitly name each newly affected host the control protects. Prior-cycle IOC actions may be proposed again for this verified new scope; a duplicate within the current cycle remains prohibited.");
      lines.push(`Hosts requiring additional evidence before an action: ${JSON.stringify(context.spreadResponse.uncoveredHosts)}. Never invent missing targets. Include checks for any remaining scope; a truncated re-hunt does not establish the full spread or successful containment.`);
      lines.push("Finish by re-hunting the original and newly affected hosts plus the recorded shared indicators. No recurrence and no newly affected hosts are required before claiming containment.");
    }
    lines.push("");

    const linkedIocs = targetableIocValues(context);
    lines.push("IOCs:");
    if (context.iocs.length === 0) lines.push("  (none recorded)");
    for (const ioc of context.iocs) {
      const note = linkedIocs.has(ioc.iocValue)
        ? ioc.manual ? "added by an analyst" : "linked to evidence"
        : "CONTEXT ONLY — not linked to any evidence (e.g. the reporting agent's own address); NEVER a target, never block it";
      lines.push(`  - [${ioc.ref}] type=${ioc.iocType} value=${ioc.iocValue} source=${ioc.source} reputationScore=${ioc.reputationScore ?? "unknown"}${ioc.networkRole ? ` role=${ioc.networkRole}` : ""} (${note})`);
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
    for (const i of targetable) lines.push(`  - ${JSON.stringify(i.iocValue)} (${i.iocType}${i.networkRole ? `, ${i.networkRole} IP of the alert` : ""})`);
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
      // The YAML containment procedure is the source of truth for strategy; the playbook's own step list is shown only
      // when no procedure exists, so the model never gets two competing strategies.
      if (!procedure) {
        lines.push("  Response strategy:");
        for (const s of playbook.strategy) lines.push(`  ${s.stepOrder}. ${s.title}: ${s.description ?? ""}`);
      } else {
        lines.push("  Response strategy: see the containment procedure below.");
      }
    } else {
      lines.push("Selected Playbook: NONE — no incident-level playbook matches this incident; no response Action can be recommended.");
    }
    lines.push("");

    if (context.signals?.length) {
      lines.push(`Evidence signals present (derived from recorded evidence only): ${context.signals.join(", ")}`);
    }
    for (const t of context.transitions ?? []) {
      if (t.because.length) lines.push(`Response branch opened by the evidence: ${t.from} -> ${t.to} (procedure step ${t.stepOrder}; because ${t.because.join(", ")}). Continue the investigation as ${t.to} as well.`);
    }
    if (context.retrievedKnowledge?.length) {
      lines.push("Retrieved response knowledge (the only knowledge you may cite):");
      for (const k of context.retrievedKnowledge) lines.push(`  - [${k.ref}] ${k.kind} (${k.source}, phase=${k.phase}) ${k.title}: ${k.guidance}${k.requiresApproval ? " | requires approval" : ""}`);
    }
    if (procedure) {
      const allowed = new Set(procedures.map((p) => p.actionCode));
      lines.push(`Containment procedure ${procedure.procedureCode} (v${procedure.version}) — primary strategy source:`);
      lines.push(`  Objective: ${procedure.objective}`);
      lines.push(`  Strategy: ${procedure.strategy}`);
      for (const step of procedure.steps) {
        lines.push(`  Step ${step.stepOrder} [${step.phase}] ${step.title} — ${step.objective} (role=${step.responsibleRole})`);
        for (const item of step.items) {
          if (item.type === "ACTION") {
            const p = procedures.find((x) => x.actionCode === item.actionCode);
            const availability = !allowed.has(item.actionCode!)
              ? "NOT AVAILABLE for this incident (not allowed by the playbook / SOC guidance) — do not use"
              : p && !isRecommendable(p)
                ? `NOT RECOMMENDABLE in this cycle (${p.applicable === false ? "not applicable" : `missing evidence: ${p.evidence?.missing.join(", ")}`}) — do not use`
                : "available";
            lines.push(`    - ACTION ${item.actionCode}: ${item.text} | condition: ${item.condition ?? "none"} | ${availability}`);
          } else if (item.type === "MANUAL") {
            lines.push(`    - MANUAL: ${item.text} | condition: ${item.condition ?? "none"}${item.approver ? ` | requires ${item.approver} approval` : ""}`);
          } else {
            lines.push(`    - CHECK: ${item.text}`);
          }
        }
        const decision = procedure.decisions.find((d) => d.id === step.decisionRef);
        if (decision) lines.push(`    Decision ${decision.id} (made by people, never by AI): ${decision.question} -> ${decision.options.map((o) => `${o.value}: ${o.leadsTo}`).join("; ")}`);
      }
      lines.push(`  Containment is verified when: ${procedure.verification.successCriteria.join("; ") || "(no criteria recorded)"}`);
      lines.push("");
    }

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
    const previous = noveltyHistory(context);
    if (previous.length) {
      lines.push("Earlier Recommendations of this incident already proposed these Action + target pairs:");
      for (const s of previous) lines.push(`  - Recommendation #${s.recommendationNumber} (investigation #${s.investigationNumber}): ${s.actionCode} -> ${JSON.stringify(s.target)}`);
      lines.push("  This Recommendation MUST include at least one step whose Action + target pair is NOT in that list. The same Action on a different target counts as new; an earlier pair may be repeated only alongside a new one.");
      const options = newStepOptions(context);
      if (options?.length) lines.push(`  Pairs not proposed before that the evidence supports: ${options.map((o) => `${o.actionCode} -> ${JSON.stringify(o.target)}`).join(", ")}`);
      lines.push("");
    }

    if (procedure) {
      lines.push(
        "Respond with ONE JSON object: { summary: string, steps: [{ stepOrder, type: \"CHECK\"|\"ACTION\"|\"MANUAL\", action, condition, procedureStep, objective, responsibleRole, target, reason, evidenceRefs, instructions: [{ order, instruction, target, expectedResult }], playbook, runbook, verificationCriteria, expectedResult, missingEvidence, confidence, requiresApprovalSuggested, phase?, status?, priority?, knowledgeRefs? }] }"
      );
      lines.push("summary states the containment objective and strategy for THIS incident in one or two sentences.");
    } else {
      lines.push(
        "Respond with ONE JSON object: { summary: string, steps: [{ stepOrder, action, objective, responsibleRole, target, reason, evidenceRefs, instructions: [{ order, instruction, target, expectedResult }], playbook, runbook, verificationCriteria, expectedResult, missingEvidence, confidence, requiresApprovalSuggested }] }"
      );
      lines.push("summary describes the selected Action(s) and why, in one or two sentences — not the Core Flow.");
    }
    lines.push("requiresApprovalSuggested must equal the Policy approvalRequired value of that Action. confidence is 0-1.");

    return lines.join("\n");
  }
}
