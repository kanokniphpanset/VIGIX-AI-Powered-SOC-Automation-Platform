import { NotificationEvent, ResponseProcessStep } from "../events/NotificationEvent";

/**
 * NotificationTemplateRenderer — ports the exact templates already
 * designed and approved in docs/architecture/notification-event-contract.md
 * §6/§9 (previously rendered inside the n8n Code node) into the backend.
 * Pure functions, no I/O — content is not redesigned here, only relocated.
 */

export interface RenderedEmail {
  subject: string;
  body: string;
}

function renderStepsRequiringApproval(steps: NotificationEvent["recommendation"] extends undefined ? never : NonNullable<NotificationEvent["recommendation"]>["stepsRequiringApproval"]): string {
  if (!steps || steps.length === 0) return "  (none)";
  return steps
    .map((s) => {
      const actionPart = s.action ? `${s.action.name} (${s.action.code})` : "no catalog action";
      const targetPart = s.target ? ` → ${s.target}` : "";
      const runbookPart = s.runbook ? ` [${s.runbook.code}]` : "";
      return `  - ${s.title} — ${actionPart}${targetPart}${runbookPart}`;
    })
    .join("\n");
}

/** Same plain-text (box-drawing) rendering used for Email on every event,
 * and reused as the fallback body for Discord/Telegram on the 6 events
 * that don't have a bespoke channel-specific renderer yet (see below). */
function renderProcessStep(s: ResponseProcessStep): string[] {
  return [
    `${s.stepOrder}. ${s.title}${s.target ? ` — target: ${s.target}` : ""}`,
    ...(s.objective ? [`   Objective: ${s.objective}`] : []),
    `   Why: ${s.reason}`,
    ...s.instructions.map((i) => `   ${s.stepOrder}.${i.order} ${i.instruction}${i.target ? ` [${i.target}]` : ""}${i.expectedResult ? ` -> expected: ${i.expectedResult}` : ""}${i.verify ? ` -> verify: ${i.verify}` : ""}${i.preconditions?.length ? ` -> before: ${i.preconditions.join(" / ")}` : ""}${i.rollback ? ` -> rollback: ${i.rollback}` : ""}`),
    ...(s.expectedResult ? [`   Expected result: ${s.expectedResult}`] : []),
    ...(s.verificationCriteria ? [`   Verification / re-hunt: ${s.verificationCriteria}`] : []),
  ];
}

export function renderEmail(event: NotificationEvent): RenderedEmail {
  switch (event.eventType) {
    case "APPROVAL_REQUIRED": {
      const subject = `[VIGIX][${event.incident.priority}] Approval Required — ${event.incident.id}`;
      const body = [
        "VIGIX Incident Response Notification",
        "",
        "Incident",
        "──────────────",
        `Incident ID:  ${event.incident.id}`,
        `Title:        ${event.incident.title}`,
        `Severity:     ${event.incident.priority}`,
        "",
        "Recommendation",
        "──────────────",
        `Recommendation: ${event.recommendation!.id} (#${event.recommendation!.recommendationNumber})`,
        `Summary: ${event.recommendation!.summary}`,
        "",
        "Steps requiring approval:",
        renderStepsRequiringApproval(event.recommendation!.stepsRequiringApproval),
        "",
        "Approval",
        "──────────────",
        `Required Role: ${event.approval!.role}`,
        `Reason: ${event.approval!.reason}`,
        "",
        "Please review and make a decision in VIGIX.",
        "",
        "Open Approval:",
        event.links.approval || "(not available)",
      ].join("\n");
      return { subject, body };
    }
    case "APPROVAL_APPROVED": {
      const subject = `[VIGIX] Approved — respond to ${event.incident.id}`;
      const process = event.recommendation!.responseProcess;
      const body = [
        "VIGIX Incident Response Notification — APPROVED: Response Recommendation Process",
        "",
        `Incident:  ${event.incident.id} — ${event.incident.title}`,
        `Severity:  ${process?.severity ?? event.incident.priority}`,
        "",
        "Situation summary",
        "──────────────",
        event.recommendation!.summary,
        ...(process?.evidence.length ? ["", "Evidence", "──────────────", ...process.evidence.map((e) => `  - ${e}`)] : []),
        "",
        "Approval",
        "──────────────",
        "Status: APPROVED",
        `Decided By: ${event.approval!.decidedBy ?? "unknown"}`,
        `Comment: ${event.approval!.comment ?? "(none)"}`,
        ...(process?.steps.length ? ["", "Recommended response (execute in order)", "──────────────", ...process.steps.flatMap(renderProcessStep)] : []),
        "",
        "Next steps for IR",
        "──────────────",
        "1. Open the Response Ticket and press Start response (status READY_FOR_EXECUTION -> IN_PROGRESS).",
        "2. Carry out the instructions above on the named target(s); VIGIX executes nothing on any system.",
        "3. Mark eradicated when done (-> AWAITING_REHUNT), then run Re-hunt: VIGIX queries Wazuh again for the IOCs/hosts.",
        "4. NO_MATCH -> RESOLVED. MATCH -> NOT_RESOLVED: a new investigation cycle opens (max 3 rounds, then ESCALATED).",
        "",
        "Open Response Ticket:",
        event.links.ticket || "(not available)",
        "Approval Queue:",
        event.links.approval || "(not available)",
      ].join("\n");
      return { subject, body };
    }
    case "APPROVAL_REJECTED": {
      const subject = `[VIGIX] Rejected — ${event.incident.id}`;
      const body = [
        "VIGIX Incident Response Notification",
        "",
        `Incident: ${event.incident.id} — ${event.incident.title}`,
        `Recommendation: ${event.recommendation!.id} — ${event.recommendation!.summary}`,
        "",
        "Approval",
        "──────────────",
        "Status: REJECTED",
        `Decided By: ${event.approval!.decidedBy ?? "unknown"}`,
        `Reason for rejection: ${event.approval!.comment ?? "(none)"}`,
        "",
        "Please review the recommendation and evidence, and consider next steps.",
        "",
        "Open Approval:",
        event.links.approval || "(not available)",
      ].join("\n");
      return { subject, body };
    }
    case "RESPONSE_ASSIGNED": {
      const t = event.ticket!;
      const subject = `[VIGIX] Response Ticket awaiting IR decision — ${t.id}`;
      const body = [
        "VIGIX Incident Response Notification",
        "",
        "Incident",
        "──────────────",
        `Incident ID: ${event.incident.id}`,
        `Severity: ${event.incident.priority}`,
        "",
        "Ticket",
        "──────────────",
        `Ticket ID: ${t.id}`,
        `Action: ${t.action ? `${t.action.name} (${t.action.code})` : "(none)"}`,
        `Target: ${t.target ?? "(none)"}`,
        t.runbook ? `Runbook: ${t.runbook.code}` : null,
        `Assigned Team: ${t.assignedRole}`,
        `Status: ${t.status}`,
        "",
        "SOC sent this recommendation to IR. Open the ticket, review the incident, evidence, AI analysis and proposed",
        "actions, then APPROVE or REJECT it (a note is required). Nothing is executed before an IR approval.",
        "",
        "Open Response Ticket:",
        event.links.ticket || "(not available)",
      ]
        .filter((l): l is string => l !== null)
        .join("\n");
      return { subject, body };
    }
    case "RESPONSE_COMPLETED": {
      const t = event.ticket!;
      const subject = `[VIGIX] Response Completed — ${t.id}`;
      const body = [
        "VIGIX Incident Response Notification",
        "",
        `Incident: ${event.incident.id}`,
        `Ticket: ${t.id}`,
        `Action: ${t.action ? t.action.name : "(none)"}`,
        `Target: ${t.target ?? "(none)"}`,
        "",
        "Status: COMPLETED",
        "",
        "Next Step: Verification required before this incident can be considered resolved.",
        "",
        "Open Response Ticket:",
        event.links.ticket || "(not available)",
      ].join("\n");
      return { subject, body };
    }
    case "VERIFICATION_NOT_RESOLVED": {
      const v = event.verification!;
      const subject = `[VIGIX] Verification NOT RESOLVED — ${event.incident.id}`;
      const body = [
        "VIGIX Incident Response Notification",
        "",
        `Incident: ${event.incident.id} — ${event.incident.title}`,
        "",
        "Verification Result: NOT RESOLVED",
        "──────────────",
        `Threat Contained: ${v.threatContained}`,
        `Spread Detected: ${v.spreadDetected}`,
        `IOC Recurrence: ${v.iocRecurrence}`,
        `Matching Events: ${v.matchingEvents ?? "unknown"}`,
        `Notes: ${v.notes ?? "(none)"}`,
        "",
        "This incident is not yet resolved. Review the evidence and continue investigation.",
      ].join("\n");
      return { subject, body };
    }
    case "INVESTIGATION_REOPENED": {
      const subject = `[VIGIX] Investigation #${event.incident.investigationNumber} Reopened — ${event.incident.id}`;
      const body = [
        "VIGIX Incident Response Notification",
        "",
        `Incident: ${event.incident.id} — ${event.incident.title}`,
        "",
        `Investigation #${event.incident.investigationNumber} has been opened for this incident,`,
        "based on verification evidence indicating the threat is not fully contained.",
        "",
        "A new recommendation will be generated for this investigation cycle.",
      ].join("\n");
      return { subject, body };
    }
  }
}

/** Discord/Telegram presentation. Only RESPONSE_ASSIGNED has a bespoke
 * renderer per channel (matches what was already live-tested via n8n in
 * N3.5) — the other 6 events reuse the plain Email body as an honest
 * fallback until their own channel-specific templates are written. */
export function renderForChannel(event: NotificationEvent, channel: "discord" | "telegram"): string {
  const { body } = renderEmail(event);

  if (event.eventType === "RESPONSE_ASSIGNED") {
    const t = event.ticket!;
    const actionText = t.action ? `${t.action.name} (${t.action.code})` : "(none)";
    const targetText = t.target ? ` → ${t.target}` : "";

    if (channel === "discord") {
      return [
        `**[VIGIX] Response Assigned — ${t.id}**`,
        `Incident \`${event.incident.id}\` · Severity **${event.incident.priority}**`,
        `Action: **${actionText}**${targetText ? ` → \`${t.target}\`` : ""}`,
        `Assigned: ${t.assignedRole} · Status: ${t.status}`,
        `<${event.links.ticket || ""}>`,
      ].join("\n");
    }
    if (channel === "telegram") {
      return [
        "🔔 VIGIX — Response Assigned",
        `Ticket: ${t.id}`,
        `Incident: ${event.incident.id} (${event.incident.priority})`,
        `Action: ${actionText}${targetText}`,
        `Team: ${t.assignedRole} | Status: ${t.status}`,
        event.links.ticket || "",
      ].join("\n");
    }
  }

  return body;
}
