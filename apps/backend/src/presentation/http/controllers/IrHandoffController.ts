import { Request, Response } from "express";
import { z } from "zod";
import { INotificationChannelAdapter } from "../../../application/notification/ports/INotificationChannelAdapter";
import { IRoleEmailResolver } from "../../../application/notification/services/RoleEmailDirectory";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

const line = z.string().trim().min(1).max(300);

const HandoffSchema = z
  .object({
    incidentId: line,
    title: line,
    severity: line,
    category: line.optional(),
    asset: line.optional(),
    description: z.string().trim().max(2000).optional(),
    recommendation: z.string().trim().max(2000).optional(),
    mitre: z.array(line).max(20).optional(),
    iocs: z.array(line).max(30).optional(),
    note: z.string().trim().max(1000).optional(),
    sla: z
      .object({
        priority: line.optional(),
        firstResponseMinutes: z.number().int().min(0).max(525600).optional(),
        resolutionMinutes: z.number().int().min(0).max(525600).optional(),
        firstResponseDueAt: z.string().datetime().optional(),
        resolutionDueAt: z.string().datetime().optional(),
        status: line.optional(),
      })
      .strict()
      .optional(),
    incidentUrl: z.string().url().max(500).optional(),
  })
  .strict();

/**
 * IrHandoffController — SOC hands an investigated incident to the IR Team by
 * email. Delivery-only: it changes no Incident/Approval/Response state and
 * the recipient is always the IR_TEAM address configured by an admin in
 * Settings (else the server's IR_TEAM_EMAIL), never caller-supplied.
 */
export class IrHandoffController {
  handoff: (req: Request, res: Response) => Promise<void>;

  constructor(
    private readonly emailAdapter: INotificationChannelAdapter,
    private readonly roleEmail: IRoleEmailResolver
  ) {
    this.handoff = async (req, res) => {
      const parsed = HandoffSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: "VALIDATION_ERROR", issues: parsed.error.issues });
        return;
      }
      const irTeamEmail = (await this.roleEmail.resolve(req.user?.tenantId ?? DEFAULT_TENANT_ID, "IR_TEAM")).email;
      if (!irTeamEmail) {
        res.status(400).json({ error: "IR_TEAM_EMAIL_NOT_CONFIGURED", message: "No IR_TEAM email is set in Settings or on the server." });
        return;
      }
      if (!this.emailAdapter.isConfigured()) {
        res.status(400).json({ error: "CHANNEL_NOT_CONFIGURED", channel: "email", message: "Email delivery is not configured (EMAIL_HOST/EMAIL_FROM)." });
        return;
      }

      const d = parsed.data;
      const list = (items?: string[]) => (items && items.length ? items.map((i) => `  - ${i}`).join("\n") : "  (none)");
      const mins = (m?: number) => (m === undefined ? "-" : m < 60 ? `${m} min` : m % 60 === 0 ? `${m / 60} hr` : `${Math.floor(m / 60)} hr ${m % 60} min`);
      const due = (iso?: string) => (iso ? `${iso} (UTC)` : "-");
      const sla = d.sla;
      const body = [
        `Incident ${d.incidentId} has been handed over to the IR Team for response.`,
        "",
        `Title: ${d.title}`,
        `Severity: ${d.severity}`,
        `Category: ${d.category ?? "-"}`,
        `Asset: ${d.asset ?? "-"}`,
        "",
        ...(sla
          ? [
              "SLA:",
              `  Priority: ${sla.priority ?? "-"}`,
              `  First Response SLA: ${mins(sla.firstResponseMinutes)}`,
              `  Resolution SLA: ${mins(sla.resolutionMinutes)}`,
              `  First Response Due: ${due(sla.firstResponseDueAt)}`,
              `  Resolution Due: ${due(sla.resolutionDueAt)}`,
              `  SLA Status: ${sla.status ?? "-"}`,
              "",
            ]
          : []),
        "Description:",
        d.description ?? "-",
        "",
        "Recommended response (SOC analysis, advisory only):",
        d.recommendation ?? "-",
        "",
        "MITRE ATT&CK:",
        list(d.mitre),
        "",
        "IOCs:",
        list(d.iocs),
        ...(d.note ? ["", "SOC note:", d.note] : []),
        ...(d.incidentUrl ? ["", "Review the incident in VIGIX (Investigation, evidence, IOC, recommendation):", d.incidentUrl] : []),
        "",
        `Handed over by: ${req.user?.role ?? "unknown"} (user ${req.user?.id ?? "unknown"})`,
      ].join("\n");

      const subject = `[VIGIX] IR handoff: ${d.incidentId} (${d.severity}) - ${d.title}`.replace(/[\r\n]+/g, " ").slice(0, 200);
      const outcome = await this.emailAdapter.send({ recipient: irTeamEmail, subject, body });
      res.status(outcome.status === "SENT" ? 200 : 502).json({ ...outcome, recipient: irTeamEmail });
    };
  }
}
