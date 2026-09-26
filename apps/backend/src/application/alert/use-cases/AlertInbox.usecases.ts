import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { Alert } from "../../../domain/alert/entities/Alert.entity";
import { AlertSummary, summarizeAlert } from "../../../domain/alert/alertSummary";
import { extractAlertIocs } from "../../../domain/investigation/alertIocs";
import { Result } from "../../../shared/result/Result";
import { IAlertScenarioRepository } from "../../../domain/alert/repositories/IAlertScenarioRepository";
import { ATTACK_SCENARIOS, AttackScenario, findAttackScenario } from "../../../domain/alert/attackScenarios";
import {
  AlertDisplayState,
  AlertWorkflowState,
  INBOX_SORTS,
  InboxSort,
  InboxStatus,
  OPEN_WORKFLOW_STATES,
  SlaMinutesBySeverity,
  SlaStatus,
  displayState,
  inSocWorkflow,
  isInboxStatus,
  slaDueAt,
  slaStatus,
} from "../../../domain/alert/triageWorkflow";
import { IAlertInboxQuery } from "../ports/IAlertInboxQuery";

/**
 * Alert Inbox read models: the SOC review queue (MEDIUM / HIGH / CRITICAL only — LOW alerts are outside the SOC
 * workflow). Read-only — nothing here decides, links or changes an alert. There is no alert owner or claim.
 * The list is a database query (IAlertInboxQuery): filters, SLA-urgency ordering and pagination run in SQL, so every
 * alert is reachable however old it is. Wazuh fields come from the stored raw payload (summarizeAlert) as received;
 * a missing field stays null (the UI shows "Not available"), never a guessed value.
 */

export interface InboxIncidentRef {
  id: string;
  title: string;
  status: string;
  priority: string;
}

export interface InboxAlertItem {
  id: string;
  externalAlertId: string;
  siemSource: string;
  severity: string;
  /** Legacy alert status (received / escalated / closed / monitoring), kept for existing consumers. */
  status: string;
  receivedAt: string;
  summary: AlertSummary;
  /** Wazuh rule.firedtimes as received (null when absent). */
  firedTimes: number | null;
  /** Canonical SOC workflow (stored) and its display form. */
  workflowState: AlertWorkflowState;
  displayState: AlertDisplayState;
  /** SOC can still decide it (open, no incident, MEDIUM / HIGH / CRITICAL). */
  actionable: boolean;
  /** Outcome: FALSE_POSITIVE / INFORMATIONAL (closed), ESCALATED when it became an incident, MONITOR (legacy), else null. */
  disposition: "FALSE_POSITIVE" | "INFORMATIONAL" | "MONITOR" | "ESCALATED" | null;
  reviewAt: string | null;
  monitorReason: string | null;
  closedAt: string | null;
  /** Triage SLA from Policy (TRIAGE_SLA); null when Policy sets no target for this severity. */
  slaDueAt: string | null;
  slaStatus: SlaStatus | null;
  /** Minutes since the alert was received. */
  ageMinutes: number;
  incident: InboxIncidentRef | null;
  /** Analyst-set lab test-scenario label (VIGIX metadata), or null. */
  scenario: AttackScenario | null;
  /** Latest SOC triage record (history), or null. */
  triage: { disposition: string; note: string | null; triagedBy: string; triagedAt: string } | null;
}

export interface AlertInboxFilters {
  /** needs-review | in-incident | closed | all (default) */
  status?: string;
  search?: string;
  severity?: string;
  source?: string;
  /** "linked" | "unlinked" */
  incident?: string;
  mitre?: string;
  /** Scenario attack type, e.g. "SSH Brute Force" (exact, case-insensitive). */
  attackType?: string;
  /** Scenario id (ATK-01..ATK-10) or case name (exact, case-insensitive). */
  scenario?: string;
  /** Wazuh agent (host) name (exact, case-insensitive). */
  agent?: string;
  from?: Date;
  to?: Date;
  /** urgency (default) | severity | oldest | newest */
  sort?: string;
  limit?: number;
  offset?: number;
}

const iso = (d: Date | null) => (d ? d.toISOString() : null);
const firedTimes = (raw: Record<string, unknown>): number | null => {
  const v = (raw.rule as Record<string, unknown> | undefined)?.firedtimes;
  return typeof v === "number" && Number.isFinite(v) ? v : null;
};

export function toInboxItem(
  a: Alert,
  ctx: { incident: InboxIncidentRef | null; scenario: AttackScenario | null; slaMinutes: SlaMinutesBySeverity; slaDue?: Date | null; now: Date }
): InboxAlertItem {
  const due = ctx.slaDue !== undefined ? ctx.slaDue : slaDueAt({ severity: a.severity, receivedAt: a.receivedAt, reviewAt: a.reviewAt, workflowState: a.workflowState }, ctx.slaMinutes);
  return {
    id: a.id,
    externalAlertId: a.externalAlertId,
    siemSource: a.siemSource,
    severity: a.severity,
    status: a.status,
    receivedAt: a.receivedAt.toISOString(),
    summary: summarizeAlert(a.rawPayload),
    firedTimes: firedTimes(a.rawPayload),
    workflowState: a.workflowState,
    displayState: displayState({ workflowState: a.workflowState, incidentId: ctx.incident?.id ?? null }),
    actionable: !ctx.incident && OPEN_WORKFLOW_STATES.includes(a.workflowState) && inSocWorkflow(a.severity),
    disposition: ctx.incident ? "ESCALATED" : (a.triage?.disposition ?? null),
    reviewAt: iso(a.reviewAt),
    monitorReason: a.monitorReason,
    closedAt: iso(a.closedAt),
    slaDueAt: iso(due),
    slaStatus: slaStatus({ workflowState: a.workflowState, closedAt: a.closedAt, severity: a.severity }, due, ctx.slaMinutes, ctx.now),
    ageMinutes: Math.max(0, Math.floor((ctx.now.getTime() - a.receivedAt.getTime()) / 60_000)),
    incident: ctx.incident,
    scenario: ctx.scenario,
    triage: a.triage ? { disposition: a.triage.disposition, note: a.triage.note, triagedBy: a.triage.triagedBy, triagedAt: a.triage.triagedAt.toISOString() } : null,
  };
}

/** Triage SLA targets (Policy TRIAGE_SLA). The port keeps the application layer free of the policy engine type. */
export interface ITriageSlaSource {
  triageSlaMinutes(tenantId: string): Promise<SlaMinutesBySeverity>;
}

export class ListAlertInboxUseCase {
  constructor(
    private readonly inbox: IAlertInboxQuery,
    private readonly sla: ITriageSlaSource,
    private readonly clock: () => Date = () => new Date()
  ) {}

  async execute(input: { tenantId: string; filters: AlertInboxFilters }): Promise<Result<{ items: InboxAlertItem[]; total: number; status: InboxStatus; sort: InboxSort }>> {
    const f = input.filters;
    const status: InboxStatus = isInboxStatus(f.status) ? f.status : "all";
    const sort: InboxSort = INBOX_SORTS.includes(f.sort as InboxSort) ? (f.sort as InboxSort) : "urgency";
    const slaMinutes = await this.sla.triageSlaMinutes(input.tenantId);
    const eq = (a: string, b: string) => a.toLowerCase() === b.trim().toLowerCase();
    const q = f.search?.trim().toLowerCase();

    const { rows, total } = await this.inbox.query({
      tenantId: input.tenantId,
      status,
      severity: f.severity || undefined,
      source: f.source || undefined,
      agent: f.agent || undefined,
      mitre: f.mitre || undefined,
      incident: f.incident === "linked" || f.incident === "unlinked" ? f.incident : undefined,
      scenarioIds:
        f.attackType || f.scenario
          ? ATTACK_SCENARIOS.filter((s) => (!f.attackType || eq(s.attackType, f.attackType)) && (!f.scenario || eq(s.id, f.scenario) || eq(s.caseName, f.scenario))).map((s) => s.id)
          : undefined,
      search: q || undefined,
      searchScenarioIds: q ? ATTACK_SCENARIOS.filter((s) => [s.id, s.attackType, s.caseName].some((v) => v.toLowerCase().includes(q))).map((s) => s.id) : undefined,
      from: f.from,
      to: f.to,
      sort,
      slaMinutes,
      limit: Math.min(Math.max(f.limit ?? 50, 1), 200),
      offset: Math.max(f.offset ?? 0, 0),
    });
    const now = this.clock();
    return Result.ok({
      items: rows.map((r) => toInboxItem(r.alert, { incident: r.incident, scenario: findAttackScenario(r.scenarioId ?? undefined), slaMinutes, slaDue: r.slaDueAt, now })),
      total,
      status,
      sort,
    });
  }
}

export interface AlertView {
  alert: InboxAlertItem;
  rawPayload: Record<string, unknown>;
  iocs: { iocType: string; value: string; path: string }[];
}

export class GetAlertViewUseCase {
  constructor(
    private readonly alerts: IAlertRepository,
    private readonly incidents: IIncidentRepository,
    private readonly sla: ITriageSlaSource,
    private readonly scenarios?: IAlertScenarioRepository,
    private readonly clock: () => Date = () => new Date()
  ) {}

  async execute(input: { tenantId: string; alertId: string }): Promise<Result<AlertView, "ALERT_NOT_FOUND">> {
    const alert = await this.alerts.findById(input.alertId, input.tenantId);
    if (!alert) return Result.fail("ALERT_NOT_FOUND");
    const linked = await this.incidents.findLinkedIncidents([alert.id], input.tenantId);
    const incId = linked.get(alert.id);
    const inc = incId ? (await this.incidents.findByIds([incId], input.tenantId))[0] : undefined;
    const tag = this.scenarios ? (await this.scenarios.findByAlertIds([alert.id], input.tenantId)).get(alert.id) : undefined;
    return Result.ok({
      alert: toInboxItem(alert, {
        incident: inc ? { id: inc.id, title: inc.title, status: inc.status, priority: inc.priority } : null,
        scenario: findAttackScenario(tag?.scenarioId),
        slaMinutes: await this.sla.triageSlaMinutes(input.tenantId),
        now: this.clock(),
      }),
      rawPayload: alert.rawPayload,
      iocs: extractAlertIocs(alert.rawPayload).map((i) => ({ iocType: i.iocType, value: i.value, path: i.path })),
    });
  }
}
