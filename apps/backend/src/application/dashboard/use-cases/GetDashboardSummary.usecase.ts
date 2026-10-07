import { DashboardCounts, IDashboardReadRepository } from "../ports/IDashboardReadRepository";
import { IncidentSla, IncidentSlaService } from "../../sla/IncidentSlaService";
import { ISiemRehuntPort, RehuntHealth } from "../../verification/ports/ISiemRehuntPort";
import { Result } from "../../../shared/result/Result";
import { ReportWindow, windowStart } from "../reportWindow";

export interface IntegrationHealth {
  rehunt: RehuntHealth & { provider: "wazuh-indexer" | "mock" };
  aiOrchestrator: { reachable: boolean; latencyMs: number | null };
}

export interface SlaWatchItem {
  incidentId: string;
  title: string;
  status: string;
  priority: string | null;
  clock: "firstResponse" | "resolution";
  dueAt: string;
  slaStatus: string;
}

/** One System Health row. UNKNOWN = VIGIX has no way to check it (shown as "No data available", never as healthy). */
export interface HealthItem {
  key: string;
  label: string;
  status: "UP" | "DEGRADED" | "DOWN" | "NOT_CONFIGURED" | "UNKNOWN";
  detail: string | null;
  latencyMs: number | null;
}
export type HealthProbe = () => Promise<Omit<HealthItem, "key" | "label">>;

export interface DashboardSummary extends DashboardCounts {
  generatedAt: string;
  /** The report window the backend resolved and filtered event counts by (null = all time). */
  window: { period: ReportWindow | null; since: string | null };
  sla: { breached: number; atRisk: number; onTrack: number; notStarted: number; watchlist: SlaWatchItem[] };
  integrations: IntegrationHealth;
  systemHealth: HealthItem[];
}

/** SLA is evaluated for at most this many unresolved incidents (newest first) per dashboard load. */
export const SLA_WATCH_LIMIT = 100;

/**
 * GetDashboardSummaryUseCase — the operations dashboard: real counts from PostgreSQL, the SLA of every unresolved
 * incident (Policy-derived, read-only — see IncidentSlaService) and live integration health (re-hunt provider,
 * AI orchestrator). Nothing here writes.
 */
export class GetDashboardSummaryUseCase {
  constructor(
    private readonly repo: IDashboardReadRepository,
    private readonly slaService: IncidentSlaService,
    private readonly rehunt: ISiemRehuntPort,
    private readonly rehuntProvider: "wazuh-indexer" | "mock",
    private readonly aiHealth: () => Promise<{ reachable: boolean; latencyMs: number | null }>,
    /** Extra live checks (AI worker, Qdrant, notification, Wazuh manager...), each isolated: a failing probe is DOWN. */
    private readonly probes: { key: string; label: string; probe: HealthProbe }[] = []
  ) {}

  async execute(input: { tenantId: string; days?: number; period?: ReportWindow | null; since?: Date | null }): Promise<Result<DashboardSummary>> {
    const now = new Date();
    // Backend owns the window math: a `period` (daily/weekly/1m/3m) is resolved to its start instant here; an
    // explicit `since` still works as an override/back-compat. period wins when both are given.
    const since = input.period ? windowStart(input.period, now) : input.since ?? null;
    const [counts, open, rehuntHealth, ai, dbLatency, probed] = await Promise.all([
      this.repo.counts(input.tenantId, input.days ?? 14, since),
      this.repo.openIncidents(input.tenantId, SLA_WATCH_LIMIT),
      this.rehunt.health().catch((e: unknown) => ({ configured: false, reachable: false, indexPattern: "", error: e instanceof Error ? e.message : String(e) })) as Promise<RehuntHealth>,
      this.aiHealth().catch(() => ({ reachable: false, latencyMs: null })),
      this.repo.ping().catch(() => null),
      Promise.all(
        this.probes.map(async (p): Promise<HealthItem> => {
          try {
            return { key: p.key, label: p.label, ...(await p.probe()) };
          } catch (e) {
            return { key: p.key, label: p.label, status: "DOWN", detail: e instanceof Error ? e.message : String(e), latencyMs: null };
          }
        })
      ),
    ]);
    const mock = this.rehuntProvider === "mock";
    const systemHealth: HealthItem[] = [
      { key: "backend", label: "Backend", status: "UP", detail: "Serving this request", latencyMs: null },
      { key: "postgres", label: "PostgreSQL", status: dbLatency == null ? "DOWN" : "UP", detail: dbLatency == null ? "Query failed" : null, latencyMs: dbLatency },
      { key: "ai-orchestrator", label: "AI Orchestrator", status: ai.reachable ? "UP" : "DOWN", detail: ai.reachable ? null : "Health endpoint unreachable", latencyMs: ai.latencyMs },
      {
        key: "wazuh-indexer",
        label: "Wazuh Indexer",
        status: mock ? "NOT_CONFIGURED" : !rehuntHealth.configured ? "NOT_CONFIGURED" : rehuntHealth.reachable ? (rehuntHealth.clusterStatus === "red" ? "DEGRADED" : "UP") : "DOWN",
        detail: mock
          ? "Re-hunt uses mock fixtures (REHUNT_PROVIDER=mock); the real indexer is not queried"
          : rehuntHealth.error ?? (rehuntHealth.clusterStatus ? `cluster ${rehuntHealth.clusterStatus}` : null),
        latencyMs: null,
      },
      ...probed,
    ];

    const slas: (IncidentSla & { title: string; status: string })[] = [];
    for (const inc of open) {
      try {
        slas.push({ ...(await this.slaService.forIncident(input.tenantId, inc, now)), title: inc.title, status: inc.status });
      } catch {
        /* one incident's SLA failing must not break the dashboard */
      }
    }

    const tally = { breached: 0, atRisk: 0, onTrack: 0, notStarted: 0 };
    const watch: SlaWatchItem[] = [];
    for (const s of slas) {
      // The clock that matters now: first response until someone starts responding, then resolution.
      const clock = s.firstResponse && !s.firstResponse.at ? "firstResponse" : "resolution";
      const c = s[clock];
      if (!c) continue;
      if (c.status === "BREACHED") tally.breached++;
      else if (c.status === "AT_RISK") tally.atRisk++;
      else if (c.status === "ON_TRACK") tally.onTrack++;
      else if (c.status === "NOT_STARTED") tally.notStarted++;
      watch.push({ incidentId: s.incidentId, title: s.title, status: s.status, priority: s.priority, clock, dueAt: c.dueAt, slaStatus: c.status });
    }
    const rank: Record<string, number> = { BREACHED: 0, AT_RISK: 1, ON_TRACK: 2, NOT_STARTED: 3 };
    watch.sort((a, b) => (rank[a.slaStatus] ?? 9) - (rank[b.slaStatus] ?? 9) || a.dueAt.localeCompare(b.dueAt));

    return Result.ok({
      ...counts,
      generatedAt: now.toISOString(),
      window: { period: input.period ?? null, since: since ? since.toISOString() : null },
      sla: { ...tally, watchlist: watch.slice(0, 8) },
      integrations: { rehunt: { ...rehuntHealth, provider: this.rehuntProvider }, aiOrchestrator: ai },
      systemHealth,
    });
  }
}
