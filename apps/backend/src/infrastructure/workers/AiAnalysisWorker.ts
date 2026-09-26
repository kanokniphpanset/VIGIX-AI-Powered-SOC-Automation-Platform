import { AiAnalysisJobService } from "../../application/agent-orchestration/services/AiAnalysisJobService";

export interface AiAnalysisWorkerOptions {
  /** How often to look for due jobs when idle. */
  pollMs: number;
  /** How often to look for abandoned RUNNING jobs. */
  recoveryMs: number;
}

/**
 * In-process worker for the DB-backed AI analysis queue. Processes one job at a time (single-flight), drains due
 * jobs back-to-back, recovers abandoned RUNNING jobs on start and periodically. Stopping only prevents new claims.
 */
export class AiAnalysisWorker {
  private pollTimer: NodeJS.Timeout | null = null;
  private recoveryTimer: NodeJS.Timeout | null = null;
  private busy = false;
  private stopped = true;
  private lastTickAt: Date | null = null;

  constructor(private readonly jobs: AiAnalysisJobService, private readonly options: AiAnalysisWorkerOptions) {}

  async start(): Promise<void> {
    if (!this.stopped) return;
    this.stopped = false;
    await this.recover();
    this.pollTimer = setInterval(() => void this.tick(), this.options.pollMs);
    this.recoveryTimer = setInterval(() => void this.recover(), this.options.recoveryMs);
    void this.tick();
  }

  stop(): void {
    this.stopped = true;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.recoveryTimer) clearInterval(this.recoveryTimer);
    this.pollTimer = this.recoveryTimer = null;
  }

  /** Runs due jobs until none is left. Safe to call concurrently (single-flight). */
  async tick(): Promise<void> {
    if (this.busy || this.stopped) return;
    this.busy = true;
    this.lastTickAt = new Date();
    try {
      while (!this.stopped) {
        const outcome = await this.jobs.processNext();
        if (!outcome || outcome.outcome === "DEFERRED") break;
        console.log(`[ai-worker] job ${outcome.job.id} (${outcome.job.trigger} #${outcome.job.attempt}) -> ${outcome.outcome}`);
      }
    } catch (err) {
      console.error("[ai-worker] tick failed", err instanceof Error ? err.message : err);
    } finally {
      this.busy = false;
    }
  }

  /** Liveness for the dashboard's System Health (read-only). */
  status(): { running: boolean; busy: boolean; lastTickAt: string | null; pollMs: number } {
    return { running: !this.stopped, busy: this.busy, lastTickAt: this.lastTickAt?.toISOString() ?? null, pollMs: this.options.pollMs };
  }

  private async recover(): Promise<void> {
    try {
      const stale = await this.jobs.recoverStale();
      if (stale.length) console.warn(`[ai-worker] recovered ${stale.length} abandoned RUNNING job(s)`);
    } catch (err) {
      console.error("[ai-worker] recovery failed", err instanceof Error ? err.message : err);
    }
  }
}
