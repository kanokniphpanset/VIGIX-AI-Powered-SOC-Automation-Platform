import { AiAnalysisJobService, AiJobPolicy } from "../src/application/agent-orchestration/services/AiAnalysisJobService";
import { AiAnalysisJob, AiJobTrigger, IAiAnalysisJobRepository } from "../src/application/agent-orchestration/ports/IAiAnalysisJobRepository";
import { AiAnalysisRunnerError, IAiAnalysisRunnerPort, RunAnalysisInput, RunAnalysisOutput } from "../src/application/agent-orchestration/ports/IAiAnalysisRunnerPort";
import { IInvestigationRepository } from "../src/domain/investigation/IInvestigationRepository";
import { AiAnalysisWorker } from "../src/infrastructure/workers/AiAnalysisWorker";
import { LangGraphOrchestratorAdapter } from "../src/infrastructure/ai/LangGraphOrchestratorAdapter";
import { OrchestratorCallbackController } from "../src/presentation/http/webhooks/orchestrator-callback.webhook";
import { PrismaAiAnalysisRunGuard } from "../src/infrastructure/database/postgres/repositories/AiAnalysisRunGuard.prisma";

/**
 * P1 — DB-backed AI analysis queue on agent_executions: QUEUED -> RUNNING -> SUCCESS/PARTIAL_SUCCESS | FAILED,
 * bounded retry with backoff, stale-RUNNING recovery. The analysis itself is the existing runner (execution_id).
 */

const TENANT = "00000000-0000-0000-0000-000000000001";
const POLICY: AiJobPolicy = { maxAttempts: 3, baseBackoffMs: 30_000, staleRunningMs: 15 * 60_000, busyDelayMs: 30_000 };

/** In-memory model of PrismaAiAnalysisJobRepository's semantics. */
class InMemoryJobs implements IAiAnalysisJobRepository {
  readonly rows: AiAnalysisJob[] = [];
  /** Runs started outside the queue (e.g. the manual Run AI Analysis) — RUNNING rows with no trigger. */
  readonly externalRunning: Array<{ incidentId: string; startedAt: Date }> = [];
  readonly completedAt: Array<{ incidentId: string; at: Date }> = [];
  constructor(private readonly clock: () => Date) {}

  async enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: AiJobTrigger; attempt: number; notBefore: Date }) {
    const job: AiAnalysisJob = {
      id: `job-${this.rows.length + 1}`,
      incidentId: input.incidentId,
      alertId: input.alertId,
      tenantId: input.tenantId,
      trigger: input.trigger,
      attempt: input.attempt,
      status: "QUEUED",
      queuedAt: this.clock(),
      startedAt: null,
      completedAt: null,
      nextAttemptAt: input.notBefore,
      errorCode: null,
      errorMessage: null,
    };
    this.rows.push(job);
    return { ...job };
  }
  async claimNext(now: Date) {
    const due = this.rows
      .filter((r) => r.status === "QUEUED" && (!r.nextAttemptAt || r.nextAttemptAt <= now))
      .sort((a, b) => (a.nextAttemptAt?.getTime() ?? 0) - (b.nextAttemptAt?.getTime() ?? 0))[0];
    if (!due) return null;
    due.status = "RUNNING";
    due.startedAt = now;
    return { ...due };
  }
  async release(id: string, notBefore: Date) {
    const r = this.get(id);
    r.status = "QUEUED";
    r.nextAttemptAt = notBefore;
  }
  async markFailed(id: string, code: string, message: string, now: Date) {
    const r = this.get(id);
    if (r.status === "SUCCESS" || r.status === "PARTIAL_SUCCESS") return false;
    Object.assign(r, { status: "FAILED", errorCode: r.errorCode ?? code, errorMessage: r.errorMessage ?? message, completedAt: r.completedAt ?? now });
    return true;
  }
  async cancel(id: string, reason: string, now: Date) {
    Object.assign(this.get(id), { status: "CANCELLED", errorCode: "SUPERSEDED", errorMessage: reason, completedAt: now });
  }
  async findStaleRunning(before: Date) {
    return this.rows.filter((r) => r.status === "RUNNING" && r.startedAt! < before).map((r) => ({ ...r }));
  }
  async hasOtherActiveRun(incidentId: string, excludeId: string, since: Date) {
    return (
      this.rows.some((r) => r.incidentId === incidentId && r.id !== excludeId && r.status === "RUNNING" && r.startedAt! >= since) ||
      this.externalRunning.some((r) => r.incidentId === incidentId && r.startedAt >= since)
    );
  }
  async hasCompletedSince(incidentId: string, since: Date) {
    return this.completedAt.some((c) => c.incidentId === incidentId && c.at >= since);
  }
  async latestForIncident(incidentId: string) {
    return [...this.rows].reverse().find((r) => r.incidentId === incidentId) ?? null;
  }
  get(id: string) {
    return this.rows.find((r) => r.id === id)!;
  }
}

/** Plays the orchestrator: records the call and writes the terminal status on the execution row like persist_agent_results. */
class FakeRunner implements IAiAnalysisRunnerPort {
  readonly calls: RunAnalysisInput[] = [];
  next: Array<(input: RunAnalysisInput) => RunAnalysisOutput | Promise<RunAnalysisOutput>> = [];
  constructor(private readonly jobs: InMemoryJobs) {}
  async runAnalysis(input: RunAnalysisInput): Promise<RunAnalysisOutput> {
    this.calls.push(input);
    const step = this.next.shift() ?? ((i: RunAnalysisInput) => this.succeed(i));
    return step(input);
  }
  succeed(input: RunAnalysisInput, status: "SUCCESS" | "PARTIAL_SUCCESS" = "SUCCESS"): RunAnalysisOutput {
    const row = this.jobs.get(input.executionId!);
    row.status = status;
    return { graphRunId: input.executionId!, incidentId: row.incidentId, status, decision: "human_approval" };
  }
}

function setup(clockStart = new Date("2026-09-24T10:00:00Z")) {
  let now = clockStart;
  const jobs = new InMemoryJobs(() => now);
  const runner = new FakeRunner(jobs);
  const synced: Array<[string, string]> = [];
  const investigations = { syncIncident: async (i: string, t: string) => void synced.push([i, t]) } as unknown as IInvestigationRepository;
  const audits: Array<{ action: string; entityId: string; actor: string; metadata: Record<string, unknown> }> = [];
  const auditLogger = { record: async (e: never) => void audits.push(e) } as never;
  const service = new AiAnalysisJobService(jobs, runner, investigations, auditLogger, POLICY, () => now);
  const advance = (ms: number) => (now = new Date(now.getTime() + ms));
  const enqueue = () => service.enqueue({ tenantId: TENANT, incidentId: "inc-1", alertId: "alert-1", trigger: "INGEST" });
  return { jobs, runner, synced, audits, service, advance, enqueue, now: () => now };
}

const fail = (code: "AI_UNAVAILABLE" | "AI_FAILED") => () => {
  throw new AiAnalysisRunnerError(code, "boom");
};

describe("AiAnalysisJobService", () => {
  it("returns null when nothing is due", async () => {
    const { service } = setup();
    expect(await service.processNext()).toBeNull();
  });

  it("QUEUED -> RUNNING -> runs the existing pipeline with execution_id -> SUCCESS, syncs the investigation, audits", async () => {
    const { service, enqueue, jobs, runner, synced, audits } = setup();
    const job = await enqueue();
    expect(job).toMatchObject({ status: "QUEUED", attempt: 1, trigger: "INGEST" });

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "COMPLETED", status: "SUCCESS" });
    expect(runner.calls).toEqual([{ alertId: "alert-1", tenantId: TENANT, executionId: job.id }]);
    expect(jobs.get(job.id).status).toBe("SUCCESS");
    expect(synced).toEqual([["inc-1", TENANT]]);
    expect(audits).toEqual([expect.objectContaining({ action: "AI_ANALYSIS_JOB_COMPLETED", entityId: "inc-1", actor: "vigix-ai-worker" })]);
    expect(await service.processNext()).toBeNull();
  });

  it("on failure marks FAILED with the reason and queues ONE retry (attempt+1) after exponential backoff", async () => {
    const { service, enqueue, jobs, runner, advance, audits, now } = setup();
    const job = await enqueue();
    runner.next.push(fail("AI_UNAVAILABLE"));

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "FAILED", error: "AI_UNAVAILABLE" });
    expect(jobs.get(job.id)).toMatchObject({ status: "FAILED", errorCode: "AI_UNAVAILABLE" });
    const retry = jobs.rows[1];
    expect(retry).toMatchObject({ status: "QUEUED", trigger: "RETRY", attempt: 2, alertId: "alert-1", incidentId: "inc-1" });
    expect(retry.nextAttemptAt!.getTime() - now().getTime()).toBe(30_000);
    expect(audits[0]).toMatchObject({ action: "AI_ANALYSIS_JOB_FAILED", metadata: expect.objectContaining({ retryJobId: retry.id, exhausted: false }) });

    // Not due yet -> nothing claimed.
    expect(await service.processNext()).toBeNull();
    advance(30_000);
    expect(await service.processNext()).toMatchObject({ outcome: "COMPLETED" });
    expect(jobs.get(retry.id).status).toBe("SUCCESS");
  });

  it("stops after maxAttempts (bounded, no infinite loop) with backoff 30s, 60s", async () => {
    const { service, enqueue, jobs, runner, advance, audits } = setup();
    await enqueue();
    runner.next.push(fail("AI_FAILED"), fail("AI_FAILED"), fail("AI_FAILED"), fail("AI_FAILED"));

    const gaps: number[] = [];
    for (let i = 0; i < 10; i++) {
      if (await service.processNext()) continue;
      const next = jobs.rows.find((r) => r.status === "QUEUED");
      if (!next) break;
      const gap = next.nextAttemptAt!.getTime() - jobs.rows[jobs.rows.indexOf(next) - 1].completedAt!.getTime();
      gaps.push(gap);
      advance(gap);
    }

    expect(jobs.rows.map((r) => [r.attempt, r.status])).toEqual([
      [1, "FAILED"],
      [2, "FAILED"],
      [3, "FAILED"],
    ]);
    expect(gaps).toEqual([30_000, 60_000]);
    expect(runner.calls).toHaveLength(3);
    expect(audits[audits.length - 1]).toMatchObject({ action: "AI_ANALYSIS_JOB_FAILED", metadata: expect.objectContaining({ exhausted: true, retryJobId: null }) });
  });

  it("defers (without using an attempt) while another run holds the incident, e.g. a manual run", async () => {
    const { service, enqueue, jobs, runner, now } = setup();
    const job = await enqueue();
    jobs.externalRunning.push({ incidentId: "inc-1", startedAt: now() });

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "DEFERRED" });
    expect(runner.calls).toEqual([]);
    expect(jobs.get(job.id)).toMatchObject({ status: "QUEUED", attempt: 1 });
    expect(jobs.get(job.id).nextAttemptAt!.getTime() - now().getTime()).toBe(POLICY.busyDelayMs);
  });

  it("cancels a retry when an earlier attempt completed after all (SUPERSEDED)", async () => {
    const { service, enqueue, jobs, runner, advance, now } = setup();
    await enqueue();
    runner.next.push(fail("AI_UNAVAILABLE"));
    await service.processNext();
    jobs.completedAt.push({ incidentId: "inc-1", at: new Date(now().getTime() + 5_000) });
    advance(30_000);

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "SUPERSEDED" });
    expect(jobs.rows[1].status).toBe("CANCELLED");
    expect(runner.calls).toHaveLength(1);
  });

  it("refuses an incident mismatch without retrying", async () => {
    const { service, enqueue, jobs, runner, synced } = setup();
    const job = await enqueue();
    runner.next.push((i) => ({ graphRunId: i.executionId!, incidentId: "other-incident", status: "SUCCESS", decision: null }));

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "FAILED", error: "INCIDENT_MISMATCH", retryJob: null });
    expect(jobs.get(job.id)).toMatchObject({ status: "FAILED", errorCode: "INCIDENT_MISMATCH" });
    expect(jobs.rows).toHaveLength(1);
    expect(synced).toEqual([]);
  });

  it("does not overwrite a run the orchestrator completed when only the HTTP wait failed", async () => {
    const { service, enqueue, jobs, runner, audits } = setup();
    const job = await enqueue();
    runner.next.push((i) => {
      runner.succeed(i, "PARTIAL_SUCCESS");
      throw new AiAnalysisRunnerError("AI_UNAVAILABLE", "timeout");
    });

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "COMPLETED", status: "COMPLETED_AFTER_ERROR" });
    expect(jobs.get(job.id).status).toBe("PARTIAL_SUCCESS");
    expect(jobs.rows).toHaveLength(1);
    expect(audits[0].metadata).toMatchObject({ status: "COMPLETED_AFTER_ERROR", clientError: "AI_UNAVAILABLE" });
  });

  it("recovers abandoned RUNNING jobs: FAILED STALE_RUNNING + bounded retry", async () => {
    const { service, enqueue, jobs, advance } = setup();
    const job = await enqueue();
    await jobs.claimNext(new Date("2026-09-24T10:00:00Z")); // backend died after claiming
    advance(10 * 60_000);
    expect(await service.recoverStale()).toEqual([]);
    advance(6 * 60_000);

    const stale = await service.recoverStale();

    expect(stale.map((s) => s.id)).toEqual([job.id]);
    expect(jobs.get(job.id)).toMatchObject({ status: "FAILED", errorCode: "STALE_RUNNING" });
    expect(jobs.rows[1]).toMatchObject({ status: "QUEUED", trigger: "RETRY", attempt: 2 });
  });

  it("never touches recommendation / policy / approval / response / n8n (only the analysis runner is called)", async () => {
    const { service, enqueue, audits } = setup();
    await enqueue();
    await service.processNext();
    expect(audits.map((a) => a.action)).toEqual(["AI_ANALYSIS_JOB_COMPLETED"]);
  });
});

describe("AiAnalysisWorker", () => {
  it("drains due jobs one at a time and stops on DEFERRED / empty", async () => {
    const outcomes = [{ outcome: "COMPLETED", job: { id: "a" } }, { outcome: "COMPLETED", job: { id: "b" } }, null];
    const service = { processNext: jest.fn(async () => outcomes.shift() ?? null), recoverStale: jest.fn(async () => []) };
    const worker = new AiAnalysisWorker(service as never, { pollMs: 60_000, recoveryMs: 60_000 });
    const log = jest.spyOn(console, "log").mockImplementation(() => undefined);
    await worker.start();
    for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r));
    worker.stop();
    log.mockRestore();
    expect(service.recoverStale).toHaveBeenCalledTimes(1);
    expect(service.processNext).toHaveBeenCalledTimes(3);
  });

  it("is single-flight: a tick while busy does nothing", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const service = {
      processNext: jest.fn(async () => {
        await gate;
        return null;
      }),
      recoverStale: jest.fn(async () => []),
    };
    const worker = new AiAnalysisWorker(service as never, { pollMs: 60_000, recoveryMs: 60_000 });
    await worker.start();
    await worker.tick();
    await worker.tick();
    release();
    await new Promise((r) => setImmediate(r));
    worker.stop();
    expect(service.processNext).toHaveBeenCalledTimes(1);
  });

  it("survives an error in a tick", async () => {
    const service = { processNext: jest.fn(async () => Promise.reject(new Error("db down"))), recoverStale: jest.fn(async () => []) };
    const worker = new AiAnalysisWorker(service as never, { pollMs: 60_000, recoveryMs: 60_000 });
    const err = jest.spyOn(console, "error").mockImplementation(() => undefined);
    await worker.start();
    await worker.tick();
    worker.stop();
    err.mockRestore();
    expect(service.processNext).toHaveBeenCalled();
  });
});

describe("LangGraphOrchestratorAdapter.runAnalysis", () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  async function bodyFor(input: RunAnalysisInput) {
    const fetchMock = jest.fn(async () => new Response(JSON.stringify({ graph_run_id: "g", incident_id: "inc-1", status: "SUCCESS" }), { status: 200 }));
    global.fetch = fetchMock as never;
    await new LangGraphOrchestratorAdapter("http://ai").runAnalysis(input);
    return JSON.parse((fetchMock.mock.calls[0] as unknown as [string, { body: string }])[1].body);
  }

  it("sends the queued job id as execution_id, analysis-only", async () => {
    expect(await bodyFor({ alertId: "a", tenantId: TENANT, executionId: "job-1" })).toEqual({ alert_id: "a", tenant_id: TENANT, analysis_only: true, execution_id: "job-1" });
  });

  it("omits execution_id for the direct manual run", async () => {
    expect(await bodyFor({ alertId: "a", tenantId: TENANT })).toEqual({ alert_id: "a", tenant_id: TENANT, analysis_only: true });
  });
});

describe("OrchestratorCallbackController (AI decision is advisory)", () => {
  function call(body: Record<string, unknown>) {
    const audits: Array<{ action: string; metadata: Record<string, unknown> }> = [];
    const controller = new OrchestratorCallbackController({ record: async (e: never) => void audits.push(e) } as never);
    const res = { statusCode: 0, body: undefined as unknown, status(c: number) { this.statusCode = c; return this; }, json(b: unknown) { this.body = b; return this; } };
    return { audits, res, run: () => controller.handle({ body } as never, res as never) };
  }

  it("records an auto_response decision without triggering any playbook", async () => {
    const fetchSpy = jest.spyOn(global, "fetch");
    const { audits, res, run } = call({ incidentId: "inc-1", decision: "auto_response", riskScore: 95, severity: "critical" }); // a legacy riskScore is ignored
    await run();
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ acknowledged: true, playbookTriggered: false });
    expect(audits).toEqual([expect.objectContaining({ action: "AI_DECISION_RECORDED", metadata: expect.objectContaining({ decision: "auto_response", playbookTriggered: false, advisoryOnly: true }) })]);
    expect(audits[0].metadata).not.toHaveProperty("riskScore");
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("rejects a callback without incidentId / decision", async () => {
    const { res, audits, run } = call({ decision: "dismiss" });
    await run();
    expect(res.statusCode).toBe(400);
    expect(audits).toEqual([]);
  });
});

describe("PrismaAiAnalysisRunGuard", () => {
  it("counts a QUEUED job as in progress, so a manual run cannot overlap a queued one", async () => {
    const count = jest.fn(async () => 1);
    const guard = new PrismaAiAnalysisRunGuard({ agentExecution: { count } } as never);
    expect(await guard.hasRunningExecution("inc-1", new Date(0))).toBe(true);
    expect(count).toHaveBeenCalledWith({ where: expect.objectContaining({ incidentId: "inc-1", status: { in: ["RUNNING", "running", "QUEUED"] } }) });
  });
});

describe("AI analysis failure is never reported as success (E2E 2026-09-26: silent LLM fallback)", () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it("adapter: a FAILED pipeline (the LLM analysis failed) throws AI_ANALYSIS_FAILED with the orchestrator's reason", async () => {
    global.fetch = (async () =>
      new Response(JSON.stringify({ graph_run_id: "g", incident_id: "inc-1", status: "FAILED", error_code: "LLM_TIMEOUT", error_message: "LLM analysis failed (ReadTimeout)" }), { status: 200 })) as never;
    const err = await new LangGraphOrchestratorAdapter("http://ai").runAnalysis({ alertId: "a", tenantId: TENANT }).catch((e) => e);
    expect(err).toBeInstanceOf(AiAnalysisRunnerError);
    expect(err).toMatchObject({ code: "AI_ANALYSIS_FAILED", reason: "LLM_TIMEOUT" });
    expect(String(err.message)).toContain("LLM_TIMEOUT");
  });

  it("adapter: SUCCESS / PARTIAL_SUCCESS still map as before", async () => {
    for (const status of ["SUCCESS", "PARTIAL_SUCCESS"] as const) {
      global.fetch = (async () => new Response(JSON.stringify({ graph_run_id: "g", incident_id: "inc-1", status }), { status: 200 })) as never;
      expect(await new LangGraphOrchestratorAdapter("http://ai").runAnalysis({ alertId: "a", tenantId: TENANT })).toMatchObject({ status });
    }
  });

  it("job: an LLM analysis failure is FAILED with the specific reason (LLM_TIMEOUT) and retried, not SUCCESS", async () => {
    const { service, enqueue, jobs, runner, audits } = setup();
    const job = await enqueue();
    runner.next.push(() => {
      throw new AiAnalysisRunnerError("AI_ANALYSIS_FAILED", "LLM_TIMEOUT: LLM analysis failed (ReadTimeout)", "LLM_TIMEOUT");
    });

    const out = await service.processNext();

    expect(out).toMatchObject({ outcome: "FAILED", error: "LLM_TIMEOUT" });
    expect(jobs.get(job.id)).toMatchObject({ status: "FAILED", errorCode: "LLM_TIMEOUT" });
    expect(jobs.rows[1]).toMatchObject({ status: "QUEUED", trigger: "RETRY", attempt: 2 });
    expect(audits[0]).toMatchObject({ action: "AI_ANALYSIS_JOB_FAILED" });
  });
});
