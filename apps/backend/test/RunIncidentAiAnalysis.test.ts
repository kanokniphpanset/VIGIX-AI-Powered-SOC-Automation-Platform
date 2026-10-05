import type { NextFunction, Request, Response } from "express";
import { RunIncidentAiAnalysisUseCase, IAiAnalysisRunGuard } from "../src/application/incident/use-cases/RunIncidentAiAnalysis.usecase";
import { GetIncidentAiAnalysisUseCase } from "../src/application/incident/use-cases/GetIncidentAiAnalysis.usecase";
import { AiAnalysisRunnerError, IAiAnalysisRunnerPort, RunAnalysisInput } from "../src/application/agent-orchestration/ports/IAiAnalysisRunnerPort";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { buildAiAnalysisRoutes } from "../src/presentation/http/routes/ai-analysis.routes";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";

// No real orchestrator / LLM / DB: the runner, guard and repositories are in-memory fakes.
const T = "00000000-0000-0000-0000-000000000001";
const INC = "inc-atk02";
const ALERT = "alert-d5ca329c";

function world(opts: { alertId?: string | null; owners?: string[]; running?: boolean; runner?: Partial<IAiAnalysisRunnerPort>; analysedBefore?: boolean } = {}) {
  const state = { analysed: !!opts.analysedBefore, alerts: 1, incidents: 1, statusChanges: 0, syncs: 0 };
  const incidents = {
    findById: async (id: string) => (id === INC ? { id: INC, alertId: opts.alertId === undefined ? ALERT : opts.alertId, status: "investigating" } : null),
    create: async () => { state.incidents++; throw new Error("must not create incidents"); },
    updateStatus: async () => { state.statusChanges++; },
  } as never;
  const guard: IAiAnalysisRunGuard = {
    hasRunningExecution: async () => !!opts.running,
    incidentsWithPrimaryAlert: async (alertId) => (alertId === ALERT ? opts.owners ?? [INC] : []),
  };
  const runnerCalls: RunAnalysisInput[] = [];
  const runner: IAiAnalysisRunnerPort = {
    runAnalysis: async (input) => {
      runnerCalls.push(input);
      if (opts.runner?.runAnalysis) return opts.runner.runAnalysis(input);
      state.analysed = true;
      return { graphRunId: "exec-1", incidentId: INC, status: "SUCCESS", decision: "auto_response" };
    },
  };
  const context = {
    getIncidentContext: async (id: string) => (id === INC ? { incidentId: INC } : null),
    getLatestAiAnalysis: async () => (state.analysed ? { summary: "Repeated authentication failures may indicate brute force.", keyFindings: ["T1110"] } : null),
  } as never;
  const investigations = { syncIncident: async () => { state.syncs++; } } as never;
  const audits: { action: string; actor: string; entityId: string; metadata: Record<string, unknown> }[] = [];
  const audit = { record: async (e: never) => void audits.push(e) } as unknown as AuditLogger;
  const useCase = new RunIncidentAiAnalysisUseCase(incidents, guard, runner, investigations, new GetIncidentAiAnalysisUseCase(context), audit);
  const run = () => useCase.execute({ tenantId: T, incidentId: INC, actor: "soc-1" });
  return { useCase, run, state, audits, runnerCalls };
}

describe("Run / Re-run AI Analysis for an existing incident", () => {
  test("first run: runs the existing pipeline on the incident's own alert, syncs the investigation, returns the fresh analysis, audits", async () => {
    const w = world();
    const r = await w.run();
    expect(r.isSuccess).toBe(true);
    expect(r.value).toMatchObject({ incidentId: INC, graphRunId: "exec-1", status: "SUCCESS", rerun: false, analysis: { keyFindings: ["T1110"] } });
    // VIGIX has no AI severity: the analysis carries none, and neither does the audit.
    expect(r.value.analysis).not.toHaveProperty("aiSeverity");
    expect(w.runnerCalls).toEqual([{ alertId: ALERT, tenantId: T }]);
    expect(w.state.syncs).toBe(1);
    expect(w.audits).toEqual([expect.objectContaining({ action: "AI_ANALYSIS_RUN", actor: "soc-1", entityId: INC, metadata: expect.objectContaining({ trigger: "manual", outcome: "SUCCESS", rerun: false, graphRunId: "exec-1" }) })]);
    expect(w.audits[0].metadata).not.toHaveProperty("severitySuggestion");
  });

  test("re-run is flagged as such when an analysis already existed", async () => {
    const w = world({ analysedBefore: true });
    expect((await w.run()).value.rerun).toBe(true);
    expect(w.audits[0].metadata.rerun).toBe(true);
  });

  test("new investigation round: passes the round's verification evidence to the pipeline and audits the trigger", async () => {
    const w = world({ analysedBefore: true });
    const investigationContext = {
      investigationNumber: 2,
      verification: {
        id: "ver-1", result: "NOT_RESOLVED", query: "rule.id:5710", timeRangeStart: null, timeRangeEnd: null, matchingEvents: 2,
        affectedHosts: ["WEB-01"], iocRecurrence: true, spreadDetected: false, threatContained: false, evidenceSource: "MOCK_REHUNT",
      },
    };
    const r = await w.useCase.execute({ tenantId: T, incidentId: INC, actor: "system", trigger: "investigation_reopened", investigationContext });
    expect(r.isSuccess).toBe(true);
    expect(w.runnerCalls).toEqual([{ alertId: ALERT, tenantId: T, investigationContext }]);
    expect(w.audits[0]).toMatchObject({
      actor: "system",
      metadata: { trigger: "investigation_reopened", investigationNumber: 2, causedByVerificationId: "ver-1", outcome: "SUCCESS", rerun: true },
    });
  });

  test("incident not found: nothing runs", async () => {
    const w = world();
    const r = await w.useCase.execute({ tenantId: T, incidentId: "missing", actor: "u" });
    expect(r.error).toBe("INCIDENT_NOT_FOUND");
    expect(w.runnerCalls).toHaveLength(0);
  });

  test("incident without an alert: nothing runs", async () => {
    const w = world({ alertId: null });
    expect((await w.run()).error).toBe("INCIDENT_HAS_NO_ALERT");
    expect(w.runnerCalls).toHaveLength(0);
  });

  test("alert that is another incident's (or several incidents') primary alert is refused — the pipeline would attach elsewhere", async () => {
    expect((await world({ owners: ["other-incident"] }).run()).error).toBe("ALERT_OWNED_BY_OTHER_INCIDENT");
    expect((await world({ owners: [INC, "other-incident"] }).run()).error).toBe("ALERT_OWNED_BY_OTHER_INCIDENT");
    expect((await world({ owners: [] }).run()).error).toBe("ALERT_OWNED_BY_OTHER_INCIDENT");
  });

  test("AI orchestrator unavailable: clear error, audited as FAILED, no sync, no status change, no records", async () => {
    const w = world({ runner: { runAnalysis: async () => { throw new AiAnalysisRunnerError("AI_UNAVAILABLE", "down"); } } });
    const r = await w.run();
    expect(r.error).toBe("AI_UNAVAILABLE");
    expect(w.state.syncs).toBe(0);
    expect(w.state.statusChanges).toBe(0);
    expect(w.audits[0].metadata).toMatchObject({ outcome: "FAILED", error: "AI_UNAVAILABLE" });
  });

  test("concurrent requests for the same incident: exactly one pipeline run, the other is ANALYSIS_IN_PROGRESS", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const w = world({ runner: { runAnalysis: async () => { await gate; return { graphRunId: "exec-1", incidentId: INC, status: "SUCCESS", decision: null }; } } });
    const first = w.run();
    const second = await w.run();
    release();
    expect(second.error).toBe("ANALYSIS_IN_PROGRESS");
    expect((await first).isSuccess).toBe(true);
    expect(w.runnerCalls).toHaveLength(1);
    expect((await w.run()).isSuccess).toBe(true); // lock released afterwards
  });

  test("a pipeline run already RUNNING for the incident (e.g. from ingestion) is respected", async () => {
    const w = world({ running: true });
    expect((await w.run()).error).toBe("ANALYSIS_IN_PROGRESS");
    expect(w.runnerCalls).toHaveLength(0);
  });

  test("no duplicate alert or incident: the existing alert id is reused and a pipeline answer for another incident is rejected", async () => {
    const ok = world();
    await ok.run();
    expect(ok.runnerCalls[0].alertId).toBe(ALERT);
    expect(ok.state).toMatchObject({ alerts: 1, incidents: 1 });

    const mismatch = world({ runner: { runAnalysis: async () => ({ graphRunId: "exec-9", incidentId: "a-new-incident", status: "SUCCESS", decision: null }) } });
    expect((await mismatch.run()).error).toBe("AI_FAILED");
    expect(mismatch.audits[0].metadata).toMatchObject({ outcome: "FAILED", error: "INCIDENT_MISMATCH", pipelineIncidentId: "a-new-incident" });
    expect(mismatch.state.syncs).toBe(0);
  });
});

describe("POST /api/v1/incidents/:incidentId/ai-analysis/run — route gate and status codes", () => {
  function route(result: unknown) {
    const calls: string[] = [];
    const router = buildAiAnalysisRoutes({ execute: async () => (calls.push("run"), result) } as never) as unknown as {
      stack: { route?: { stack: { handle: (req: Request, res: Response, next: NextFunction) => unknown }[] } }[];
    };
    async function call(role: string | null) {
      const req = { header: (n: string) => (n.toLowerCase() === "authorization" && role ? `Bearer ${signToken({ id: `u-${role}`, tenantId: T, role })}` : undefined), params: { incidentId: INC }, body: {} } as unknown as Request;
      let status = 200;
      let body: unknown;
      const res = { status: (s: number) => ((status = s), res), json: (b: unknown) => ((body = b), res) } as unknown as Response;
      for (const { handle } of router.stack[0].route!.stack) {
        let next = false;
        await handle(req, res, () => void (next = true));
        if (!next) break;
      }
      return { status, body };
    }
    return { call, calls };
  }

  test("SOC, IR_TEAM and admin may run it; MANAGER and anonymous may not", async () => {
    const { call, calls } = route({ isFailure: false, value: { status: "SUCCESS" } });
    expect((await call("SOC")).status).toBe(200);
    expect((await call("IR_TEAM")).status).toBe(200);
    expect((await call("admin")).status).toBe(200);
    expect((await call("MANAGER")).status).toBe(403);
    expect((await call(null)).status).toBe(401);
    expect(calls).toHaveLength(3);
  });

  test.each([
    ["INCIDENT_NOT_FOUND", 404],
    ["INCIDENT_HAS_NO_ALERT", 422],
    ["ANALYSIS_IN_PROGRESS", 409],
    ["ALERT_OWNED_BY_OTHER_INCIDENT", 409],
    ["AI_UNAVAILABLE", 503],
    ["AI_FAILED", 502],
  ])("%s → HTTP %i", async (error, status) => {
    const { call } = route({ isFailure: true, error });
    expect(await call("SOC")).toEqual({ status, body: { error } });
  });
});
