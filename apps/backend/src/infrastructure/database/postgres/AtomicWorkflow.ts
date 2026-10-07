import { AsyncLocalStorage } from "node:async_hooks";
import { Prisma, PrismaClient } from "@prisma/client";

export type WorkflowScope = "incident" | "recommendation" | "response" | "approval" | "playbook" | "intake";
type Context = { tx: Prisma.TransactionClient; writes: number; auditFailure?: unknown; retry?: OwnershipChanged; afterCommit: Array<() => Promise<void>>; sequence: { value: number } };
class OwnershipChanged extends Error {
  constructor() { super("Alert ownership changed concurrently; retry the workflow"); }
}
class FailedResult extends Error {
  constructor(readonly result: unknown) { super("Workflow returned a failure after writing state"); }
}
const WRITES = new Set(["create", "createMany", "update", "updateMany", "upsert", "delete", "deleteMany"]);

/** Per-request unit of work. Repositories and audit share this client only inside run().
 * Existing repository transactions become savepoints, not independent commits.
 * External effects run after commit; rollback discards them. No identity is accepted from HTTP here.
 */
export class AtomicWorkflow {
  private readonly context = new AsyncLocalStorage<Context>();
  readonly prisma: PrismaClient;

  constructor(private readonly base: PrismaClient) {
    this.prisma = new Proxy(base, {
      get: (target, property) => {
        const current = this.context.getStore();
        if (!current) {
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        }
        if (property === "$transaction") {
          return (work: ((tx: Prisma.TransactionClient) => Promise<unknown>) | Promise<unknown>[]) =>
            this.nested(() => Array.isArray(work) ? Promise.all(work) : work(this.prisma));
        }
        const value = Reflect.get(current.tx, property, current.tx);
        if (typeof value === "function") return value.bind(current.tx);
        if (!value || typeof value !== "object") return value;
        return new Proxy(value, {
          get: (delegate, method) => {
            const operation = Reflect.get(delegate, method, delegate);
            if (typeof operation !== "function") return operation;
            return async (...args: unknown[]) => {
              try {
                const result = await operation.apply(delegate, args);
                if (property !== "auditLog" && WRITES.has(String(method))) current.writes++;
                return result;
              } catch (error) {
                if (property === "auditLog" && WRITES.has(String(method))) current.auditFailure = error;
                throw error;
              }
            };
          },
        });
      },
    });
  }

  private check<T>(state: Context, result: T): T {
    if (state.retry) throw state.retry;
    // A caught audit error must never turn a successful mutation into an unaudited commit.
    if (state.writes && state.auditFailure) throw state.auditFailure;
    if (state.writes && (result as { isFailure?: boolean } | null)?.isFailure) throw new FailedResult(result);
    return result;
  }

  private async nested<T>(work: () => Promise<T>): Promise<T> {
    const parent = this.context.getStore()!;
    const name = `workflow_${++parent.sequence.value}`;
    const child: Context = { tx: parent.tx, writes: 0, afterCommit: [], sequence: parent.sequence };
    await parent.tx.$executeRawUnsafe(`SAVEPOINT ${name}`);
    try {
      const result = await this.context.run(child, async () => this.check(child, await work()));
      await parent.tx.$executeRawUnsafe(`RELEASE SAVEPOINT ${name}`);
      parent.writes += child.writes;
      parent.afterCommit.push(...child.afterCommit);
      return result;
    } catch (error) {
      await parent.tx.$executeRawUnsafe(`ROLLBACK TO SAVEPOINT ${name}`);
      await parent.tx.$executeRawUnsafe(`RELEASE SAVEPOINT ${name}`);
      if (error instanceof OwnershipChanged) parent.retry = error;
      if (error instanceof FailedResult) return error.result as T;
      throw error;
    }
  }

  async run<T>(scope: WorkflowScope, input: { tenantId: string; [key: string]: unknown }, work: () => Promise<T>): Promise<T> {
    if (!input.tenantId) throw new Error("Trusted tenant context required");
    const execute = async () => { await this.lock(scope, input); return work(); };
    if (this.context.getStore()) return this.nested(execute);
    const afterCommit: Array<() => Promise<void>> = [];
    let result!: T;
    for (let attempt = 0; attempt < 3; attempt++) {
      afterCommit.length = 0;
      try {
        result = await this.base.$transaction(async tx => {
          const state: Context = { tx, writes: 0, afterCommit, sequence: { value: 0 } };
          return this.context.run(state, async () => this.check(state, await execute()));
        }, { maxWait: 10000, timeout: 30000 });
        break;
      } catch (error) {
        if (error instanceof FailedResult) return error.result as T;
        // Only pre-write ownership discovery retries; no external effects have run.
        if (error instanceof OwnershipChanged && attempt < 2) continue;
        throw error;
      }
    }
    // Commit has completed; failures here cannot undo the already audited workflow transition.
    for (const effect of afterCommit) {
      try { await effect(); } catch (error) { console.error("Post-commit workflow effect failed", error instanceof Error ? error.message : error); }
    }
    return result;
  }

  async afterCommit(work: () => Promise<void>): Promise<void> {
    const current = this.context.getStore();
    if (current) current.afterCommit.push(work);
    else await work();
  }

  defer<T extends object>(target: T, methods: Array<keyof T>): T {
    return new Proxy(target, { get: (object, property) => {
      const value = Reflect.get(object, property, object);
      if (typeof value !== "function") return value;
      if (methods.includes(property as keyof T)) return (...args: unknown[]) => this.afterCommit(() => value.apply(object, args));
      return value.bind(object);
    } });
  }

  wrap<T extends object>(target: T, scope: WorkflowScope, method: keyof T = "execute" as keyof T): T {
    const original = (target[method] as unknown as (input: { tenantId: string; [key: string]: unknown }) => Promise<unknown>).bind(target);
    (target[method] as unknown) = (input: { tenantId: string; [key: string]: unknown }) => this.run(scope, input, () => original(input));
    return target;
  }

  private async lock(scope: WorkflowScope, input: { tenantId: string; [key: string]: unknown }): Promise<void> {
    const tx = this.context.getStore()!.tx;
    const tenantId = input.tenantId;
    const incidents = new Set<string>();
    if (typeof input.incidentId === "string") incidents.add(input.incidentId);
    if (scope === "incident" && typeof input.id === "string") incidents.add(input.id);
    const recommendationId = input.recommendationId ?? (scope === "recommendation" ? input.id : undefined) ?? (input.recommendation as { id?: string } | undefined)?.id;
    if (typeof recommendationId === "string") {
      const r = await tx.recommendation.findFirst({ where: { id: recommendationId, tenantId }, select: { incidentId: true } });
      if (r) incidents.add(r.incidentId);
    }
    if (typeof input.responseId === "string") {
      const r = await tx.responsePlan.findFirst({ where: { id: input.responseId, tenantId }, select: { incidentId: true } });
      if (r) incidents.add(r.incidentId);
    }
    if (typeof input.approvalId === "string") {
      const a = await tx.approval.findFirst({ where: { id: input.approvalId, recommendation: { tenantId } }, select: { recommendation: { select: { incidentId: true } } } });
      if (a?.recommendation) incidents.add(a.recommendation.incidentId);
    }
    const alerts = Array.isArray(input.alertIds) ? input.alertIds.filter((id): id is string => typeof id === "string") : [];
    if (alerts.length) {
      // Lock aliases too: two stored rows for one SIEM identity must not create separate incidents.
      const selected = await tx.alert.findMany({ where: { id: { in: alerts }, tenantId }, select: { siemSource: true, externalAlertId: true } });
      if (selected.length) {
        const aliases = await tx.alert.findMany({ where: { tenantId, OR: selected.map(a => ({ siemSource: a.siemSource, externalAlertId: a.externalAlertId })) }, select: { id: true } });
        alerts.push(...aliases.map(a => a.id));
      }
      const links = await tx.incidentAlert.findMany({ where: { alertId: { in: alerts }, incident: { tenantId } }, select: { incidentId: true } });
      links.forEach(link => incidents.add(link.incidentId));
    }
    // Stable order across merge, approval, response and verification avoids lock-order inversions.
    for (const id of [...incidents].sort()) await tx.$queryRaw`SELECT id FROM incidents WHERE id = ${id} AND tenant_id = ${tenantId} FOR UPDATE`;
    for (const id of [...new Set(alerts)].sort()) await tx.$queryRaw`SELECT id FROM alerts WHERE id = ${id} AND tenant_id = ${tenantId} FOR UPDATE`;
    if (alerts.length) {
      const fresh = await tx.incidentAlert.findMany({ where: { alertId: { in: alerts }, incident: { tenantId } }, select: { incidentId: true } });
      if (fresh.some(link => !incidents.has(link.incidentId))) throw new OwnershipChanged();
    }
    if (scope === "playbook" && typeof input.id === "string") await tx.$queryRaw`SELECT id FROM playbooks WHERE id = ${input.id} AND tenant_id = ${tenantId} FOR UPDATE`;
    else if (scope === "intake" || (scope === "playbook" && !input.id)) await tx.$queryRaw`SELECT id FROM tenants WHERE id = ${tenantId} FOR UPDATE`;
  }
}
