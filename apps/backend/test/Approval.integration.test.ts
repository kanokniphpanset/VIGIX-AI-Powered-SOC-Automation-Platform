import express from 'express';
import { AddressInfo } from 'node:net';
import { buildApprovalRoutes } from '../src/presentation/http/routes/approval.routes';
import { signToken } from '../src/presentation/http/middlewares/auth.middleware';

test('HTTP approval gate rejects AI authorization while allowing the human approval handler', async () => {
  const reached: string[] = [];
  const handler = (_req: express.Request, res: express.Response) => { reached.push('human'); res.json({ ok: true }); };
  const app = express(); app.use(express.json());
  app.use('/approvals', buildApprovalRoutes({ request: handler, getById: handler, approve: handler, reject: handler } as never));
  const server = app.listen(0);
  await new Promise<void>(resolve => server.once('listening', resolve));
  try {
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/approvals/approval-test/approve`;
    const post = (role: string) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${signToken({ id: 'test', tenantId: 'isolated-test', role })}` }, body: JSON.stringify({ approved: true, reason: 'Model says safe' }) });
    expect((await post('AI')).status).toBe(403);
    expect(reached).toEqual([]);
    // Two roles: only IR_TEAM decides. SOC and a retired MANAGER token are refused before any handler runs.
    expect((await post('SOC')).status).toBe(403);
    expect((await post('MANAGER')).status).toBe(403);
    expect(reached).toEqual([]);
    expect((await post('IR_TEAM')).status).toBe(200);
    expect(reached).toEqual(['human']);
  } finally { await new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve())); }
});
