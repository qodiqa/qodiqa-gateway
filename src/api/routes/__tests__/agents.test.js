'use strict';

/**
 * /v1/agents and /v1/sessions (src/api/routes/agents.js) over the memory store.
 *
 *   RT-01  agent lifecycle over HTTP: create (201), duplicate (409), list, get, change limits, suspend / revoke (absorbing)
 *   RT-02  session lifecycle: start with min() limits, get, end, kill; another tenant's session is a 404
 *   RT-03  validation errors carry their precise code; a store failure is a 503 that leaks nothing
 *   RT-04  the permissions asked for: MANAGE_AGENTS / READ_AGENTS / MANAGE_AGENT_SESSIONS
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const express = require('express');
const request = require('supertest');
const store = require('../../../core/agents/agentStore');
const { createAgentsRouter } = require('../agents');
const { createSessionsRouter } = require('../agentSessions');

function app({ allow = true } = {}) {
  const asked = [];
  const requirePermission = (p) => (req, res, next) => { asked.push(p); return allow ? next() : res.status(403).json({ status: 'failure', error: { code: 'FORBIDDEN' } }); };
  const a = express();
  a.use(express.json());
  a.use((req, res, next) => { req.rbacUser = { id: 'op-1' }; next(); });
  a.use('/v1/agents', createAgentsRouter({ requirePermission }));
  a.use('/v1/sessions', createSessionsRouter({ requirePermission }));
  return { a, asked };
}
beforeEach(() => store._resetForTests());

describe('routes', () => {
  test('RT-01 agent lifecycle', async () => {
    const { a } = app();
    const c = await request(a).post('/v1/agents').send({ tenantId: 't1', displayName: 'Bot', allowedActionClasses: ['read'], maxActionsPerSession: 3 });
    expect(c.status).toBe(201); expect(c.body.data).toMatchObject({ status: 'active', maxActionsPerSession: 3 });
    const bot = c.body.data.agentId; expect(bot).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect((await request(a).post('/v1/agents').send({ tenantId: 't1', agentId: 'mine', displayName: 'Bot' })).body.error.code).toBe('AGENT_ID_IS_ISSUED');
    expect((await request(a).get('/v1/agents?tenantId=t1')).body.data.agents.map((x) => x.agentId)).toEqual([bot]);
    expect((await request(a).get(`/v1/agents/${bot}?tenantId=t1`)).body.data.displayName).toBe('Bot');
    expect((await request(a).get(`/v1/agents/${bot}?tenantId=t2`)).status).toBe(404);
    const p = await request(a).patch(`/v1/agents/${bot}`).send({ tenantId: 't1', maxActionsPerSession: 7 });
    expect(p.body.data.maxActionsPerSession).toBe(7);
    expect((await request(a).patch(`/v1/agents/${bot}`).send({ tenantId: 't1', status: 'revoked' })).body.data.status).toBe('revoked');
    expect((await request(a).patch(`/v1/agents/${bot}`).send({ tenantId: 't1', status: 'active' })).status).toBe(409);
  });

  test('RT-02 session lifecycle', async () => {
    const { a } = app();
    const bot = (await request(a).post('/v1/agents').send({ tenantId: 't1', displayName: 'Bot', allowedActionClasses: ['read'], maxActionsPerSession: 3 })).body.data.agentId;
    const s = await request(a).post('/v1/sessions').send({ tenantId: 't1', agentId: bot, maxActions: 50, ttlSeconds: 60 });
    expect(s.status).toBe(201); expect(s.body.data).toMatchObject({ status: 'active', maxActions: 3 });
    const id = s.body.data.sessionId;
    expect((await request(a).get(`/v1/sessions/${id}?tenantId=t1`)).body.data.sessionId).toBe(id);
    expect((await request(a).get(`/v1/sessions/${id}?tenantId=t2`)).status).toBe(404);
    expect((await request(a).get('/v1/sessions?tenantId=t1&status=active')).body.data.sessions).toHaveLength(1);
    expect((await request(a).post(`/v1/sessions/${id}/kill`).send({ tenantId: 't2' })).status).toBe(404);
    const k = await request(a).post(`/v1/sessions/${id}/kill`).send({ tenantId: 't1', reason: 'loop' });
    expect(k.body.data).toMatchObject({ status: 'killed', endedReason: 'loop' });
    const s2 = await request(a).post('/v1/sessions').send({ tenantId: 't1', agentId: bot });
    expect((await request(a).post(`/v1/sessions/${s2.body.data.sessionId}/end`).send({ tenantId: 't1' })).body.data.status).toBe('ended');
    expect((await request(a).post('/v1/sessions').send({ tenantId: 't1', agentId: '11111111-1111-4111-8111-111111111111' })).status).toBe(404);
  });

  test('RT-03 precise validation codes; a store failure is a 503 that leaks nothing', async () => {
    const { a } = app();
    const bad = await request(a).post('/v1/agents').send({ tenantId: 't1', displayName: 'Bot', allowedActionClasses: ['launch-missiles'] });
    expect(bad.status).toBe(400); expect(bad.body.error.code).toBe('INVALID_ACTION_CLASSES');
    expect((await request(a).post('/v1/agents').send({ displayName: 'Bot' })).body.error.code).toBe('INVALID_TENANT_ID');
    expect((await request(a).get('/v1/sessions/not-a-uuid?tenantId=t1')).body.error.code).toBe('INVALID_SESSION_ID');
    const spy = jest.spyOn(store, 'listAgents').mockRejectedValue(new Error('connect ECONNREFUSED 10.1.2.3:5432'));
    const r = await request(a).get('/v1/agents?tenantId=t1');
    expect(r.status).toBe(503); expect(JSON.stringify(r.body)).not.toMatch(/10\.1\.2\.3|5432/);
    spy.mockRestore();
  });

  test('RT-04 permissions', async () => {
    const { a, asked } = app();
    await request(a).get('/v1/agents?tenantId=t1');
    const x1 = (await request(a).post('/v1/agents').send({ tenantId: 't1', displayName: 'X' })).body.data.agentId;
    await request(a).post('/v1/sessions').send({ tenantId: 't1', agentId: x1 });
    expect(asked).toEqual(['READ_AGENTS', 'MANAGE_AGENTS', 'MANAGE_AGENT_SESSIONS']);
    const d = app({ allow: false });
    expect((await request(d.a).post('/v1/agents').send({ tenantId: 't1', displayName: 'Y' })).status).toBe(403);
    expect(await store.listAgents('t1')).toHaveLength(1);                     // only x1 exists
    const { PERMISSIONS } = require('../../../core/rbac/roles');
    expect(PERMISSIONS.MANAGE_AGENTS).toEqual(['admin']);
    expect(PERMISSIONS.MANAGE_AGENT_SESSIONS).toEqual(expect.arrayContaining(['admin', 'operator']));
    expect(PERMISSIONS.READ_AGENTS).not.toContain('viewer');
  });
});
