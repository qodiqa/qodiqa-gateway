'use strict';

/**
 *.1-F6B.4 - agent identities and sessions (process-memory store; the PostgreSQL store is proven in test/integration/agents.integration.test.js).
 *
 *   AG-01  creating an agent validates every field; the agentId is ISSUED by the gateway (UUID v4) and cannot be chosen
 *   AG-02  a session never has more autonomy than its agent: effective limits = min(requested, agent, platform caps)
 *   AG-03  revoked is absorbing; suspending or revoking ends the agent's active sessions; a revoked agent has no usable session
 * AG-04 checkSession: unknown / foreign-tenant / foreign-agent sessions are indistinguishable; expired, ended, killed and inactive-agent are named
 * AG-05 reserveAction: budget, cost, action class, the action chain (seq and previous hash), session expiry
 * AG-06 force-stop: killSession aborts the registered executions of the session at once and every later check / reservation refuses it
 *   AG-07  tenant isolation of every read and write
 */

jest.mock('../../../../services/logger', () => ({ emit: jest.fn() }));

const crypto = require('crypto');
const store = require('../agentStore');
const killRegistry = require('../killRegistry');

const T = 'tenant-a'; const U = 'tenant-b';
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const H = (c) => c.repeat(64);
const spki = () => crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
const mk = (over = {}, tenant = T) => store.createAgent(tenant, { displayName: 'Agent One', allowedActionClasses: ['read', 'external_api'], ...over }, 'op');
beforeEach(() => { store._resetForTests(); jest.useRealTimers(); });

describe('agents', () => {
  test('AG-01 validation; the agentId is issued by the gateway', async () => {
    const a = await mk({ publicKey: spki(), ownerUserId: 'u-1', maxActionsPerSession: 10, maxSessionSeconds: 600, costBudgetMicros: 5_000_000 });
    expect(a.agentId).toMatch(UUID4);
    expect(a).toMatchObject({ tenantId: T, status: 'active', ownerUserId: 'u-1', allowedActionClasses: ['external_api', 'read'], maxActionsPerSession: 10, costBudgetMicros: 5_000_000 });
    const b = await mk();
    expect(b.agentId).not.toBe(a.agentId);                                                          // same name, two identities
    await expect(mk({ agentId: 'chosen-by-the-caller' })).rejects.toMatchObject({ code: 'AGENT_ID_IS_ISSUED', status: 400 });
    expect((await mk({}, U)).tenantId).toBe(U);
    const bad = [
      [{ displayName: '' }, 'INVALID_DISPLAY_NAME'], [{ allowedActionClasses: ['read', 'rm -rf'] }, 'INVALID_ACTION_CLASSES'], [{ allowedActionClasses: ['read', 'read'] }, 'INVALID_ACTION_CLASSES'],
      [{ publicKey: 'AAAA' }, 'INVALID_PUBLIC_KEY'], [{ maxActionsPerSession: -1 }, 'INVALID_LIMIT'], [{ maxActionsPerSession: 1.5 }, 'INVALID_LIMIT'], [{ maxSessionSeconds: 0 }, 'INVALID_LIMIT'],
      [{ costBudgetMicros: -5 }, 'INVALID_LIMIT'], [{ ownerUserId: '' }, 'INVALID_OWNER'],
    ];
    for (const [over, code] of bad) await expect(mk(over)).rejects.toMatchObject({ code });
    await expect(mk({}, 'bad tenant!')).rejects.toMatchObject({ code: 'INVALID_TENANT_ID' });
    await expect(store.getAgent(T, 'not-a-uuid')).rejects.toMatchObject({ code: 'INVALID_AGENT_ID' });
  });

  test('AG-02 a session cannot have more autonomy than its agent', async () => {
    const a = await mk({ maxActionsPerSession: 5, maxSessionSeconds: 120, costBudgetMicros: 1000 });
    const s = await store.startSession(T, a.agentId, { ttlSeconds: 86_400, maxActions: 1000, costBudgetMicros: 999_999 }, 'op');
    expect(s.maxActions).toBe(5); expect(s.costBudgetMicros).toBe(1000);
    expect(Date.parse(s.expiresAt) - Date.parse(s.startedAt)).toBe(120_000);
    const lower = await store.startSession(T, a.agentId, { ttlSeconds: 30, maxActions: 2, costBudgetMicros: 10 }, 'op');
    expect(lower.maxActions).toBe(2); expect(lower.costBudgetMicros).toBe(10); expect(Date.parse(lower.expiresAt) - Date.parse(lower.startedAt)).toBe(30_000);
    const u = await mk({ displayName: 'Unbounded' });
    await expect(store.startSession(T, u.agentId, { ttlSeconds: 10 ** 9 }, 'op')).rejects.toMatchObject({ code: 'INVALID_LIMIT' });          // above the platform cap
    const d = await store.startSession(T, u.agentId, {}, 'op');
    expect(d.maxActions).toBe(100); expect(Date.parse(d.expiresAt) - Date.parse(d.startedAt)).toBe(3_600_000);
    await expect(store.startSession(T, crypto.randomUUID(), {}, 'op')).rejects.toMatchObject({ code: 'AGENT_NOT_FOUND', status: 404 });
  });

  test('AG-03 revoked is absorbing; suspend / revoke end the active sessions', async () => {
    const a = await mk(); const id = a.agentId;
    const s1 = await store.startSession(T, id, {}, 'op'); const s2 = await store.startSession(T, id, {}, 'op');
    expect((await store.updateAgent(T, id, { status: 'suspended' }, 'op')).status).toBe('suspended');
    expect((await store.getSession(T, s1.sessionId)).status).toBe('killed');
    await expect(store.startSession(T, id, {}, 'op')).rejects.toMatchObject({ code: 'AGENT_NOT_ACTIVE' });
    expect((await store.updateAgent(T, id, { status: 'active' }, 'op')).status).toBe('active');   // suspension is reversible
    const s3 = await store.startSession(T, id, {}, 'op');
    const rev = await store.updateAgent(T, id, { status: 'revoked' }, 'op');
    expect(rev.status).toBe('revoked'); expect(rev.revokedAt).not.toBeNull();
    expect((await store.getSession(T, s3.sessionId)).status).toBe('killed');
    expect((await store.getSession(T, s2.sessionId)).status).toBe('killed');
    await expect(store.updateAgent(T, id, { status: 'active' }, 'op')).rejects.toMatchObject({ code: 'AGENT_REVOKED', status: 409 });
    await expect(store.updateAgent(T, id, { displayName: 'x' }, 'op')).rejects.toMatchObject({ code: 'AGENT_REVOKED' });
    expect(await store.checkSession(T, id, s3.sessionId)).toMatchObject({ ok: false });
  });

  test('AG-04 checkSession names what is wrong and hides what exists elsewhere', async () => {
    const a1 = await mk(); const a2 = await mk({ displayName: 'Two' }); const other = await mk({}, U);
    const s = await store.startSession(T, a1.agentId, { ttlSeconds: 1 }, 'op');
    expect(await store.checkSession(T, a1.agentId, s.sessionId)).toMatchObject({ ok: true });
    const unknown = { ok: false, reason: 'AGENT_SESSION_UNKNOWN' };
    expect(await store.checkSession(T, a1.agentId, crypto.randomUUID())).toEqual(unknown);
    expect(await store.checkSession(U, other.agentId, s.sessionId)).toEqual(unknown);           // another tenant's session
    expect(await store.checkSession(T, a2.agentId, s.sessionId)).toEqual(unknown);              // another agent's session
    expect(await store.checkSession(T, a1.agentId, 'not-a-uuid')).toEqual({ ok: false, reason: 'AGENT_SESSION_INVALID' });
    await store.endSession(T, s.sessionId, 'done', 'op');
    expect(await store.checkSession(T, a1.agentId, s.sessionId)).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });
    const e = await store.startSession(T, a1.agentId, { ttlSeconds: 1 }, 'op');
    const real = Date.now; Date.now = () => real() + 2000;
    try { expect(await store.checkSession(T, a1.agentId, e.sessionId)).toEqual({ ok: false, reason: 'AGENT_SESSION_EXPIRED' }); } finally { Date.now = real; }
    expect((await store.getSession(T, e.sessionId)).status).toBe('expired');
  });

  test('AG-05 reserveAction enforces budget, cost, action class and the action chain', async () => {
    const a = await mk({ maxActionsPerSession: 3, costBudgetMicros: 100 });
    const s = await store.startSession(T, a.agentId, {}, 'op'); const id = s.sessionId;
    expect(await store.reserveAction(T, id, { actionClass: 'financial' })).toEqual({ ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' });         //
    expect(await store.reserveAction(T, id, { actionClass: 'nonsense' })).toEqual({ ok: false, reason: 'ACTION_CLASS_INVALID' });
    expect(await store.reserveAction(T, id, { actionClass: 'read', costMicros: -1 })).toEqual({ ok: false, reason: 'COST_INVALID' });
    const a1 = await store.reserveAction(T, id, { actionClass: 'read', costMicros: 60, actionHash: H('a'), prevActionHash: null });
    expect(a1).toMatchObject({ ok: true, seq: 1 }); expect(a1.session).toMatchObject({ actionsUsed: 1, nextSeq: 2, lastActionHash: H('a'), costUsedMicros: 60 });
    expect(await store.reserveAction(T, id, { actionClass: 'read', prevActionHash: H('b') })).toEqual({ ok: false, reason: 'ACTION_CHAIN_MISMATCH' });   // omitted / reordered / replayed
    expect(await store.reserveAction(T, id, { actionClass: 'read', prevActionHash: null })).toEqual({ ok: false, reason: 'ACTION_CHAIN_MISMATCH' });
    expect(await store.reserveAction(T, id, { actionClass: 'external_api', costMicros: 50, prevActionHash: H('a') })).toEqual({ ok: false, reason: 'COST_BUDGET_EXHAUSTED' });
    expect(await store.reserveAction(T, id, { actionClass: 'external_api', costMicros: 40, actionHash: H('c'), prevActionHash: H('a') })).toMatchObject({ ok: true, seq: 2 });
    expect(await store.reserveAction(T, id, { actionClass: 'read', actionHash: H('d'), prevActionHash: H('c') })).toMatchObject({ ok: true, seq: 3 });
    expect(await store.reserveAction(T, id, { actionClass: 'read' })).toEqual({ ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' });
    const c = await mk({ displayName: 'C', allowedActionClasses: ['read'], maxActionsPerSession: 5 });
    const sc = await store.startSession(T, c.agentId, {}, 'op');
    const got = await Promise.all(Array.from({ length: 12 }, () => store.reserveAction(T, sc.sessionId, { actionClass: 'read' })));
    expect(got.filter((x) => x.ok)).toHaveLength(5);
    expect(new Set(got.filter((x) => x.ok).map((x) => x.seq)).size).toBe(5);
  });

  test('AG-06 force-stop aborts what runs and refuses what follows', async () => {
    const a = await mk();
    const s = await store.startSession(T, a.agentId, {}, 'op');
    const c1 = new AbortController(); const c2 = new AbortController(); const other = new AbortController();
    const un = killRegistry.register(T, s.sessionId, c1, 'provider call'); killRegistry.register(T, s.sessionId, c2, 'tool call'); killRegistry.register(T, crypto.randomUUID(), other);
    expect(killRegistry.count(T, s.sessionId)).toBe(2);
    const k = await store.killSession(T, s.sessionId, 'runaway loop', 'op');
    expect(k).toMatchObject({ status: 'killed', endedReason: 'runaway loop' });
    expect(c1.signal.aborted && c2.signal.aborted).toBe(true);
    expect(c1.signal.reason.code).toBe('AGENT_SESSION_KILLED');
    expect(other.signal.aborted).toBe(false);
    un();
    expect(await store.checkSession(T, a.agentId, s.sessionId)).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });
    expect(await store.reserveAction(T, s.sessionId, { actionClass: 'read' })).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });
    await expect(store.killSession(T, crypto.randomUUID(), 'x', 'op')).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND', status: 404 });
    expect((await store.killSession(T, s.sessionId, 'again', 'op')).status).toBe('killed');          // idempotent
  });

  test('AG-06b runUnderSession: a running execution is aborted by the kill, and unregistered when it ends however it ends', async () => {
    const a = await mk(); const s = await store.startSession(T, a.agentId, {}, 'op');
    let seen = null;
    const run = killRegistry.runUnderSession(T, s.sessionId, (signal) => new Promise((resolve, reject) => { signal.addEventListener('abort', () => { seen = signal.reason.code; reject(signal.reason); }); }), 'tool call');
    await new Promise((r) => setImmediate(r));
    expect(killRegistry.count(T, s.sessionId)).toBe(1);
    await store.killSession(T, s.sessionId, 'stop', 'op');
    await expect(run).rejects.toMatchObject({ code: 'AGENT_SESSION_KILLED' });
    expect(seen).toBe('AGENT_SESSION_KILLED');
    expect(killRegistry.count(T, s.sessionId)).toBe(0);
    const b2 = await store.startSession(T, a.agentId, {}, 'op');
    expect(await killRegistry.runUnderSession(T, b2.sessionId, async () => 'done')).toBe('done');
    await expect(killRegistry.runUnderSession(T, b2.sessionId, async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(killRegistry.count(T, b2.sessionId)).toBe(0);
  });

  test('AG-07 tenants never see each other', async () => {
    const a = await mk(); const s = await store.startSession(T, a.agentId, {}, 'op');
    expect(await store.getAgent(U, a.agentId)).toBeNull();
    expect(await store.getSession(U, s.sessionId)).toBeNull();
    expect(await store.listAgents(U)).toEqual([]); expect(await store.listSessions(U)).toEqual([]);
    await expect(store.updateAgent(U, a.agentId, { status: 'revoked' }, 'op')).rejects.toMatchObject({ code: 'AGENT_NOT_FOUND' });
    await expect(store.endSession(U, s.sessionId, 'x', 'op')).rejects.toMatchObject({ code: 'SESSION_NOT_FOUND' });
    expect((await store.getSession(T, s.sessionId)).status).toBe('active');
  });
});
