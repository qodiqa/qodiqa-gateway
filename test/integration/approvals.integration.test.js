'use strict';

/**
 * approval_requests (migration 106) on real PostgreSQL, through the real store.
 *
 *   AR-01  ownership, forced RLS, constraints: the approver is never the requester, one LIVE request per session position, decided/window/used consistency
 *   AR-02  privileges: the action facts are fixed at insert; only the decision moves; no delete
 *   AR-03  tenant isolation
 *   AR-04  concurrency (two replicas, one database): one decision wins, one spend wins, expiry and release are applied once
 *   AR-05  a request that ends unapproved gives its position back; the position is reusable (the partial unique index)
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const DB = `qodiqa_f6f_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PW = 'QODIQA_PG_' + 'PASSWORD';
const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });
const T = 'default'; const U = 'tenant-b';
const H = () => crypto.randomBytes(32).toString('hex');

let maint; let admin; let pgPool; let A; let B;
const saved = {};
const load = () => ({ pool: require('../../src/infra/postgres/pool'), agents: require('../../src/core/agents/agentStore'), approvals: require('../../src/core/approvals/approvalStore'), executor: require('../../src/core/actions/executor') });

async function world(tenant = T, opts = {}) {
  const a = await A.agents.createAgent(tenant, { displayName: 'Bot', allowedActionClasses: ['communication'], ...opts }, 'op');
  const s = await A.agents.startSession(tenant, a.agentId, {}, 'op');
  return { agentId: a.agentId, sessionId: s.sessionId };
}
/** reserve the next position of the session and open a request for it - what the authorize route does */
async function openRequest(w, { tenant = T, requesterId = 'identity:i1', requesterUserId = null, store = A } = {}) {
  const s = await store.agents.getSession(tenant, w.sessionId);
  const actionHash = H();
  const r = await store.agents.reserveAction(tenant, w.sessionId, { actionClass: 'communication', actionHash, prevActionHash: s.lastActionHash });
  expect(r.ok).toBe(true);
  return store.approvals.request(tenant, { sessionId: w.sessionId, agentId: w.agentId, seq: r.seq, actionHash, prevActionHash: s.lastActionHash, server: 'srv', tool: 'notify', schemaHash: H(), actionClass: 'communication',
    args: { to: 'x@y.z' }, requesterId, requesterUserId });
}

describeOrSkip('approvals (real PostgreSQL)', () => {
  beforeAll(async () => {
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_CLIENT_ID', 'QODIQA_APPROVAL_NOTIFY']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB; process.env.QODIQA_CLIENT_ID = T; process.env.QODIQA_APPROVAL_NOTIFY = 'false';
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    require('../helpers/signingIdentity').provisionTestSigningIdentity({ tenantId: T });
    A = load();
    jest.isolateModules(() => { B = load(); B.pool.initialize(); });
    admin = new Pool({ ...baseCfg(), ...maintCreds(), database: DB });
  });
  afterAll(async () => {
    if (B && B.pool) await B.pool.shutdown().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (admin) await admin.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try {
        await maint.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [DB]);
        await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      } catch (err) { console.warn(`[f6f] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('AR-01 ownership, forced RLS, constraints', async () => {
    const t = (await admin.query("SELECT c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname = 'approval_requests'")).rows[0];
    expect([t.rls, t.forced]).toEqual([true, true]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) expect(t.owner).toBe('qodiqa_owner');
    const w = await world();
    const ins = (over = {}, extraCols = '', extraVals = '') => {
      const v = { id: crypto.randomUUID(), seq: 50 + Math.floor(Math.random() * 1e6), ...over };
      return admin.query(`INSERT INTO approval_requests (tenant_id, approval_id, session_id, agent_id, seq, action_hash, server_id, tool_name, schema_hash, action_class, args, requester_id, policy_rule_id, expires_at${extraCols})
        VALUES ('${T}', $1, $2, $3, $4, $5, 's', 't', $5, 'communication', '{}'::jsonb, 'identity:i1', 'tool:requiresApproval', now() + interval '10 minutes'${extraVals})`, [v.id, w.sessionId, w.agentId, v.seq, H()]);
    };
    await ins({ seq: 10 });
    await expect(ins({ seq: 10 })).rejects.toThrow(/position_live/);                                                  // one live request per position
    await expect(ins({}, ', approver_id, decided_at, decision_token, status', ", 'identity:i1', now(), '{}'::jsonb, 'DENIED'")).rejects.toThrow(/independent/);   // the approver is the requester
    await expect(ins({}, ', requester_user_id, approver_id, decided_at, decision_token, status', ", 'alice', 'alice', now(), '{}'::jsonb, 'DENIED'")).rejects.toThrow(/independent/);   // ... or the user the agent acts for
    await expect(ins({}, ', status', ", 'APPROVED'")).rejects.toThrow(/decided_consistent|window/);
    await expect(ins({}, ', status, approver_id, decided_at, decision_token, not_before, approval_expires_at', ", 'APPROVED', 'bob', now(), '{}'::jsonb, now(), now() - interval '1 minute'")).rejects.toThrow(/window/);
    await expect(ins({}, ', used_at', ', now()')).rejects.toThrow(/used_only_approved/);
    await expect(ins({}, ', status', ", 'PENDING'::text || 'x'")).rejects.toThrow();
    await expect(admin.query("INSERT INTO approval_requests (tenant_id, approval_id, session_id, agent_id, seq, action_hash, server_id, tool_name, schema_hash, action_class, args, requester_id, policy_rule_id, expires_at) VALUES ('x', gen_random_uuid(), gen_random_uuid(), 'a', 1, 'zz', 's', 't', 'zz', 'c', '{}', 'r', 'p', now())")).rejects.toThrow();
    // a terminal request frees its position
    await admin.query("UPDATE approval_requests SET status = 'EXPIRED', expired_at = now() WHERE session_id = $1 AND seq = 10", [w.sessionId]);
    await ins({ seq: 10 });
  });

  test('AR-02 privileges: the action is fixed, only the decision moves', async () => {
    const w = await world();
    await openRequest(w);
    const c = await admin.connect();
    const asRole = async (role, sql) => { await c.query('BEGIN'); await c.query(`SET LOCAL ROLE ${role}`); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]); try { return await c.query(sql); } finally { await c.query('ROLLBACK'); } };
    try {
      for (const col of ["action_hash = '" + 'b'.repeat(64) + "'", 'seq = 9', "args = '{}'::jsonb", "tool_name = 'other'", "requester_id = 'x'", "requested_at = now()", "expires_at = now() + interval '9 days'", "agent_id = 'z'", "tenant_id = 'x'", "session_id = gen_random_uuid()", "requester_user_id = 'u'"])
        await expect(asRole('qodiqa_app', `UPDATE approval_requests SET ${col}`)).rejects.toThrow(/permission denied/i);
      await expect(asRole('qodiqa_app', 'DELETE FROM approval_requests')).rejects.toThrow(/permission denied/i);
      expect((await asRole('qodiqa_app', "UPDATE approval_requests SET status = 'CANCELLED', cancelled_by = 'x', cancelled_at = now() WHERE status = 'PENDING'")).rowCount).toBeGreaterThanOrEqual(1);
      expect((await asRole('qodiqa_read', 'SELECT 1 FROM approval_requests')).rowCount).toBeGreaterThanOrEqual(1);
      await expect(asRole('qodiqa_read', "UPDATE approval_requests SET status = 'CANCELLED'")).rejects.toThrow(/permission denied/i);
    } finally { c.release(); }
  });

  test('AR-03 tenant isolation', async () => {
    require('../../services/artifact/keyStore').rotateKey(U);
    const w = await world(U);
    const a = await openRequest(w, { tenant: U });
    expect(await A.approvals.get(T, a.approvalId)).toBeNull();
    expect((await A.approvals.list(T)).map((x) => x.approvalId)).not.toContain(a.approvalId);
    expect((await A.approvals.get(U, a.approvalId)).status).toBe('PENDING');
    await expect(A.approvals.decide(T, a.approvalId, { decision: 'DENY', reason: 'x' }, { id: 'bob' })).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app');
      expect((await c.query('SELECT 1 FROM approval_requests')).rows).toEqual([]);
      await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      expect((await c.query("UPDATE approval_requests SET status = 'CANCELLED', cancelled_at = now() WHERE tenant_id = 'tenant-b'")).rowCount).toBe(0);
      await c.query('ROLLBACK');
    } finally { c.release(); }
  });

  test('AR-04 concurrency across replicas', async () => {
    // decisions: eight approvers race, one wins; the loser(s) see APPROVAL_NOT_PENDING
    const w = await world();
    const a = await openRequest(w);
    const res = await Promise.allSettled(Array.from({ length: 8 }, (_, i) => (i % 2 ? A : B).approvals.decide(T, a.approvalId, { decision: 'APPROVE' }, { id: `approver-${i}` })));
    expect(res.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    expect(res.filter((r) => r.status === 'rejected').every((r) => ['APPROVAL_NOT_PENDING'].includes(r.reason.code))).toBe(true);
    const done = await A.approvals.get(T, a.approvalId);
    expect(done).toMatchObject({ status: 'APPROVED', mfa: 'step-up' });
    expect(done.decisionToken.payload.approverId).toBe(done.approverId);
    // the spend: eight artifacts race for one approval, one wins
    const expected = { agentId: w.agentId, sessionId: w.sessionId, actionHash: a.actionHash };
    const spends = await Promise.all(Array.from({ length: 8 }, () => (Math.random() < 0.5 ? A : B).approvals.issue(T, a.approvalId, expected, { requestId: crypto.randomUUID() })));
    expect(spends.filter((s) => s.ok)).toHaveLength(1);
    expect(spends.filter((s) => !s.ok).every((s) => s.reason === 'APPROVAL_ALREADY_USED')).toBe(true);
    const used = await A.approvals.get(T, a.approvalId);
    expect(used.usedAt).toBeTruthy();
    // a different action cannot spend it
    const w2 = await world(); const a2 = await openRequest(w2); await A.approvals.decide(T, a2.approvalId, { decision: 'APPROVE' }, { id: 'bob' });
    expect(await A.approvals.issue(T, a2.approvalId, { ...expected, agentId: w2.agentId, sessionId: w2.sessionId }, { requestId: crypto.randomUUID() })).toMatchObject({ ok: false, reason: 'APPROVAL_INVALID' });
    // the independence rule at the database too
    const w3 = await world(T, { ownerUserId: 'alice' }); const a3 = await openRequest(w3, { requesterUserId: 'alice' });
    await expect(A.approvals.decide(T, a3.approvalId, { decision: 'APPROVE' }, { id: 'alice' })).rejects.toMatchObject({ code: 'APPROVAL_NOT_INDEPENDENT' });
    await expect(admin.query("UPDATE approval_requests SET status = 'DENIED', approver_id = 'alice', decided_at = now(), decision_token = '{}'::jsonb WHERE approval_id = $1", [a3.approvalId])).rejects.toThrow(/independent/);
    // expiry is applied once even when two replicas sweep at the same time
    const w4 = await world();
    const a4 = await openRequest(w4);
    await admin.query("UPDATE approval_requests SET expires_at = now() - interval '1 second' WHERE approval_id = $1", [a4.approvalId]);
    const swept = await Promise.all([A.approvals.expireDue(T), B.approvals.expireDue(T), A.approvals.expireDue(T)]);
    expect(swept.reduce((x, y) => x + y, 0)).toBe(1);
    expect((await A.approvals.get(T, a4.approvalId)).status).toBe('EXPIRED');
  });

  test('AR-05 a request that ends unapproved gives its position back', async () => {
    const w = await world();
    const one = await openRequest(w);
    expect(one.seq).toBe(1);
    expect(await A.approvals.hasOpen(T, w.sessionId)).toBe(true);
    expect(await B.approvals.hasOpen(T, w.sessionId)).toBe(true);
    await A.approvals.decide(T, one.approvalId, { decision: 'DENY', reason: 'no' }, { id: 'bob' });
    expect(await B.approvals.hasOpen(T, w.sessionId)).toBe(false);
    expect(await A.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 1, actionsUsed: 0, lastActionHash: null });
    const two = await openRequest(w);                                                                                         // the SAME position, reused (partial unique index)
    expect(two.seq).toBe(1);
    await A.approvals.cancel(T, two.approvalId, { by: 'identity:i1' });
    expect(await A.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 1, actionsUsed: 0 });
    // granted and spent: the artifact owns the place; cancelling does not give it back
    const three = await openRequest(w);
    await A.approvals.decide(T, three.approvalId, { decision: 'APPROVE' }, { id: 'bob' });
    expect((await A.approvals.issue(T, three.approvalId, { agentId: w.agentId, sessionId: w.sessionId, actionHash: three.actionHash }, { requestId: crypto.randomUUID() })).ok).toBe(true);
    await A.approvals.cancel(T, three.approvalId, { by: 'identity:i1' });
    expect(await A.agents.getSession(T, w.sessionId)).toMatchObject({ nextSeq: 2, actionsUsed: 1, lastActionHash: three.actionHash });
    expect(await A.approvals.hasOpen(T, w.sessionId)).toBe(false);
    // the chain moved on after the reservation: the place cannot be given back, it is closed in the ledger
    const w2 = await world();
    const x = await openRequest(w2);
    await A.agents.reserveAction(T, w2.sessionId, { actionClass: 'communication', actionHash: H(), prevActionHash: x.actionHash });
    await A.approvals.decide(T, x.approvalId, { decision: 'DENY', reason: 'no' }, { id: 'bob' });
    expect(await A.executor.getExecution(T, w2.sessionId, 1)).toMatchObject({ status: 'failed' });
  });

  test('AR-06 the arguments are sealed in the row and read back through the store; a row from before encryption still reads', async () => {
    const w = await world();
    const r = await openRequest(w);
    expect(r.args).toEqual({ to: 'x@y.z' });
    const raw = (await admin.query('SELECT args FROM approval_requests WHERE approval_id = $1', [r.approvalId])).rows[0].args;
    expect(Object.keys(raw)).toEqual(['$qfe']); expect(JSON.stringify(raw)).not.toContain('x@y.z');
    // a sealed value copied to another approval's row does not open there (the AAD binds tenant and approval id)
    const w2 = await world(); const r2 = await openRequest(w2);
    await admin.query('UPDATE approval_requests SET args = $1::jsonb WHERE approval_id = $2', [JSON.stringify(raw), r2.approvalId]);
    expect(await A.approvals.get(T, r2.approvalId)).toMatchObject({ args: null, argsUnreadable: 'FIELD_AUTH_FAILED' });                // unreadable, not a thrown error
    await expect(A.approvals.decide(T, r2.approvalId, { decision: 'APPROVE' }, { id: 'bob' })).rejects.toMatchObject({ code: 'APPROVAL_ARGS_UNREADABLE' });   // and never approvable
    // a plaintext row (written before encryption was on) is returned as it is
    await admin.query('UPDATE approval_requests SET args = $1::jsonb WHERE approval_id = $2', [JSON.stringify({ to: 'legacy@y.z' }), r2.approvalId]);
    expect((await A.approvals.get(T, r2.approvalId)).args).toEqual({ to: 'legacy@y.z' });
  });
});
