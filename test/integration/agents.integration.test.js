'use strict';

/**
 * agent_identities / agent_sessions (migration 100) on real PostgreSQL, through the real store.
 *
 *   AP-01  ownership, forced RLS, uniqueness, check constraints
 *   AP-02  privileges: qodiqa_app writes only the columns it is meant to; qodiqa_read only reads
 *   AP-03  tenant isolation by row-level security: no tenant context = no rows; another tenant's rows are invisible and cannot be written
 *   AP-04  the store: create, limits = min(requested, agent), revoke ends sessions, budget under CONCURRENCY never exceeds the cap, chain check, kill
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(120_000);

const DB = `qodiqa_f6b_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PW = 'QODIQA_PG_' + 'PASSWORD';
const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });
const T = 'tenant-a'; const U = 'tenant-b';

let maint; let admin; let pgPool; let store; let A1; let B1;
const saved = {};

describeOrSkip('agents and sessions (real PostgreSQL)', () => {
  beforeAll(async () => {
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW]) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    store = require('../../src/core/agents/agentStore');
    admin = new Pool({ ...baseCfg(), ...maintCreds(), database: DB });
  });
  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (admin) await admin.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try {
        await maint.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [DB]);
        await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      } catch (err) { console.warn(`[f6b] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('AP-01 ownership, forced RLS, uniqueness and constraints', async () => {
    const t = (await admin.query("SELECT c.relname, c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname IN ('agent_identities','agent_sessions') ORDER BY 1")).rows;
    expect(t.map((x) => [x.relname, x.rls, x.forced])).toEqual([['agent_identities', true, true], ['agent_sessions', true, true]]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) for (const x of t) expect(x.owner).toBe('qodiqa_owner');
    const a1 = await store.createAgent(T, { displayName: 'A', allowedActionClasses: ['read'] }, 'op');
    A1 = a1.agentId;
    await expect(store.createAgent(T, { agentId: A1, displayName: 'A again' }, 'op')).rejects.toMatchObject({ code: 'AGENT_ID_IS_ISSUED' });
    await expect(admin.query("INSERT INTO agent_identities (tenant_id, agent_id, display_name, created_by, status) VALUES ('x','bad id!','n','t','active')")).rejects.toThrow(/agent_identities_id_shape|value too long/);
    await expect(admin.query("INSERT INTO agent_identities (tenant_id, agent_id, display_name, created_by, status) VALUES ('x','11111111-1111-4111-8111-111111111111','n','t','revoked')")).rejects.toThrow(/revoked_consistent/);
    await expect(admin.query("INSERT INTO agent_sessions (tenant_id, session_id, agent_id, expires_at, max_actions, created_by) VALUES ('x', gen_random_uuid(), '22222222-2222-4222-8222-222222222222', now(), 1, 't')")).rejects.toThrow(/agent_sessions_agent_fk|foreign key/i);
  });

  test('AP-02 qodiqa_app writes only the allowed columns; qodiqa_read only reads', async () => {
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query("SET LOCAL ROLE qodiqa_app"); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      await expect(c.query("UPDATE agent_identities SET agent_id = '33333333-3333-4333-8333-333333333333'")).rejects.toThrow(/permission denied/i);
      await c.query('ROLLBACK');
      await c.query('BEGIN'); await c.query("SET LOCAL ROLE qodiqa_app"); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      await expect(c.query("UPDATE agent_identities SET tenant_id = 'other'")).rejects.toThrow(/permission denied/i);
      await c.query('ROLLBACK');
      await c.query('BEGIN'); await c.query("SET LOCAL ROLE qodiqa_app"); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      await expect(c.query("DELETE FROM agent_identities")).rejects.toThrow(/permission denied/i);
      await c.query('ROLLBACK');
      await c.query('BEGIN'); await c.query("SET LOCAL ROLE qodiqa_read"); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      expect((await c.query('SELECT count(*)::int AS n FROM agent_identities')).rows[0].n).toBe(1);
      await expect(c.query("UPDATE agent_identities SET status = 'revoked'")).rejects.toThrow(/permission denied/i);
      await c.query('ROLLBACK');
    } finally { c.release(); }
  });

  test('AP-03 row-level security isolates tenants', async () => {
    B1 = (await store.createAgent(U, { displayName: 'B', allowedActionClasses: ['read'] }, 'op')).agentId;
    const sB = await store.startSession(U, B1, {}, 'op');
    const c = await admin.connect();
    try {
      const asApp = async (tenant, sql, params = []) => {
        await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app');
        if (tenant) await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [tenant]);
        try { return (await c.query(sql, params)).rows; } finally { await c.query('ROLLBACK'); }
      };
      expect(await asApp(null, 'SELECT * FROM agent_identities')).toEqual([]);                                  // no tenant context = no rows
      expect((await asApp(T, 'SELECT agent_id FROM agent_identities')).map((r) => r.agent_id)).toEqual([A1]);
      expect((await asApp(U, 'SELECT agent_id FROM agent_identities')).map((r) => r.agent_id)).toEqual([B1]);
      expect(await asApp(T, 'SELECT * FROM agent_sessions WHERE session_id = $1', [sB.sessionId])).toEqual([]);
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app'); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      await expect(c.query("INSERT INTO agent_identities (tenant_id, agent_id, display_name, created_by) VALUES ('tenant-b','44444444-4444-4444-8444-444444444444','n','t')")).rejects.toThrow(/row-level security/i);
      await c.query('ROLLBACK');
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app'); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      const upd = await c.query("UPDATE agent_identities SET status = 'revoked', revoked_at = now() WHERE tenant_id = 'tenant-b'");
      expect(upd.rowCount).toBe(0);                                                                                // cannot even see the row to update it
      await c.query('ROLLBACK');
    } finally { c.release(); }
    expect(await store.getAgent(T, B1)).toBeNull();
    expect(await store.getSession(T, sB.sessionId)).toBeNull();
    expect((await store.getSession(U, sB.sessionId)).status).toBe('active');
  });

  test('AP-04 the store on PostgreSQL: limits, revoke, concurrent budget, chain, kill', async () => {
    const worker = (await store.createAgent(T, { displayName: 'W', allowedActionClasses: ['read', 'external_api'], maxActionsPerSession: 5, maxSessionSeconds: 90, costBudgetMicros: 1000 }, 'op')).agentId;
    const s = await store.startSession(T, worker, { ttlSeconds: 9999, maxActions: 999, costBudgetMicros: 99999 }, 'op');
    expect(s).toMatchObject({ maxActions: 5, costBudgetMicros: 1000, status: 'active', nextSeq: 1 });
    expect(Date.parse(s.expiresAt) - Date.parse(s.startedAt)).toBe(90_000);
    const got = await Promise.all(Array.from({ length: 12 }, () => store.reserveAction(T, s.sessionId, { actionClass: 'read', costMicros: 10 })));
    expect(got.filter((x) => x.ok)).toHaveLength(5);
    expect(new Set(got.filter((x) => x.ok).map((x) => x.seq))).toEqual(new Set([1, 2, 3, 4, 5]));
    expect(got.filter((x) => !x.ok).every((x) => x.reason === 'ACTION_BUDGET_EXHAUSTED')).toBe(true);
    expect((await store.getSession(T, s.sessionId)).actionsUsed).toBe(5);
    // chain
    const s2 = await store.startSession(T, worker, {}, 'op');
    expect(await store.reserveAction(T, s2.sessionId, { actionClass: 'read', actionHash: 'a'.repeat(64), prevActionHash: null })).toMatchObject({ ok: true, seq: 1 });
    expect(await store.reserveAction(T, s2.sessionId, { actionClass: 'read', prevActionHash: null })).toEqual({ ok: false, reason: 'ACTION_CHAIN_MISMATCH' });
    expect(await store.reserveAction(T, s2.sessionId, { actionClass: 'read', actionHash: 'b'.repeat(64), prevActionHash: 'a'.repeat(64) })).toMatchObject({ ok: true, seq: 2 });
    expect(await store.reserveAction(T, s2.sessionId, { actionClass: 'financial' })).toEqual({ ok: false, reason: 'ACTION_CLASS_NOT_ALLOWED' });
    // kill, then revoke ends the rest
    const k = await store.killSession(T, s2.sessionId, 'loop', 'op');
    expect(k.status).toBe('killed');
    expect(await store.reserveAction(T, s2.sessionId, { actionClass: 'read' })).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });
    const s3 = await store.startSession(T, worker, {}, 'op');
    await store.updateAgent(T, worker, { status: 'revoked' }, 'op');
    expect((await store.getSession(T, s3.sessionId)).status).toBe('killed');
    expect(await store.checkSession(T, worker, s3.sessionId)).toEqual({ ok: false, reason: 'AGENT_SESSION_ENDED' });
    // TTL expiry is applied on read
    const shortlived = (await store.createAgent(T, { displayName: 'S', allowedActionClasses: ['read'] }, 'op')).agentId;
    const e = await store.startSession(T, shortlived, { ttlSeconds: 1 }, 'op');
    await new Promise((r) => setTimeout(r, 1300));
    expect((await store.getSession(T, e.sessionId)).status).toBe('expired');
    expect(await store.reserveAction(T, e.sessionId, { actionClass: 'read' })).toEqual({ ok: false, reason: 'AGENT_SESSION_EXPIRED' });
  });
});
