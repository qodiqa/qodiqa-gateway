'use strict';

/**
 * tool_registry (migration 101) on real PostgreSQL, through the real registry.
 *
 *   TP-01  ownership, forced RLS, one active version per tool, check constraints
 *   TP-02  privileges: qodiqa_app cannot rewrite schema / class / reversibility of a version, cannot delete; qodiqa_read only reads
 *   TP-03  tenant isolation by row-level security
 *   TP-04  the registry: lifecycle (active / pending / supersede), concurrent registration of the same change creates ONE pending version, resolveForAction
 *   TP-06  action_plans (migration 103): forced RLS, fixed columns, the bounded counter under concurrency, one active plan per session
 *   TP-05  action_executions (migration 102): forced RLS, fixed columns, privileges, exactly-once and in-order consumption under concurrency, closing
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(120_000);

const DB = `qodiqa_f6c_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PW = 'QODIQA_PG_' + 'PASSWORD';
const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });
const T = 'tenant-a'; const U = 'tenant-b';
const spec = (over = {}) => ({ server: 'srv', name: 'files/read', schema: { type: 'object', required: ['path'], properties: { path: { type: 'string' } } }, actionClass: 'read', reversible: true, ...over });

let maint; let admin; let pgPool; let registry; let hashOf; let executor; let plans; let agentStore;
const saved = {};

describeOrSkip('tool registry (real PostgreSQL)', () => {
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
    registry = require('../../src/core/actions/toolRegistry');
    hashOf = require('../../src/core/actions/actionHash').computeSchemaHash;
    executor = require('../../src/core/actions/executor');
    plans = require('../../src/core/actions/planStore');
    agentStore = require('../../src/core/agents/agentStore');
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
      } catch (err) { console.warn(`[f6c] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('TP-01 ownership, forced RLS, one active version, constraints', async () => {
    const t = (await admin.query("SELECT c.relname, c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname = 'tool_registry'")).rows[0];
    expect([t.rls, t.forced]).toEqual([true, true]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) expect(t.owner).toBe('qodiqa_owner');
    const ins = (status, v, over = '') => admin.query(`INSERT INTO tool_registry (tenant_id, server_id, tool_name, version, status, schema, schema_hash, action_class, reversible, created_by) VALUES ('x','s','n',${v},'${status}','{}'::jsonb,'${'a'.repeat(64)}','read',true,'t')${over}`);
    await ins('active', 1);
    await expect(ins('active', 2)).rejects.toThrow(/tool_registry_one_active/);
    await expect(ins('weird', 3)).rejects.toThrow(/check constraint/);
    await expect(admin.query(`INSERT INTO tool_registry (tenant_id, server_id, tool_name, version, status, schema, schema_hash, action_class, reversible, created_by) VALUES ('x','s','m',1,'active','[]'::jsonb,'${'a'.repeat(64)}','read',true,'t')`)).rejects.toThrow(/schema_is_object/);
    await expect(admin.query(`INSERT INTO tool_registry (tenant_id, server_id, tool_name, version, status, schema, schema_hash, action_class, reversible, created_by) VALUES ('x','s','m',1,'active','{}'::jsonb,'XYZ','read',true,'t')`)).rejects.toThrow(/schema_hash/);
  });

  test('TP-02 qodiqa_app cannot rewrite what a version means; qodiqa_read only reads', async () => {
    const c = await admin.connect();
    const asRole = async (role, sql) => {
      await c.query('BEGIN'); await c.query(`SET LOCAL ROLE ${role}`); await c.query("SELECT set_config('qodiqa.tenant_id', 'x', true)");
      try { return await c.query(sql); } finally { await c.query('ROLLBACK'); }
    };
    try {
      for (const col of ["schema = '{}'::jsonb", "schema_hash = '" + 'b'.repeat(64) + "'", "action_class = 'financial'", 'reversible = false', "tool_name = 'other'", "tenant_id = 'y'", 'version = 9'])
        await expect(asRole('qodiqa_app', `UPDATE tool_registry SET ${col}`)).rejects.toThrow(/permission denied/i);
      await expect(asRole('qodiqa_app', 'DELETE FROM tool_registry')).rejects.toThrow(/permission denied/i);
      expect((await asRole('qodiqa_app', "UPDATE tool_registry SET status = 'disabled', updated_at = now()")).rowCount).toBe(1);
      expect((await asRole('qodiqa_read', 'SELECT 1 FROM tool_registry')).rowCount).toBe(1);
      await expect(asRole('qodiqa_read', "UPDATE tool_registry SET status = 'disabled'")).rejects.toThrow(/permission denied/i);
    } finally { c.release(); }
  });

  test('TP-03 row-level security isolates tenants', async () => {
    await registry.register(T, spec(), 'alice');
    await registry.register(U, spec({ name: 'other' }), 'bob');
    expect((await registry.list(T)).map((x) => x.name)).toEqual(['files/read']);
    expect((await registry.list(U)).map((x) => x.name)).toEqual(['other']);
    expect(await registry.get(T, 'srv', 'other')).toBeNull();
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app');
      expect((await c.query('SELECT * FROM tool_registry')).rows).toEqual([]);                                   // no tenant context = no rows
      await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      await expect(c.query(`INSERT INTO tool_registry (tenant_id, server_id, tool_name, version, status, schema, schema_hash, action_class, reversible, created_by) VALUES ('tenant-b','s','n',1,'active','{}'::jsonb,'${'a'.repeat(64)}','read',true,'t')`)).rejects.toThrow(/row-level security/i);
      await c.query('ROLLBACK');
    } finally { c.release(); }
  });

  test('TP-04 lifecycle, concurrent change registration, resolveForAction', async () => {
    const h1 = hashOf(spec().schema);
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h1)).toMatchObject({ ok: true });
    const changed = spec({ schema: { type: 'object', required: ['path'], properties: { path: { type: 'string' }, mode: { type: 'string' } } } });
    const results = await Promise.allSettled(Array.from({ length: 6 }, () => registry.register(T, changed, 'alice')));
    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled).toHaveLength(1);                                                                           // the others are TOOL_UNCHANGED or a version race, never a second pending version
    expect((await registry.get(T, 'srv', 'files/read')).versions.filter((v) => v.status === 'pending_review')).toHaveLength(1);
    expect((await registry.get(T, 'srv', 'files/read')).active.version).toBe(1);
    const h2 = hashOf(changed.schema);
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h2)).toEqual({ ok: false, reason: 'TOOL_SCHEMA_CHANGED' });
    await expect(registry.approve(T, 'srv', 'files/read', 2, 'alice')).rejects.toMatchObject({ code: 'TOOL_SELF_APPROVAL' });
    await registry.approve(T, 'srv', 'files/read', 2, 'bob');
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h2)).toMatchObject({ ok: true, tool: { version: 2 } });
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h1)).toEqual({ ok: false, reason: 'TOOL_SCHEMA_CHANGED' });
    await registry.disable(T, 'srv', 'files/read', 'bob');
    expect(await registry.resolveForAction(T, 'srv', 'files/read', h2)).toEqual({ ok: false, reason: 'TOOL_DISABLED' });
  });

  test('TP-05 action_executions: RLS, privileges, exactly-once and in-order consumption', async () => {
    const t = (await admin.query("SELECT c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname = 'action_executions'")).rows[0];
    expect([t.rls, t.forced]).toEqual([true, true]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) expect(t.owner).toBe('qodiqa_owner');
    const sid = crypto.randomUUID(); const agent = crypto.randomUUID();
    const c1 = (seq, requestId = crypto.randomUUID(), tenantId = T) => ({ tenantId, sessionId: sid, seq, requestId, agentId: agent, actionHash: crypto.randomBytes(32).toString('hex'), server: 'srv', tool: 'files/read', approvalRef: null });
    // seq 2 before seq 1 is an order violation; 1 then 2 pass; a repeated seq and a repeated requestId are replays
    expect(await executor.consume(c1(2))).toEqual({ ok: false, reason: 'ACTION_ORDER_VIOLATION' });
    const one = c1(1); expect(await executor.consume(one)).toEqual({ ok: true });
    expect(await executor.consume(c1(1))).toEqual({ ok: false, reason: 'ACTION_REPLAY' });
    expect(await executor.consume({ ...c1(2), requestId: one.requestId })).toEqual({ ok: false, reason: 'ACTION_REPLAY' });
    expect(await executor.consume(c1(2))).toEqual({ ok: true });
    // concurrency: eight racers for seq 3 - exactly one wins; eight racers with ONE requestId across seqs 4..11 - exactly one wins
    const race = await Promise.all(Array.from({ length: 8 }, () => executor.consume(c1(3))));
    expect(race.filter((r) => r.ok)).toHaveLength(1);
    expect(race.filter((r) => !r.ok).every((r) => r.reason === 'ACTION_REPLAY')).toBe(true);
    const shared = crypto.randomUUID();
    const race2 = await Promise.all(Array.from({ length: 8 }, () => executor.consume(c1(4, shared))));
    expect(race2.filter((r) => r.ok)).toHaveLength(1);
    // another tenant's rows are invisible: the same session id / seq under tenant-b is a different ledger
    expect(await executor.consume(c1(1, crypto.randomUUID(), U))).toEqual({ ok: true });
    expect(await executor.getExecution(T, sid, 1)).toMatchObject({ seq: 1, status: 'intent' });
    expect(await executor.getExecution(U, sid, 2)).toBeNull();
    // closing settles once; stale intents are closed as unknown
    expect((await admin.query(`UPDATE action_executions SET started_at = now() - interval '1 hour' WHERE session_id = $1 AND seq = 2`, [sid])).rowCount).toBe(1);
    expect(await executor.reconcileOpen(T, { olderThanMs: 60_000 })).toBe(1);
    expect(await executor.getExecution(T, sid, 2)).toMatchObject({ status: 'unknown' });
    // privileges: only the outcome columns move, nothing is deleted
    const c = await admin.connect();
    const asApp = async (sql) => { await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app'); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]); try { return await c.query(sql); } finally { await c.query('ROLLBACK'); } };
    try {
      for (const col of ["action_hash = '" + 'b'.repeat(64) + "'", 'seq = 9', "tool_name = 'other'", "request_id = gen_random_uuid()", "tenant_id = 'x'", "agent_id = 'z'"]) await expect(asApp(`UPDATE action_executions SET ${col}`)).rejects.toThrow(/permission denied/i);
      await expect(asApp('DELETE FROM action_executions')).rejects.toThrow(/permission denied/i);
      expect((await asApp("UPDATE action_executions SET status = 'failed', finished_at = now() WHERE status = 'intent'")).rowCount).toBeGreaterThanOrEqual(1);
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app');
      expect((await c.query('SELECT 1 FROM action_executions')).rows).toEqual([]);                                           // no tenant context = no rows
      await c.query('ROLLBACK');
    } finally { c.release(); }
    await expect(admin.query(`INSERT INTO action_executions (tenant_id, session_id, seq, request_id, agent_id, action_hash, server_id, tool_name, status) VALUES ('x', gen_random_uuid(), 1, gen_random_uuid(), 'a', '${'a'.repeat(64)}', 's', 't', 'completed')`)).rejects.toThrow(/finished_consistent/);
  });

  test('TP-06 action_plans: RLS, fixed columns, bounded counter under concurrency, one active plan per session', async () => {
    const t = (await admin.query("SELECT c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname = 'action_plans'")).rows[0];
    expect([t.rls, t.forced]).toEqual([true, true]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) expect(t.owner).toBe('qodiqa_owner');
    const agent = (await agentStore.createAgent(T, { displayName: 'P', allowedActionClasses: ['read'] }, 'op')).agentId;
    const sess = (await agentStore.startSession(T, agent, {}, 'op')).sessionId;
    const p1 = await plans.createPlan(T, { sessionId: sess, agentId: agent, steps: [{ server: 'srv', name: 'files/read', maxCalls: 3 }, { server: 'srv', name: 'other', maxCalls: 1 }] }, 'op');
    expect(await plans.activePlan(T, sess)).toMatchObject({ planId: p1.planId, used: [0, 0] });
    const racers = await Promise.all(Array.from({ length: 10 }, () => plans.consumeStep(T, p1.planId, { sessionId: sess, agentId: agent, server: 'srv', name: 'files/read' })));
    expect(racers.filter((r) => r.ok)).toHaveLength(3);                                                              // never more than maxCalls
    expect(racers.filter((r) => !r.ok).every((r) => r.reason === 'ACTION_PLAN_STEP_EXHAUSTED')).toBe(true);
    expect(new Set(racers.filter((r) => r.ok).map((r) => r.used))).toEqual(new Set([1, 2, 3]));
    expect((await plans.getPlan(T, p1.planId)).used).toEqual([3, 0]);
    expect(await plans.consumeStep(T, p1.planId, { sessionId: sess, agentId: agent, server: 'srv', name: 'nope' })).toEqual({ ok: false, reason: 'ACTION_NOT_IN_PLAN' });
    expect(await plans.consumeStep(U, p1.planId, { sessionId: sess, agentId: agent, server: 'srv', name: 'files/read' })).toEqual({ ok: false, reason: 'ACTION_PLAN_UNKNOWN' });   // another tenant
    // a new plan closes the previous one (one active plan per session)
    const p2 = await plans.createPlan(T, { sessionId: sess, agentId: agent, steps: [{ server: 'srv', name: 'files/read', maxCalls: 1 }] }, 'op');
    expect((await plans.getPlan(T, p1.planId)).status).toBe('closed');
    expect((await plans.activePlan(T, sess)).planId).toBe(p2.planId);
    expect(await plans.consumeStep(T, p1.planId, { sessionId: sess, agentId: agent, server: 'srv', name: 'other' })).toEqual({ ok: false, reason: 'ACTION_PLAN_EXPIRED' });
    // privileges: steps, session and hash are fixed; no delete
    const c = await admin.connect();
    const asApp = async (sql) => { await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app'); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]); try { return await c.query(sql); } finally { await c.query('ROLLBACK'); } };
    try {
      for (const col of ["steps = '[]'::jsonb", "plan_hash = '" + 'b'.repeat(64) + "'", 'session_id = gen_random_uuid()', "agent_id = 'z'", "expires_at = now() + interval '9 days'", "tenant_id = 'x'"]) await expect(asApp(`UPDATE action_plans SET ${col}`)).rejects.toThrow(/permission denied/i);
      await expect(asApp('DELETE FROM action_plans')).rejects.toThrow(/permission denied/i);
      expect((await asApp("UPDATE action_plans SET status = 'closed', closed_at = now() WHERE status = 'active'")).rowCount).toBe(1);
    } finally { c.release(); }
    await expect(admin.query(`UPDATE action_plans SET used = '[1,2,3]'::jsonb WHERE plan_id = '${p2.planId}'`)).rejects.toThrow(/used_shape/);
    await expect(plans.createPlan(T, { sessionId: sess, agentId: agent, steps: [{ server: 'srv', name: 'x', maxCalls: 0 }] }, 'op')).rejects.toMatchObject({ code: 'INVALID_PLAN' });
  });
});
