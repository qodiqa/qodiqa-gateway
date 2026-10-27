'use strict';

/**
 * agent_delegations / delegation_uses (migration 104) on real PostgreSQL, through the real store.
 *
 *   DP-01  ownership, forced RLS, constraints (depth, self-delegation, root shape, budget, revoked-consistent)
 *   DP-02  privileges: the token is fixed at insert; only state moves; no delete; delegation_uses is insert-only; qodiqa_read only reads
 *   DP-03  tenant isolation by row-level security
 *   DP-04  chains on PostgreSQL: issue, verifyLive, the shared action limit under concurrency, cascade revocation by recursive statement, agents revoked with their delegations
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const DB = `qodiqa_f6d_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PW = 'QODIQA_PG_' + 'PASSWORD';
const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });
const T = 'default'; const U = 'tenant-b';

let maint; let admin; let pgPool; let agents; let del; let tok;
const saved = {};
const mkAgent = async (tenant, classes = ['read', 'write', 'delegate']) => (await agents.createAgent(tenant, { displayName: 'A', allowedActionClasses: classes }, 'op')).agentId;

describeOrSkip('delegations (real PostgreSQL)', () => {
  beforeAll(async () => {
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_CLIENT_ID']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB; process.env.QODIQA_CLIENT_ID = T;
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    agents = require('../../src/core/agents/agentStore');
    del = require('../../src/core/delegation/delegationStore');
    tok = require('../../src/core/delegation/delegationToken');
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
      } catch (err) { console.warn(`[f6d] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('DP-01 ownership, forced RLS, constraints', async () => {
    const t = (await admin.query("SELECT c.relname, c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname IN ('agent_delegations','delegation_uses') ORDER BY 1")).rows;
    expect(t.map((x) => [x.relname, x.rls, x.forced])).toEqual([['agent_delegations', true, true], ['delegation_uses', true, true]]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) for (const x of t) expect(x.owner).toBe('qodiqa_owner');
    const a = await mkAgent(T); const b = await mkAgent(T);
    const ins = (over = {}) => {
      const v = { delegation_id: crypto.randomUUID(), parent_id: null, root: a, issuer: a, subject: b, depth: 1, max_depth: 3, max_actions: null, used: 0, status: 'active', revoked: false, ...over };
      return admin.query(`INSERT INTO agent_delegations (tenant_id, delegation_id, parent_id, root_agent_id, issuer_agent_id, subject_agent_id, depth, max_depth, classes, max_actions, actions_used, status, token, token_digest, issued_at, expires_at, created_by, revoked_at)
        VALUES ('${T}', $1, $2, $3, $4, $5, $6, $7, ARRAY['read'], $8, $9, '${v.status}', '{}'::jsonb, '${'a'.repeat(64)}', now(), now() + interval '1 hour', 't', ${v.revoked ? 'now()' : 'NULL'})`,
      [v.delegation_id, v.parent_id, v.root, v.issuer, v.subject, v.depth, v.max_depth, v.max_actions, v.used]);
    };
    await expect(ins({ depth: 4, max_depth: 3 })).rejects.toThrow(/depth_bound/);
    await expect(ins({ issuer: a, subject: a })).rejects.toThrow(/not_self/);
    await expect(ins({ depth: 2, parent_id: null })).rejects.toThrow(/root_shape/);
    await expect(ins({ depth: 1, parent_id: crypto.randomUUID() })).rejects.toThrow(/root_shape|parent_fk/);
    await expect(ins({ max_actions: 2, used: 3 })).rejects.toThrow(/budget/);
    await expect(ins({ status: 'revoked', revoked: false })).rejects.toThrow(/revoked_consistent/);
    await expect(ins({ subject: crypto.randomUUID() })).rejects.toThrow(/subject_fk|foreign key/i);
    await ins({});
  });

  test('DP-02 privileges: only state moves', async () => {
    const c = await admin.connect();
    const asRole = async (role, sql, tenant = T) => {
      await c.query('BEGIN'); await c.query(`SET LOCAL ROLE ${role}`); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [tenant]);
      try { return await c.query(sql); } finally { await c.query('ROLLBACK'); }
    };
    try {
      for (const col of ["token = '{}'::jsonb", "token_digest = '" + 'b'.repeat(64) + "'", "classes = ARRAY['financial']", 'max_actions = 99', 'depth = 2', "subject_agent_id = 'z'", "expires_at = now() + interval '9 days'", "tenant_id = 'x'", "tools = '[]'::jsonb"])
        await expect(asRole('qodiqa_app', `UPDATE agent_delegations SET ${col}`)).rejects.toThrow(/permission denied/i);
      await expect(asRole('qodiqa_app', 'DELETE FROM agent_delegations')).rejects.toThrow(/permission denied/i);
      expect((await asRole('qodiqa_app', "UPDATE agent_delegations SET status = 'revoked', revoked_at = now(), revoked_reason = 'x', revoked_by = 'y'")).rowCount).toBe(1);
      expect((await asRole('qodiqa_app', 'UPDATE agent_delegations SET actions_used = 0')).rowCount).toBe(1);
      await expect(asRole('qodiqa_app', 'UPDATE delegation_uses SET depth = 2')).rejects.toThrow(/permission denied/i);
      await expect(asRole('qodiqa_app', 'DELETE FROM delegation_uses')).rejects.toThrow(/permission denied/i);
      expect((await asRole('qodiqa_read', 'SELECT 1 FROM agent_delegations')).rowCount).toBe(1);
      await expect(asRole('qodiqa_read', "UPDATE agent_delegations SET status = 'revoked'")).rejects.toThrow(/permission denied/i);
    } finally { c.release(); }
  });

  test('DP-03 tenant isolation', async () => {
    const a = await mkAgent(U); const b = await mkAgent(U);
    const sess = (await agents.startSession(U, a, {}, 'op')).sessionId;
    // the tenant-b identity's key: its tenant signs its own delegations
    require('../../services/artifact/keyStore').rotateKey(U);                                                           // provisions tenant-b's signing key
    process.env.QODIQA_CLIENT_ID = U;
    const g = await del.issue(U, { issuerAgentId: a, subjectAgentId: b, classes: ['read'] }, 'op');
    expect(await del.get(T, g.delegation.delegationId)).toBeNull();
    expect((await del.list(T)).every((d) => d.tenantId === T)).toBe(true);
    expect(await del.verifyLive(T, g.delegation.delegationId)).toMatchObject({ ok: false, reason: 'DELEGATION_INVALID' });
    expect((await del.verifyLive(U, g.delegation.delegationId, { agentId: b })).ok).toBe(true);
    expect(sess).toBeTruthy();
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app');
      expect((await c.query('SELECT 1 FROM agent_delegations')).rows).toEqual([]);                                     // no tenant context = no rows
      await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      expect((await c.query("UPDATE agent_delegations SET status = 'revoked', revoked_at = now() WHERE tenant_id = 'tenant-b'")).rowCount).toBe(0);
      await c.query('ROLLBACK');
    } finally { c.release(); }
    process.env.QODIQA_CLIENT_ID = T;
  });

  test('DP-04 chains: limits under concurrency, cascade revocation, agents', async () => {
    const A = await mkAgent(T); const B = await mkAgent(T); const C = await mkAgent(T); const D = await mkAgent(T); const E = await mkAgent(T);
    const g1 = await del.issue(T, { issuerAgentId: A, subjectAgentId: B, classes: ['read', 'write', 'delegate'], maxDepth: 4, maxActions: 5 }, 'op');
    const g2 = await del.issue(T, { issuerAgentId: B, subjectAgentId: C, parentId: g1.delegation.delegationId, classes: ['read', 'delegate'], maxActions: 5 }, 'op');
    const g3 = await del.issue(T, { issuerAgentId: C, subjectAgentId: D, parentId: g2.delegation.delegationId, classes: ['read'], maxActions: 3 }, 'op');
    const sess = (await agents.startSession(T, D, {}, 'op')).sessionId;
    const live = await del.verifyLive(T, g3.delegation.delegationId, { agentId: D });
    expect(live).toMatchObject({ ok: true, depth: 3, chainHash: g3.chainHash, rootAgentId: A });
    expect(tok.verifyChain(live.chain, { resolveKey: require('../../src/validation/resolveKey').resolveKey }).chainHash).toBe(g3.chainHash);        // what is stored re-verifies offline
    // 10 concurrent uses of the leaf (limit 3, parents 5): exactly 3 succeed; every limited link is charged exactly 3
    const uses = await Promise.all(Array.from({ length: 10 }, () => del.useDelegation(T, live, { requestId: crypto.randomUUID(), agentId: D, sessionId: sess })));
    expect(uses.filter((u) => u.ok)).toHaveLength(3);
    expect(uses.filter((u) => !u.ok).every((u) => u.reason === 'ACTION_BUDGET_EXHAUSTED')).toBe(true);
    for (const g of [g1, g2, g3]) expect((await del.get(T, g.delegation.delegationId)).actionsUsed).toBe(3);
    expect((await admin.query('SELECT count(*)::int AS n FROM delegation_uses WHERE delegation_id = $1', [g3.delegation.delegationId])).rows[0].n).toBe(3);
    const rid = crypto.randomUUID();
    const g4 = await del.issue(T, { issuerAgentId: C, subjectAgentId: E, parentId: g2.delegation.delegationId, classes: ['read'], maxActions: 2 }, 'op');
    const live4 = await del.verifyLive(T, g4.delegation.delegationId, { agentId: E });
    expect((await del.useDelegation(T, live4, { requestId: rid, agentId: E, sessionId: sess })).ok).toBe(true);
    expect((await del.useDelegation(T, live4, { requestId: crypto.randomUUID(), agentId: E, sessionId: sess })).ok).toBe(true);                    // g1 and g2 now at 5 / 5
    expect(await del.useDelegation(T, live4, { requestId: crypto.randomUUID(), agentId: E, sessionId: sess })).toEqual({ ok: false, reason: 'ACTION_BUDGET_EXHAUSTED' });
    expect(await del.getUse(T, rid)).toMatchObject({ delegationId: g4.delegation.delegationId, chainHash: g4.chainHash, depth: 3, rootAgentId: A });
    // cascade by one recursive statement: revoking g2 revokes g3 and g4, not g1
    const r = await del.revoke(T, g2.delegation.delegationId, { reason: 'compromised', actor: 'op' });
    expect(new Set(r.revoked)).toEqual(new Set([g2.delegation.delegationId, g3.delegation.delegationId, g4.delegation.delegationId]));
    expect((await del.get(T, g1.delegation.delegationId)).status).toBe('active');
    expect((await del.get(T, g3.delegation.delegationId))).toMatchObject({ status: 'revoked', revokedReason: 'compromised', revokedBy: 'op' });
    expect(await del.verifyLive(T, g3.delegation.delegationId)).toMatchObject({ ok: false, reason: 'DELEGATION_REVOKED' });
    // an agent that is revoked takes the delegations it holds
    const g5 = await del.issue(T, { issuerAgentId: A, subjectAgentId: E, classes: ['read'] }, 'op');
    await agents.updateAgent(T, E, { status: 'suspended' }, 'op');
    expect((await del.get(T, g5.delegation.delegationId)).status).toBe('revoked');
    // a concurrent issue under a parent that is being revoked never leaves an active child of a revoked parent
    const g6 = await del.issue(T, { issuerAgentId: A, subjectAgentId: C, classes: ['read', 'delegate'] }, 'op');
    const racers = await Promise.allSettled([
      ...Array.from({ length: 4 }, () => del.issue(T, { issuerAgentId: C, subjectAgentId: D, parentId: g6.delegation.delegationId, classes: ['read'] }, 'op')),
      del.revoke(T, g6.delegation.delegationId, { reason: 'race', actor: 'op' }),
    ]);
    expect(racers.at(-1).status).toBe('fulfilled');
    const kids = (await del.list(T)).filter((d) => d.parentId === g6.delegation.delegationId);
    expect(kids.every((d) => d.status === 'revoked')).toBe(true);
  });
});
