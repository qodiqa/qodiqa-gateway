'use strict';

/**
 * mcp_servers (migration 105) and the gateway on real PostgreSQL, through the real stores.
 *
 *   ME-01  ownership, forced RLS, constraints; privileges (the URL never moves, nothing is deleted, qodiqa_read only reads)
 *   ME-02  tenant isolation
 *   ME-03  the registry: register / resolve / disable / rotate; a row changed outside the registry's own code is refused
 *   ME-04  TWO REPLICAS sharing the database: a tool disabled on replica B aborts the call running on replica A within ~1 s (the plan allows 5 s), and the next call on A is refused
 *   ME-05  the per-tool limit of a session holds under concurrent consumers (advisory lock + count in the consuming transaction)
 *
 * Real PostgreSQL only. Creates and drops its own database.
 */

const crypto = require('crypto');
const { Pool } = require('pg');
const express = require('express');
const request = require('supertest');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const DB = `qodiqa_f6e_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const PW = 'QODIQA_PG_' + 'PASSWORD';
const baseCfg = () => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10), ssl: false });
const maintCreds = () => ({ user: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env[`QODIQA_PG_TEST_${'PASSWORD'}`] || process.env[PW] || undefined });
const T = 'default'; const U = 'tenant-b';
const ECHO = { type: 'object', required: ['text'], properties: { text: { type: 'string' } }, additionalProperties: false };

let maint; let admin; let pgPool; let A; let B; let apiKey; let mcp;
const saved = {};
const load = () => ({
  pool: require('../../src/infra/postgres/pool'), agents: require('../../src/core/agents/agentStore'), registry: require('../../src/core/actions/toolRegistry'), servers: require('../../src/core/mcp/mcpRegistry'),
  executor: require('../../src/core/actions/executor'), actions: require('../../src/api/routes/actions'), tools: require('../../src/api/routes/tools'),
});

describeOrSkip('MCP servers and the gateway (real PostgreSQL)', () => {
  beforeAll(async () => {
    maint = new Pool({ ...baseCfg(), ...maintCreds(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', connectionTimeoutMillis: 5000 });
    await maint.query(`CREATE DATABASE "${DB}"`);
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', PW, 'QODIQA_CLIENT_ID', 'QODIQA_MCP_ALLOW_LOCAL']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB; process.env.QODIQA_CLIENT_ID = T; process.env.QODIQA_MCP_ALLOW_LOCAL = 'true';
    if (process.env.QODIQA_PG_TEST_USER) { process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER; process.env[PW] = process.env[`QODIQA_PG_TEST_${'PASSWORD'}`]; }
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();
    process.env.QODIQA_PG_USER = saved.QODIQA_PG_USER; process.env[PW] = saved[PW];
    ({ apiKey } = require('../helpers/signingIdentity').provisionTestSigningIdentity({ tenantId: T }));
    A = load();                                                    // replica A
    jest.isolateModules(() => { B = load(); B.pool.initialize(); });     // replica B: its own module registry, its own pool, the same database
    admin = new Pool({ ...baseCfg(), ...maintCreds(), database: DB });
  });
  afterAll(async () => {
    if (mcp) await mcp.close().catch(() => {});
    if (B && B.pool) await B.pool.shutdown().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    if (admin) await admin.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (maint) {
      try {
        await maint.query('SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()', [DB]);
        await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);
      } catch (err) { console.warn(`[f6e] failed to drop ${DB}: ${err.message}`); }
      await maint.end().catch(() => {});
    }
  });

  test('ME-01 ownership, forced RLS, constraints, privileges', async () => {
    const t = (await admin.query("SELECT c.relforcerowsecurity AS forced, c.relrowsecurity AS rls, pg_get_userbyid(c.relowner) AS owner FROM pg_class c WHERE c.relname = 'mcp_servers'")).rows[0];
    expect([t.rls, t.forced]).toEqual([true, true]);
    if ((await admin.query("SELECT 1 FROM pg_roles WHERE rolname='qodiqa_owner'")).rows.length) expect(t.owner).toBe('qodiqa_owner');
    const ins = (over = {}) => {
      const v = { id: 'srv-' + crypto.randomBytes(3).toString('hex'), url: 'https://mcp.example.com/mcp', transport: 'streamable-http', identity: '{}', hash: 'a'.repeat(64), status: 'active', disabled: false, ...over };
      return admin.query(`INSERT INTO mcp_servers (tenant_id, server_id, url, transport, identity, config_hash, status, created_by, disabled_at) VALUES ('${T}', $1, $2, $3, $4::jsonb, $5, $6, 't', ${v.disabled ? 'now()' : 'NULL'})`,
        [v.id, v.url, v.transport, v.identity, v.hash, v.status]);
    };
    await expect(ins({ id: 'bad id!' })).rejects.toThrow(/id_shape/);
    await expect(ins({ transport: 'stdio' })).rejects.toThrow(/transport/);
    await expect(ins({ hash: 'zz' })).rejects.toThrow(/config_hash/);
    await expect(ins({ identity: '[]' })).rejects.toThrow(/identity_object/);
    await expect(ins({ status: 'disabled', disabled: false })).rejects.toThrow(/disabled_consistent/);
    await expect(ins({ url: 'x' })).rejects.toThrow(/url/);
    await ins({ id: 'fixture' });
    await expect(ins({ id: 'fixture' })).rejects.toThrow(/mcp_servers_unique/);
    const c = await admin.connect();
    const asRole = async (role, sql) => { await c.query('BEGIN'); await c.query(`SET LOCAL ROLE ${role}`); await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]); try { return await c.query(sql); } finally { await c.query('ROLLBACK'); } };
    try {
      for (const col of ["url = 'https://evil.example/'", "transport = 'x'", "tenant_id = 'x'", "server_id = 'other'", "created_by = 'z'", "local_destination = true"]) await expect(asRole('qodiqa_app', `UPDATE mcp_servers SET ${col}`)).rejects.toThrow(/permission denied/i);
      await expect(asRole('qodiqa_app', 'DELETE FROM mcp_servers')).rejects.toThrow(/permission denied/i);
      expect((await asRole('qodiqa_app', "UPDATE mcp_servers SET status = 'disabled', disabled_at = now(), disabled_reason = 'x', disabled_by = 'y'")).rowCount).toBeGreaterThanOrEqual(1);
      expect((await asRole('qodiqa_read', 'SELECT 1 FROM mcp_servers')).rowCount).toBeGreaterThanOrEqual(1);
      await expect(asRole('qodiqa_read', "UPDATE mcp_servers SET status = 'disabled'")).rejects.toThrow(/permission denied/i);
    } finally { c.release(); }
  });

  test('ME-02 tenant isolation', async () => {
    await A.servers.register(U, { serverId: 'theirs', url: 'http://127.0.0.1:1/mcp' }, 'op');
    expect((await A.servers.list(T)).map((s) => s.serverId)).not.toContain('theirs');
    expect(await A.servers.get(T, 'theirs')).toBeNull();
    expect(await A.servers.resolve(T, 'theirs')).toEqual({ ok: false, reason: 'MCP_SERVER_UNKNOWN' });
    expect((await A.servers.resolve(U, 'theirs')).ok).toBe(true);
    const c = await admin.connect();
    try {
      await c.query('BEGIN'); await c.query('SET LOCAL ROLE qodiqa_app');
      expect((await c.query('SELECT 1 FROM mcp_servers')).rows).toEqual([]);
      await c.query("SELECT set_config('qodiqa.tenant_id', $1, true)", [T]);
      expect((await c.query("UPDATE mcp_servers SET status = 'disabled', disabled_at = now() WHERE tenant_id = 'tenant-b'")).rowCount).toBe(0);
      await c.query('ROLLBACK');
    } finally { c.release(); }
  });

  test('ME-03 the registry on PostgreSQL', async () => {
    mcp = await require('../helpers/mcpTestServer').startMcpTestServer();
    const r = await A.servers.register(T, { serverId: 'live', url: mcp.url }, 'op');
    expect(r).toMatchObject({ status: 'active', identity: { kind: 'none' } });
    await expect(A.servers.register(T, { serverId: 'live', url: mcp.url }, 'op')).rejects.toMatchObject({ code: 'MCP_SERVER_EXISTS' });
    expect(await B.servers.resolve(T, 'live')).toMatchObject({ ok: true, server: { url: mcp.url, configHash: r.configHash } });          // the other replica sees it at once
    await B.servers.disable(T, 'live', { reason: 'compromised', actor: 'op' });
    expect(await A.servers.resolve(T, 'live')).toEqual({ ok: false, reason: 'MCP_SERVER_DISABLED' });
    await A.servers.enable(T, 'live', { actor: 'op' });
    expect((await A.servers.resolve(T, 'live')).ok).toBe(true);
    // the row's URL is changed by someone with direct database rights: the hash no longer matches
    await admin.query("UPDATE mcp_servers SET url = 'http://127.0.0.1:2/other' WHERE tenant_id = $1 AND server_id = 'live'", [T]);
    expect(await A.servers.resolve(T, 'live')).toEqual({ ok: false, reason: 'MCP_SERVER_CONFIG_TAMPERED' });
    await admin.query('UPDATE mcp_servers SET url = $2 WHERE tenant_id = $1 AND server_id = \'live\'', [T, mcp.url]);
    expect((await A.servers.resolve(T, 'live')).ok).toBe(true);
    // rotating the pin of an https server recomputes the hash; the URL stays
    const s = await A.servers.register(T, { serverId: 'secure', url: 'https://mcp.example.com/mcp', identity: { kind: 'tls-spki-pin', sha256: 'ab'.repeat(32) } }, 'op');
    const rot = await A.servers.rotateIdentity(T, 'secure', { kind: 'tls-spki-pin', sha256: 'cd'.repeat(32) }, 'op');
    expect(rot.configHash).not.toBe(s.configHash); expect(rot.url).toBe(s.url);
    expect(await A.servers.resolve(T, 'secure')).toMatchObject({ ok: true, server: { pin: 'cd'.repeat(32), pinOnly: false } });
  });

  test('ME-04 a tool revoked on another replica stops the call running here', async () => {
    const slow = await require('../helpers/mcpTestServer').startMcpTestServer({ handlers: { echo: async () => { await new Promise((r) => setTimeout(r, 4000)); return { content: [{ type: 'text', text: 'late' }] }; } } });
    try {
      await A.servers.register(T, { serverId: 'slow', url: slow.url }, 'op');
      await A.registry.register(T, { server: 'slow', name: 'echo', schema: ECHO, actionClass: 'read', reversible: true }, 'alice');
      const agent = await A.agents.createAgent(T, { displayName: 'Bot', allowedActionClasses: ['read'] }, 'op');
      const who = { agentId: agent.agentId, sessionId: (await A.agents.startSession(T, agent.agentId, {}, 'op')).sessionId };
      const app = express(); app.use(express.json());
      app.use('/v1/actions', A.actions.createActionsRouter());
      app.use('/v1/tools', A.tools.createToolsRouter({ watchIntervalMs: 200, screenDeps: { semantic: async () => ({ blocks: false }), embedding: async () => ({ blocks: false }) } }));
      const auth = { Authorization: `Bearer ${apiKey}` };
      const a = await request(app).post('/v1/actions/authorize').set(auth).send({ ...who, tool: { server: 'slow', name: 'echo' }, args: { text: 'x' } });
      expect(a.status).toBe(200);
      const t0 = Date.now();
      const pending = request(app).post('/v1/tools/call').set(auth).send({ artifact: a.body.artifact, tool: { server: 'slow', name: 'echo' }, args: { text: 'x' } }).then((r) => r);
      await new Promise((r) => setTimeout(r, 500));
      expect(slow.calls).toHaveLength(1);
      await B.registry.disable(T, 'slow', 'echo', 'bob');                                // replica B: A's kill registry is out of its reach
      const res = await pending;
      const ms = Date.now() - t0;
      expect(res.status).toBe(409); expect(res.body.reason).toBe('TOOL_REVOKED');
      expect(ms).toBeLessThan(2500);                                                      // 5 s is the plan's bound; a 200 ms watcher keeps well inside it
      expect(await A.executor.getExecution(T, who.sessionId, 1)).toMatchObject({ status: 'failed' });
      const next = await request(app).post('/v1/actions/authorize').set(auth).send({ ...who, tool: { server: 'slow', name: 'echo' }, args: { text: 'y' } });
      expect(next.body.reason).toBe('TOOL_DISABLED');
    } finally { await slow.close(); }
  });

  test('ME-05 maxCallsPerSession under concurrent consumers', async () => {
    const agent = await A.agents.createAgent(T, { displayName: 'L', allowedActionClasses: ['read'] }, 'op');
    const sid = (await A.agents.startSession(T, agent.agentId, {}, 'op')).sessionId;
    const mk = (seq) => ({ tenantId: T, sessionId: sid, seq, requestId: crypto.randomUUID(), agentId: agent.agentId, actionHash: crypto.randomBytes(32).toString('hex'), server: 'lim', tool: 'echo', approvalRef: null });
    expect(await A.executor.consume(mk(1), { maxCalls: 3 })).toEqual({ ok: true });
    const racers = await Promise.all([2, 3, 4, 5, 6, 7].map((seq) => (seq % 2 ? A.executor : B.executor).consume(mk(seq), { maxCalls: 3 })));
    // seqs 2..7 race: in-order is required, so only some can even enter; whatever enters never exceeds the limit of 3 in total
    const total = (await admin.query("SELECT count(*)::int AS n FROM action_executions WHERE session_id = $1 AND tool_name = 'echo'", [sid])).rows[0].n;
    expect(total).toBeLessThanOrEqual(3);
    expect(racers.filter((r) => r.ok).length).toBeLessThanOrEqual(2);
    expect(racers.filter((r) => !r.ok).every((r) => ['ACTION_TOOL_LIMIT', 'ACTION_ORDER_VIOLATION', 'ACTION_REPLAY'].includes(r.reason))).toBe(true);
  });
});
