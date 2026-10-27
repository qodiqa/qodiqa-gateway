'use strict';

/**
 * a silently hung PG anchor write, against REAL PostgreSQL: a disposable database with the full migration
 * chain (the real migration-062 forward-only trigger, the real RLS policies), written as qodiqa_app, through an
 * in-process TCP proxy that can STALL the connections that exist at a given moment: bytes in both directions are held
 * (a silent partition — the server never sees the query, the client never sees an answer, the socket stays open) and
 * can later be released (the query then reaches the server LATE). New connections are unaffected.
 *
 * The write deadline is derived from the pool timeouts (checksumAnchor.js): here statement 1,000 + acquire 500 +
 * 2,000 grace = 3,500 ms. Runs in test:component:serial (it runs the migration chain).
 *
 *   N04-PG-01  a normal write through the proxy succeeds
 *   N04-PG-02  an immediate PostgreSQL error (revoked UPDATE grant) fails at once — existing behaviour
 *   N04-PG-03  a stalled write fails AT the deadline: reported, gauge 0, lastPgWriteOk false, caller settled, queue empty
 *   N04-PG-04  the next write after the timeout executes on another connection and restores health
 *   N04-PG-05  the abandoned write's LATE commit does not restore health
 *   N04-PG-06  the abandoned write's LATE arrival after a newer anchor is refused by the guard; nothing disturbed
 *   N04-PG-07  a burst with a stall in the middle stays monotonic and every caller settles
 * N04-PG-08 preserved: same-process stale write is benign
 * N04-PG-09 preserved: same count, different hash is a failure
 * N04-PG-10 preserved: another writer's higher anchor is a failure
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const net = require('net');
const path = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_new04_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const STATEMENT_MS = 1000;
const ACQUIRE_MS = 500;
const DEADLINE_MS = STATEMENT_MS + ACQUIRE_MS + 2000;
const PG_HOST = process.env.QODIQA_PG_HOST || 'localhost';
const PG_PORT = parseInt(process.env.QODIQA_PG_PORT || '5432', 10);
const base = () => ({ host: PG_HOST, port: PG_PORT, ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false, connectionTimeoutMillis: 5000 });
const UPSERT = `INSERT INTO audit_checksum_anchor (id, count, tail_hash, updated_at) VALUES (TRUE, $1, $2, now())
       ON CONFLICT (id) DO UPDATE SET count = $1, tail_hash = $2, updated_at = now()`;
const hash = (n) => crypto.createHash('sha256').update(`entry-${n}`).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const settledWithin = (p, ms) => Promise.race([p.then(() => 'settled'), sleep(ms).then(() => 'pending')]);

// ── stall-capable proxy ──────────────────────────────────────────────────────────────────────────────────────────────
const pipes = new Set();
const proxy = net.createServer((client) => {
  const server = net.connect(PG_PORT, PG_HOST);
  const p = { client, server, stalled: false, held: [] };
  pipes.add(p);
  const relay = (from, to, dir) => from.on('data', (d) => { if (p.stalled) p.held.push([to, d, dir]); else to.write(d); });
  relay(client, server, 'up'); relay(server, client, 'down');
  for (const s of [client, server]) { s.on('error', () => {}); s.on('close', () => { client.destroy(); server.destroy(); pipes.delete(p); }); }
});
const stallExisting = () => { const stalled = [...pipes]; for (const p of stalled) p.stalled = true; return stalled; };
const release = (stalled) => { for (const p of stalled) { p.stalled = false; for (const [to, d] of p.held.splice(0)) to.write(d); } };

let maint; let owner; let proxyPort;
const appPools = [];
function appPool() {
  // configured like src/infra/postgres/pool.js, connected through the proxy
  const p = new Pool({ ...base(), port: proxyPort, host: '127.0.0.1', database: DB, user: process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_PASSWORD, max: 16, connectionTimeoutMillis: ACQUIRE_MS, statement_timeout: STATEMENT_MS });
  p.on('error', () => {});   // as pool.js does
  appPools.push(p);
  return p;
}
function loadAnchor(pool) {
  jest.resetModules();
  jest.doMock('../../src/infra/postgres/pool', () => ({ isEnabled: () => true, query: (sql, params) => pool.query(sql, params) }));
  const emit = jest.fn();
  jest.doMock('../../services/logger', () => ({ emit }));
  const gauge = { set: jest.fn() };
  jest.doMock('../../src/observability/metrics', () => ({ auditChecksumAnchorBackend: gauge, auditChecksumAnchorLastWriteTimestamp: { set: jest.fn() } }));
  return { anchor: require('../../src/core/audit/checksumAnchor'), emit, gauge };
}
const failures = (emit) => emit.mock.calls.filter((c) => c[1] === 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED');
const late = (emit) => emit.mock.calls.filter((c) => c[1] === 'AUDIT_CHECKSUM_ANCHOR_PG_LATE_RESULT');
const gaugeLast = (g) => g.set.mock.calls[g.set.mock.calls.length - 1][1];
const anchorRow = async () => { const r = (await owner.query('SELECT count, tail_hash FROM audit_checksum_anchor WHERE id = TRUE')).rows[0]; return r ? { count: Number(r.count), tailHash: r.tail_hash } : null; };
const resetAnchor = () => owner.query('DELETE FROM audit_checksum_anchor');   // owner (BYPASSRLS): exempt from the guard
/** A fresh module on a fresh pool with exactly ONE warm connection (so a stall hits the next write's connection). */
async function fresh() {
  await resetAnchor();
  const pool = appPool();
  await pool.query('SELECT 1');
  return { pool, ...loadAnchor(pool) };
}

let savedEnv;
describeOrSkip('hung PG anchor write on real PostgreSQL (migration 062 trigger, qodiqa_app, stalling proxy)', () => {
  beforeAll(async () => {
    savedEnv = { s: process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS, a: process.env.QODIQA_PG_ACQUIRE_TIMEOUT_MS };
    process.env.QODIQA_PG_STATEMENT_TIMEOUT_MS = String(STATEMENT_MS);
    process.env.QODIQA_PG_ACQUIRE_TIMEOUT_MS = String(ACQUIRE_MS);
    maint = new Pool({ ...base(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const { spawnSync } = require('child_process');
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
    proxyPort = proxy.address().port;
    const probe = appPool();
    const who = (await probe.query('SELECT current_user, (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user) AS bypass')).rows[0];
    if (who.bypass) throw new Error(`${who.current_user} has BYPASSRLS — the forward-only trigger would not apply`);
  });

  afterAll(async () => {
    for (const p of pipes) { p.client.destroy(); p.server.destroy(); }
    for (const p of appPools) await p.end().catch(() => {});
    await new Promise((r) => proxy.close(() => r()));
    jest.dontMock('../../src/infra/postgres/pool'); jest.dontMock('../../services/logger'); jest.dontMock('../../src/observability/metrics');
    for (const [k, v] of [['QODIQA_PG_STATEMENT_TIMEOUT_MS', savedEnv.s], ['QODIQA_PG_ACQUIRE_TIMEOUT_MS', savedEnv.a]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);   // this suite's own disposable database
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  test('N04-PG-01 a normal write through the proxy succeeds', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(1, hash(1));
    expect(await anchorRow()).toEqual({ count: 1, tailHash: hash(1) });
    expect(gaugeLast(gauge)).toBe(1);
    expect(failures(emit)).toHaveLength(0);
  });

  test('N04-PG-02 an immediate PostgreSQL error (revoked UPDATE grant) fails at once, as before', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(1, hash(1));
    await owner.query('REVOKE UPDATE ON audit_checksum_anchor FROM qodiqa_app');
    try {
      const t0 = Date.now();
      await anchor.saveChecksumPg(2, hash(2));
      expect(Date.now() - t0).toBeLessThan(DEADLINE_MS);
    } finally {
      await owner.query('GRANT UPDATE ON audit_checksum_anchor TO qodiqa_app');
    }
    expect(failures(emit)).toHaveLength(1);
    expect(failures(emit)[0][2].error).toMatch(/permission denied/);
    expect(gaugeLast(gauge)).toBe(0);
    expect(anchor.getBackendStatus().pgWritesTimedOut).toBe(0);
  });

  test('N04-PG-03 a silently stalled write fails AT the deadline: reported, gauge 0, status false, caller settled, queue empty', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(1, hash(1));
    const stalled = stallExisting();
    try {
      const t0 = Date.now();
      const outcome = await settledWithin(anchor.saveChecksumPg(2, hash(2)), DEADLINE_MS + 3000);
      const ms = Date.now() - t0;
      expect(outcome).toBe('settled');
      expect(ms).toBeGreaterThanOrEqual(DEADLINE_MS - 50);
      expect(ms).toBeLessThan(DEADLINE_MS + 1500);
      expect(failures(emit)).toHaveLength(1);
      expect(failures(emit)[0][2].error).toMatch(/did not complete within 3500 ms/);
      expect(gaugeLast(gauge)).toBe(0);
      const st = anchor.getBackendStatus();
      expect(st).toEqual(expect.objectContaining({ lastPgWriteOk: false, pgWritesTimedOut: 1, pgWritesQueued: 0 }));
      process.stdout.write(`N04-PG-03: stalled write reported failed after ${ms} ms (deadline ${DEADLINE_MS} ms)\n`);
    } finally { release(stalled); }
  });

  test('N04-PG-04 after the timeout the next write executes on another connection and restores health', async () => {
    const { anchor, gauge } = await fresh();
    await anchor.saveChecksumPg(1, hash(1));
    const stalled = stallExisting();
    try {
      expect(await settledWithin(anchor.saveChecksumPg(2, hash(2)), DEADLINE_MS + 3000)).toBe('settled');
      expect(gaugeLast(gauge)).toBe(0);
      await anchor.saveChecksumPg(3, hash(3));                 // still stalled: the old connection is busy, a new one is used
      expect(await anchorRow()).toEqual({ count: 3, tailHash: hash(3) });
      expect(gaugeLast(gauge)).toBe(1);
      expect(anchor.getBackendStatus().lastPgWriteOk).toBe(true);
    } finally { release(stalled); }
  });

  test('N04-PG-05 the abandoned write\'s LATE commit does not restore health', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(10, hash(10));
    const stalled = stallExisting();
    expect(await settledWithin(anchor.saveChecksumPg(11, hash(11)), DEADLINE_MS + 3000)).toBe('settled');
    const sets = gauge.set.mock.calls.length;
    release(stalled);                                           // the partitioned query now reaches the server
    for (let i = 0; i < 100 && late(emit).length === 0; i++) await sleep(50);
    expect(await anchorRow()).toEqual({ count: 11, tailHash: hash(11) });   // it really committed (monotonic, allowed)
    expect(late(emit)).toHaveLength(1);
    expect(late(emit)[0][2]).toEqual(expect.objectContaining({ count: 11, outcome: 'committed' }));
    expect(gauge.set.mock.calls.length).toBe(sets);              // health untouched by the late result
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(false);
  });

  test('N04-PG-06 the abandoned write arriving after a newer anchor is refused by the guard; anchor, health, failures untouched', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(20, hash(20));
    const stalled = stallExisting();
    expect(await settledWithin(anchor.saveChecksumPg(21, hash(21)), DEADLINE_MS + 3000)).toBe('settled');
    await anchor.saveChecksumPg(22, hash(22));                  // newer anchor via a new connection
    expect(gaugeLast(gauge)).toBe(1);
    const sets = gauge.set.mock.calls.length; const fails = failures(emit).length;
    release(stalled);                                           // 21 arrives after 22
    for (let i = 0; i < 100 && late(emit).length === 0; i++) await sleep(50);
    expect(await anchorRow()).toEqual({ count: 22, tailHash: hash(22) });
    expect(late(emit)[0][2]).toEqual(expect.objectContaining({ count: 21, outcome: 'failed' }));
    expect(late(emit)[0][2].error).toMatch(/forward-only: count 22 -> 21/);
    expect(gauge.set.mock.calls.length).toBe(sets);
    expect(failures(emit).length).toBe(fails);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(true);
  });

  test('N04-PG-07 a burst with a stall in the middle stays monotonic and every caller settles', async () => {
    const { anchor } = await fresh();
    const seen = []; let stop = false;
    const sampler = (async () => { while (!stop) { const r = await anchorRow(); if (r) seen.push(r.count); await sleep(5); } })();
    const calls = [];
    let stalled = null;
    for (let k = 1; k <= 300; k++) {
      calls.push(anchor.saveChecksumPg(k, hash(k)));
      if (k === 150) { await sleep(10); stalled = stallExisting(); }
    }
    const outcome = await settledWithin(Promise.all(calls), DEADLINE_MS + 5000);
    release(stalled);
    await sleep(500);
    stop = true; await sampler;
    expect(outcome).toBe('settled');
    expect((await anchorRow()).count).toBe(300);
    expect(seen.every((v, i) => i === 0 || v >= seen[i - 1])).toBe(true);
  });

  test('N04-PG-08 preserved: a same-process stale write is benign (INFO, health untouched)', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(26654, hash(26654));
    await anchor.saveChecksumPg(26653, hash(26653));
    expect((await anchorRow()).count).toBe(26654);
    expect(failures(emit)).toHaveLength(0);
    expect(gauge.set.mock.calls.some((c) => c[1] === 0)).toBe(false);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(1);
  });

  test('N04-PG-09 preserved: same count with a different tail hash is a failure', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(500, hash(500));
    await anchor.saveChecksumPg(500, 'f'.repeat(64));
    expect((await anchorRow()).tailHash).toBe(hash(500));
    expect(failures(emit)).toHaveLength(1);
    expect(gaugeLast(gauge)).toBe(0);
  });

  test('N04-PG-10 preserved: another writer\'s higher anchor is a failure, not benign', async () => {
    const { anchor, gauge, emit } = await fresh();
    await anchor.saveChecksumPg(100, hash(100));
    const other = appPool();
    await other.query(UPSERT, [150, hash(150)]);
    await anchor.saveChecksumPg(120, hash(120));
    expect((await anchorRow()).count).toBe(150);
    expect(failures(emit)).toHaveLength(1);
    expect(gaugeLast(gauge)).toBe(0);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(0);
  });
});
