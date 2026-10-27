'use strict';

/**
 * (owner D7 = B) — boot recovery of a PostgreSQL audit mirror that is BEHIND the authoritative file
 * chain, BEFORE the fail-closed boot consistency check. Real PostgreSQL (a disposable, fully migrated DB), the real
 * audit-log module and file chain, the real mirror INSERT path, and Redis pointed at a dead port.
 *
 * BR-01 boot 1 writes N entries, all mirrored; then K entries reach audit.log but never PG (the mirror write is
 * suppressed — the state a crash after fsync or a PG outage leaves behind)
 * BR-02 boot 2, WITHOUT recovery: the unchanged consistency check refuses (exit(1)) — the pre-fix behaviour
 * BR-03 boot 2, recovery first: exactly K entries replayed, PG == file, evidence records created, the check passes,
 *       with Redis unreachable (the recovery path has no Redis dependency)
 * BR-04 idempotent: a second recovery and a third boot replay nothing; no duplicate row
 * BR-05 not repaired: a PG row that is not in the file chain (PG ahead) → recovery writes nothing and the check
 *       still refuses (fail-closed preserved)
 *
 * DB qodiqa_w10mbr_<pid>_<hex>, recorded in %TEMP%/qodiqa-w3-ledger.jsonl BEFORE creation, dropped in afterAll.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder');
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');
const { chainRows, insertRows } = require('../helpers/auditChainFixtures');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const TAG = `${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const DB = `qodiqa_w10mbr_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const asTest = (db) => ({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database: db, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false, connectionTimeoutMillis: 5000 });
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/mirrorBootRecovery.integration.test.js' }) + '\n');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

jest.setTimeout(300_000);

describeOrSkip('mirror recovery before the boot consistency check (real PostgreSQL)', () => {
  const saved = {}; let created = false; let fx; let mods = null; let logPath;
  const N = 6; const K = 5;
  const fields = () => ({ artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature: 's'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true });
  const pgCount = async () => Number((await fx.query('SELECT count(*) AS n FROM audit_chain')).rows[0].n);
  const pgHashes = async () => (await fx.query('SELECT hash FROM audit_chain ORDER BY seq')).rows.map((r) => r.hash.trim());
  const evCount = async () => Number((await fx.query('SELECT count(*) AS n FROM evidence_chain_records')).rows[0].n);
  const fileHashes = () => fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l).hash);

  async function boot() {          // a process (re)start: fresh modules, fresh pool, the file chain loaded from disk
    if (mods) { await mods.pgPool.shutdown().catch(() => {}); await mods.rolePools.shutdownAll().catch(() => {}); }
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    mods = { pgPool, rolePools: require('../../src/infra/postgres/rolePools'), auditLog: require('../../src/core/audit/audit-log'),
      backend: require('../../src/infra/postgres/pg-audit-backend'), recovery: require('../../src/core/audit/mirrorBootRecovery'),
      check: require('../../src/core/audit/mirrorConsistencyCheck') };
    return mods;
  }
  const runCheck = async () => { const exit = jest.fn(); const ok = await mods.check.verifyMirrorConsistency({ _exit: exit, _emit: () => {} }); return { ok, exited: exit.mock.calls.length > 0 }; };

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_AUDIT_LOG', 'REDIS_URL', 'QODIQA_AUDIT_ORDERING_MODE', 'QODIQA_AUDIT_MIRROR_BOOT_RECOVERY']) saved[k] = process.env[k];
    ledger('planned');
    const m = new Client(asTest('postgres')); await m.connect();
    try { await m.query(`CREATE DATABASE "${DB}"`); } finally { await m.end(); }
    created = true; ledger('created');
    const mp = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }
    logPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w10mbr-')), 'audit.log');
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_AUDIT_LOG: logPath, REDIS_URL: 'redis://127.0.0.1:1' });
    delete process.env.QODIQA_AUDIT_ORDERING_MODE; delete process.env.QODIQA_AUDIT_MIRROR_BOOT_RECOVERY;
    fx = new Client(asTest(DB)); await fx.connect();
  });

  afterAll(async () => {
    if (mods) { await mods.auditLog.drainPendingWrites().catch(() => {}); await mods.pgPool.shutdown().catch(() => {}); await mods.rolePools.shutdownAll().catch(() => {}); }
    if (fx) await fx.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (created) {
      const m = new Client(asTest('postgres')); await m.connect();
      try {
        try { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); }
        ledger((await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0 ? 'dropped' : 'DROP-FAILED');
      } finally { await m.end(); }
    }
  });

  test('BR-01 N mirrored entries, then K entries in audit.log only (crash/outage state)', async () => {
    const { auditLog, backend } = await boot();
    for (let i = 0; i < N; i++) await auditLog.append(fields());
    await auditLog.drainMirrorWriter();
    for (let t = 0; t < 100 && (await evCount()) < N; t++) await sleep(50);
    expect(await pgCount()).toBe(N);
    expect(await evCount()).toBe(N);
    const spy = jest.spyOn(backend, 'persistEntry').mockResolvedValue(undefined);   // the mirror write never happens
    for (let i = 0; i < K; i++) await auditLog.append(fields());
    await auditLog.drainMirrorWriter();
    spy.mockRestore();
    expect(fileHashes()).toHaveLength(N + K);
    expect(await pgCount()).toBe(N);
  });

  test('BR-02 restart WITHOUT recovery: the unchanged consistency check refuses (pre-fix behaviour)', async () => {
    await boot();
    expect(await runCheck()).toEqual({ ok: false, exited: true });
  });

  test('BR-03 restart WITH recovery first: K replayed, PG == file, evidence written, check passes, Redis unreachable', async () => {
    const { recovery } = await boot();
    const out = await recovery.recoverMirrorBeforeBootCheck();
    expect(out).toMatchObject({ outcome: 'recovered', replayed: K, alreadyPresent: 0 });
    expect(await pgHashes()).toEqual(fileHashes());
    for (let t = 0; t < 100 && (await evCount()) < N + K; t++) await sleep(50);
    expect(await evCount()).toBe(N + K);
    expect(await runCheck()).toEqual({ ok: true, exited: false });
  });

  test('BR-04 idempotent: a second recovery and a third boot replay nothing; no duplicate', async () => {
    expect(await mods.recovery.recoverMirrorBeforeBootCheck()).toMatchObject({ outcome: 'in_sync', replayed: 0 });
    const { recovery } = await boot();
    expect(await recovery.recoverMirrorBeforeBootCheck()).toMatchObject({ outcome: 'in_sync', replayed: 0 });
    const h = await pgHashes();
    expect(h).toHaveLength(N + K);
    expect(new Set(h).size).toBe(N + K);
    expect(await runCheck()).toEqual({ ok: true, exited: false });
  });

  test('BR-05 a PG row that is not in the file chain (PG ahead) → not repaired, check still refuses', async () => {
    const tail = fileHashes()[N + K - 1];
    const maxSeq = Number((await fx.query('SELECT max(seq) AS s FROM audit_chain')).rows[0].s);
    const rows = chainRows(1, { tag: `w10mbr-${TAG}`, parent: tail });
    await insertRows(fx, rows, [maxSeq + 1]);
    const before = await pgCount();
    const { recovery } = await boot();
    expect((await recovery.recoverMirrorBeforeBootCheck()).outcome).toBe('not_a_prefix');
    expect(await pgCount()).toBe(before);
    expect(await runCheck()).toEqual({ ok: false, exited: true });
  });
});
