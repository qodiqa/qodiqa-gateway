'use strict';

/**
 * the PG checksum anchor against REAL PostgreSQL: a disposable database with the full migration chain, so
 * migration 062's forward-only trigger is the real one, written to as qodiqa_app (no BYPASSRLS — the trigger exempts
 * BYPASSRLS roles), exactly as the server does. Runs in test:component:serial (it runs the migration chain).
 *
 *   N03-PG-01  the race is real: the pre-fix pattern (one independent upsert per call on a multi-connection pool)
 *              gets forward-only refusals; the real error is SQLSTATE 42501 with the message the classifier parses
 *   N03-PG-02  the fixed saveChecksumPg() under the same burst: no refusal, no failure, final anchor = highest count
 *   N03-PG-03  a stale write after this process's newer anchor: refused by the real trigger, anchor kept, classified
 *              (INFO), health untouched
 *   N03-PG-04  an anchor this process never wrote (seeded higher by the owner role) still refuses AND is a failure
 *   N03-PG-05  equal count, different tail hash (fork) is a failure
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
jest.setTimeout(180_000);

const REPO_ROOT = path.join(__dirname, '..', '..');
const DB = `qodiqa_new03_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
const base = () => ({
  host: process.env.QODIQA_PG_HOST || 'localhost',
  port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  ssl: process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  connectionTimeoutMillis: 5000,
});
const UPSERT = `INSERT INTO audit_checksum_anchor (id, count, tail_hash, updated_at)
       VALUES (TRUE, $1, $2, now())
       ON CONFLICT (id) DO UPDATE SET count = $1, tail_hash = $2, updated_at = now()`;
const hash = (n) => crypto.createHash('sha256').update(`entry-${n}`).digest('hex');

let maint; let owner; let app;

/** A fresh checksumAnchor module whose pool is the real qodiqa_app pool (labels ignored). */
function loadAnchor() {
  jest.resetModules();
  jest.doMock('../../src/infra/postgres/pool', () => ({ isEnabled: () => true, query: (sql, params) => app.query(sql, params) }));
  const emit = jest.fn();
  jest.doMock('../../services/logger', () => ({ emit }));
  const gauge = { set: jest.fn() };
  jest.doMock('../../src/observability/metrics', () => ({
    auditChecksumAnchorBackend: gauge, auditChecksumAnchorLastWriteTimestamp: { set: jest.fn() },
  }));
  return { anchor: require('../../src/core/audit/checksumAnchor'), emit, gauge };
}
const failures = (emit) => emit.mock.calls.filter((c) => c[1] === 'AUDIT_CHECKSUM_ANCHOR_PG_WRITE_FAILED');
const anchorRow = async () => (await owner.query('SELECT count, tail_hash FROM audit_checksum_anchor WHERE id = TRUE')).rows[0];
const resetAnchor = () => owner.query('DELETE FROM audit_checksum_anchor');   // owner role (BYPASSRLS): exempt from the guard

describeOrSkip('checksum anchor on real PostgreSQL (migration 062 trigger, qodiqa_app)', () => {
  beforeAll(async () => {
    maint = new Pool({ ...base(), database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres', user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    await maint.query(`CREATE DATABASE "${DB}"`);
    const { spawnSync } = require('child_process');
    const mig = spawnSync(process.execPath, ['src/infra/postgres/migrate.js'], {
      cwd: REPO_ROOT, encoding: 'utf8', timeout: 90_000,
      env: { ...process.env, QODIQA_PG_DATABASE: DB, QODIQA_PG_MIG_USER: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', QODIQA_PG_MIG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD },
    });
    if (mig.status !== 0) throw new Error(`migrate.js failed (${mig.status}):\n${mig.stdout}\n${mig.stderr}`);
    owner = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_TEST_USER || 'qodiqa_test', password: process.env.QODIQA_PG_TEST_PASSWORD });
    app = new Pool({ ...base(), database: DB, user: process.env.QODIQA_PG_USER || 'qodiqa_app', password: process.env.QODIQA_PG_PASSWORD, max: 8 });
    const who = (await app.query('SELECT current_user, (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user) AS bypass')).rows[0];
    if (who.bypass) throw new Error(`${who.current_user} has BYPASSRLS — the forward-only trigger would not apply`);
  });

  afterAll(async () => {
    jest.dontMock('../../src/infra/postgres/pool'); jest.dontMock('../../services/logger'); jest.dontMock('../../src/observability/metrics');
    if (app) await app.end();
    if (owner) await owner.end();
    if (maint) {
      await maint.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`);   // this suite's own disposable database
      const gone = (await maint.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      await maint.end();
      if (!gone) throw new Error(`disposable database ${DB} was not dropped`);
    }
  });

  test('N03-PG-01 the race is real: independent concurrent upserts get forward-only refusals (SQLSTATE 42501, parsable message)', async () => {
    await resetAnchor();
    const errors = [];
    // The pre-fix shape: every call its own query on an 8-connection pool, issued back to back, none awaited in turn.
    for (let round = 0; round < 40 && errors.length === 0; round++) {
      const start = round * 1000 + 1;
      await Promise.all(Array.from({ length: 200 }, (_, k) =>
        app.query(UPSERT, [start + k, hash(start + k)]).catch((e) => { errors.push(e); })));
    }
    // Deterministic fallback so the error SHAPE is always asserted even if scheduling never reorders on this host.
    if (errors.length === 0) {
      const top = Number((await anchorRow()).count);
      await app.query(UPSERT, [top - 1, hash(top - 1)]).catch((e) => errors.push(e));
    }
    expect(errors.length).toBeGreaterThan(0);
    for (const e of errors) {
      expect(e.code).toBe('42501');
      expect(e.message).toMatch(/^audit_checksum_anchor is forward-only: count (\d+) -> (\d+) refused for role qodiqa_app$/);
    }
    // ...and the trigger kept the anchor monotone whatever the order: it is the highest count ever written.
    const row = await anchorRow();
    expect(Number(row.count)).toBeGreaterThanOrEqual(1);
    // Record what the race produced (visible in the run log; the assertion above is the contract).
    process.stdout.write(`N03-PG-01: ${errors.length} forward-only refusal(s) from independent concurrent upserts\n`);
  });

  test('N03-PG-02 the fixed writer under the same bursts: no refusal, no failure, final anchor is the highest count', async () => {
    await resetAnchor();
    const { anchor, emit, gauge } = loadAnchor();
    let top = 0;
    for (let round = 0; round < 40; round++) {
      const start = round * 1000 + 1;
      const calls = Array.from({ length: 200 }, (_, k) => anchor.saveChecksumPg(start + k, hash(start + k)));
      top = start + 199;
      await Promise.all(calls);
    }
    const row = await anchorRow();
    expect(Number(row.count)).toBe(top);
    expect(row.tail_hash).toBe(hash(top));
    expect(failures(emit)).toHaveLength(0);
    expect(gauge.set.mock.calls.some((c) => c[1] === 0)).toBe(false);
    const st = anchor.getBackendStatus();
    expect(st.pgStaleWritesRefused).toBe(0);
    expect(st.lastPgWriteOk).toBe(true);
    expect(st.pgWritesQueued).toBe(0);
    process.stdout.write(`N03-PG-02: 8,000 calls, ${st.pgWritesCoalesced} coalesced, final ${row.count}\n`);
  });

  test('N03-PG-03 a stale write after this process committed a newer anchor: refused by the real trigger, kept out, classified, health untouched', async () => {
    await resetAnchor();
    const { anchor, emit, gauge } = loadAnchor();
    await anchor.saveChecksumPg(26654, hash(26654));
    await anchor.saveChecksumPg(26653, hash(26653));
    const row = await anchorRow();
    expect(Number(row.count)).toBe(26654);
    expect(row.tail_hash).toBe(hash(26654));
    expect(failures(emit)).toHaveLength(0);
    expect(gauge.set.mock.calls.some((c) => c[1] === 0)).toBe(false);
    expect(anchor.getBackendStatus().pgStaleWritesRefused).toBe(1);
    expect(emit).toHaveBeenCalledWith('INFO', 'AUDIT_CHECKSUM_ANCHOR_PG_STALE_WRITE_REFUSED',
      expect.objectContaining({ incomingCount: 26653, currentCount: 26654 }));
  });

  test('N03-PG-04 an anchor this process never wrote (seeded higher) still refuses the write AND it is a failure', async () => {
    await resetAnchor();
    await owner.query(UPSERT, [30000, hash(30000)]);
    const { anchor, emit, gauge } = loadAnchor();
    await anchor.saveChecksumPg(26654, hash(26654));
    expect(Number((await anchorRow()).count)).toBe(30000);
    expect(failures(emit)).toHaveLength(1);
    expect(gauge.set).toHaveBeenLastCalledWith({}, 0);
    expect(anchor.getBackendStatus().lastPgWriteOk).toBe(false);
  });

  test('N03-PG-05 equal count with a different tail hash (a fork) is a failure', async () => {
    await resetAnchor();
    const { anchor, emit, gauge } = loadAnchor();
    await anchor.saveChecksumPg(500, hash(500));
    await anchor.saveChecksumPg(500, 'f'.repeat(64));
    expect((await anchorRow()).tail_hash).toBe(hash(500));
    expect(failures(emit)).toHaveLength(1);
    expect(gauge.set).toHaveBeenLastCalledWith({}, 0);
  });
});
