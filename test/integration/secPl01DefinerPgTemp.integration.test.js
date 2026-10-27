'use strict';

/**
 * SECURITY DEFINER functions resolve pg_temp LAST.
 *
 * Before 078 every definer function pinned `search_path = pg_catalog, public`; PostgreSQL then searches pg_temp FIRST
 * for relations, so a caller with the (default, PUBLIC) TEMP privilege could shadow a real table with a temporary one
 * and the definer function — owner's privileges, RLS-bypassing — would use the temporary table.
 *
 *   PT-01  every SECURITY DEFINER function in public has exactly search_path=pg_catalog, public, pg_temp
 *   PT-02  read path: as qodiqa_app, a temp transparency_log_entries holding a forged row is NOT returned by the
 *          definer read functions (the real, empty table is read)
 *   PT-03  write path: as qodiqa_app, a temp audit_chain_mirror_count does NOT capture the definer insert trigger —
 *          the real counter still equals count(*) of audit_chain
 *
 * PT-02 runs as the application role inside BEGIN … ROLLBACK; PT-03 commits two fixture rows in its own database (only
 * qodiqa_system or the owner can read the counter). Disposable DB qodiqa_secpl01_<tag>, ledgered in
 * %TEMP%/qodiqa-w3-ledger.jsonl before creation, dropped and verified gone in afterAll (this suite's own database only).
 */

// DB-05 (migration 076): this suite inserts audit_chain fixture rows on its own disposable database.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

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
const DB = `qodiqa_secpl01_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const PATH_078 = 'search_path=pg_catalog, public, pg_temp';
const FORGED_HASH = '9'.repeat(64);

const conn = (database, user, password) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000,
});
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const asApp = (db) => conn(db, process.env.QODIQA_PG_USER, process.env.QODIQA_PG_PASSWORD);
const ledger = (db, event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event, by: 'test/integration/secPl01DefinerPgTemp.integration.test.js' }) + '\n');

jest.setTimeout(180_000);

describeOrSkip('SECURITY DEFINER functions resolve pg_temp last (migration 078)', () => {
  let fx; let app;
  let created = false;

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error(`unsafe db name ${DB}`);
    if (!process.env.QODIQA_PG_TEST_USER || !process.env.QODIQA_PG_PASSWORD) throw new Error('QODIQA_PG_TEST_USER and QODIQA_PG_PASSWORD are required');
    const m = new Client(asTest('postgres')); await m.connect();
    try { ledger(DB, 'planned'); await m.query(`CREATE DATABASE "${DB}"`); created = true; ledger(DB, 'created'); } finally { await m.end(); }
    const p = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    fx = new Client(asTest(DB)); await fx.connect();
    app = new Client(asApp(DB)); await app.connect();
  });

  afterAll(async () => {
    for (const c of [app, fx]) if (c) await c.end().catch(() => {});
    if (!created) return;
    const m = new Pool(asTest('postgres'));
    try {
      const { dropTestDatabase } = require('../helpers/dropTestDatabase');
      const r = await dropTestDatabase(m, DB);
      const gone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      ledger(DB, gone ? 'dropped' : `DROP-FAILED ${JSON.stringify(r)}`);
    } finally { await m.end(); }
  });

  test('PT-01 every SECURITY DEFINER function in public pins pg_temp last', async () => {
    const rows = (await fx.query(`SELECT p.oid::regprocedure::text AS fn, p.proconfig FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prosecdef ORDER BY 1`)).rows;
    expect(rows.length).toBeGreaterThan(0);
    const wrong = rows.filter((r) => JSON.stringify(r.proconfig) !== JSON.stringify([PATH_078])).map((r) => `${r.fn} ${JSON.stringify(r.proconfig)}`);
    expect(wrong).toEqual([]);
  });

  test('PT-02 a temp transparency_log_entries cannot feed forged rows to the definer read functions', async () => {
    expect(Number((await fx.query('SELECT count(*) AS n FROM transparency_log_entries')).rows[0].n)).toBe(0);
    await app.query('BEGIN');
    try {
      await app.query('CREATE TEMP TABLE transparency_log_entries (id bigint, entry_hash char(64))');
      await app.query('INSERT INTO pg_temp.transparency_log_entries (id, entry_hash) VALUES (1, $1)', [FORGED_HASH]);
      // the shadow exists and is readable by its creator — the attack's precondition holds
      expect((await app.query('SELECT entry_hash FROM pg_temp.transparency_log_entries')).rows).toEqual([{ entry_hash: FORGED_HASH }]);
      expect((await app.query('SELECT * FROM qodiqa_transparency_log_fetch_hashes_in_range(0, 10)')).rows).toEqual([]);
      expect((await app.query('SELECT * FROM qodiqa_transparency_public_hashes_from_id(0, 10)')).rows).toEqual([]);
    } finally { await app.query('ROLLBACK'); }
  });

  test('PT-03 a temp audit_chain_mirror_count cannot capture the definer insert trigger', async () => {
    const counter = async () => Number((await fx.query('SELECT row_count FROM audit_chain_mirror_count')).rows[0].row_count);
    const exact = async () => Number((await fx.query('SELECT count(*) AS n FROM audit_chain')).rows[0].n);
    const before = await counter();
    expect(before).toBe(await exact());
    await app.query('BEGIN');
    try {
      await app.query('CREATE TEMP TABLE audit_chain_mirror_count (id boolean PRIMARY KEY, row_count bigint, seeded_at timestamptz, updated_at timestamptz) ON COMMIT DROP');
      await app.query('INSERT INTO pg_temp.audit_chain_mirror_count VALUES (TRUE, 0, now(), now())');
      await insertRows(app, chainRows(2, { tag: `secpl01-${TAG}`, parent: crypto.randomBytes(32).toString('hex') }), [1, 2]);
      // the shadow was not touched by the definer trigger
      expect(Number((await app.query('SELECT row_count FROM pg_temp.audit_chain_mirror_count')).rows[0].row_count)).toBe(0);
      await app.query('COMMIT'); // this suite's own fixture rows, in its own database
    } catch (err) { await app.query('ROLLBACK').catch(() => {}); throw err; }
    // the real counter moved with the real table (before 078 it stayed at `before` while count(*) grew)
    expect(await exact()).toBe(before + 2);
    expect(await counter()).toBe(before + 2);
  });
});
