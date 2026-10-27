'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * S4 — audit_chain row-counter reconciliation on REAL PostgreSQL (OD-5: periodic cross-check, CRITICAL alert on
 * drift, NO automatic healing; owner-only rebuild; design). The real reconciler
 * module, the real backend and role pools, bound to this suite's own disposable database.
 *
 *   RC-01 (a) correct counter: reconcile IN_SYNC with stored == exact == count(*) across inserts/duplicates/deletes
 *   RC-02 (b) intentional drift: a deletion with audit_chain's triggers DISABLED (the only way the counter can drift) →
 *             CRITICAL AUDIT_MIRROR_COUNT_DRIFT MISMATCH → a CRITICAL operational alert
 *   RC-03 (c) no auto-repair: repeated runs re-alert with an escalating streak; the counter row is byte-identical
 *             (row_count, updated_at, rebuilt_at); the lag monitor still reads the drifted value
 *   RC-04 (d) owner-only rebuild: qodiqa_system / qodiqa_app are refused EXECUTE; the owner rebuild repairs; the next
 *             run is IN_SYNC and emits DRIFT_CLEARED
 *   RC-05 (e) rollback consistency: rolled-back transactions, savepoints, failed statements → IN_SYNC; a reconcile
 *             concurrent with an OPEN uncommitted insert transaction is IN_SYNC (one snapshot) and stays so after commit
 *   RC-06 (f) restart / boot: drift made while no reconciler is loaded is caught by the next process's BOOT validation
 *             (streak restarts at 1, non-fatal); a backend killed mid-insert (crash) leaves BOOT IN_SYNC
 *   RC-07 (h) missing / unreadable state: counter row deleted → CRITICAL COUNTER_MISSING (lag monitor: UNAVAILABLE);
 *             EXECUTE on the check revoked → WARN RECONCILE_FAILED, never thrown, never CRITICAL; the owner rebuild
 *             recreates the row
 *   RC-08 (i) the 60 s lag path stays O(1): 200 lag reads touch audit_chain 0 times (xact scan + tuple stats, 20k rows)
 *             and issue only the counter statement; the O(n) count is confined to the reconciler's check
 *   RC-09 the reconciler sends no statement other than the read-only check (statement log of the real role pool)
 * (g) legitimate prune incl. crash points: test/integration/auditPrune.integration.test.js PR-03 / PR-04.
 *
 * Disposable DB qodiqa_w11rec_<tag>, ledgered in %TEMP%/qodiqa-w3-ledger.jsonl before creation, dropped and verified
 * gone in afterAll. Only this suite's own fixture rows are written, in its own database.
 */

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
const DB = `qodiqa_w11rec_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');

const conn = (database, user, password) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000,
});
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const asSystem = (db) => conn(db, 'qodiqa_system', process.env.QODIQA_PG_SYSTEM_PASSWORD);
const asApp = (db) => conn(db, process.env.QODIQA_PG_USER, process.env.QODIQA_PG_PASSWORD);
const ledger = (db, event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event, by: 'test/integration/auditChainMirrorReconcile.integration.test.js' }) + '\n');

jest.setTimeout(300_000);

describeOrSkip('S4 — audit_chain counter reconciliation (real PostgreSQL)', () => {
  let fx; let sys;
  const created = [];
  const envSaved = {};
  let seq = 1; let tagN = 0;
  let mods = null;

  const exact = async () => Number((await fx.query('SELECT count(*) AS n FROM audit_chain')).rows[0].n);
  const counterRow = async () => (await fx.query('SELECT row_count, updated_at, rebuilt_at, seeded_at FROM audit_chain_mirror_count')).rows;
  const freshRows = (n) => { tagN++; return chainRows(n, { tag: `rc${tagN}-${TAG}`, parent: crypto.randomBytes(32).toString('hex') }); };
  const insert = async (rows, client = fx) => insertRows(client, rows, rows.map(() => seq++));
  /** The threat S4 exists for: audit_chain changed with its triggers bypassed (table owner). */
  const bypassDelete = async (n) => {
    await fx.query('ALTER TABLE audit_chain DISABLE TRIGGER audit_chain_mirror_count_delete');
    try { await fx.query('DELETE FROM audit_chain WHERE seq IN (SELECT seq FROM audit_chain ORDER BY seq DESC LIMIT $1)', [n]); }
    finally { await fx.query('ALTER TABLE audit_chain ENABLE TRIGGER audit_chain_mirror_count_delete'); }
  };
  const ownerRebuild = async () => { const r = (await fx.query('SELECT previous, rebuilt FROM qodiqa_audit_chain_mirror_count_rebuild()')).rows[0]; return { previous: r.previous === null ? null : Number(r.previous), rebuilt: Number(r.rebuilt) }; };

  /** Fresh module graph bound to this suite's DB — a new process, as far as module state goes. */
  async function load(record = null) {
    if (mods) await unload();
    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_AUDIT_LAG_COUNT', 'QODIQA_AUDIT_MIRROR_RECONCILE']) if (!(k in envSaved)) envSaved[k] = process.env[k];
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_DATABASE = DB;
    delete process.env.QODIQA_AUDIT_LAG_COUNT;
    delete process.env.QODIQA_AUDIT_MIRROR_RECONCILE;
    jest.resetModules();
    jest.dontMock('pg');
    if (record) {
      // statement recorder: every Pool.query() the product's pools (pgPool, role pools) send, with the login role
      jest.doMock('pg', () => {
        const real = jest.requireActual('pg');
        class RecordingPool extends real.Pool {
          query(sql, ...rest) { record.push({ user: this.options.user, sql: String(typeof sql === 'string' ? sql : sql.text).replace(/\s+/g, ' ').trim() }); return super.query(sql, ...rest); }
        }
        const m = Object.create(real); m.Pool = RecordingPool; return m;
      });
    }
    const pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    mods = { pgPool, rolePools: require('../../src/infra/postgres/rolePools'), rec: require('../../src/core/audit/mirrorCountReconciler'),
      lag: require('../../src/core/audit/pgLagMonitor'), detector: require('../../src/alerting/detection/OperationalDetector') };
    return mods;
  }
  async function unload() {
    if (!mods) return;
    mods.rec._resetState();
    await mods.pgPool.shutdown().catch(() => {});
    if (typeof mods.rolePools.shutdownAll === 'function') await mods.rolePools.shutdownAll().catch(() => {});
    mods = null;
  }
  const run = async (trigger = 'SCHEDULED') => {
    const ev = [];
    const fn = trigger === 'BOOT' ? mods.rec.validateAtBoot : mods.rec.reconcileOnce;
    const out = await fn({ trigger, emitFn: (level, type, data) => ev.push({ level, type, data }) });
    return { out, ev };
  };

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error(`unsafe db name ${DB}`);
    if (!process.env.QODIQA_PG_TEST_USER || !process.env.QODIQA_PG_SYSTEM_PASSWORD) throw new Error('QODIQA_PG_TEST_USER and QODIQA_PG_SYSTEM_PASSWORD are required');
    const m = new Client(asTest('postgres')); await m.connect();
    try { ledger(DB, 'planned'); await m.query(`CREATE DATABASE "${DB}"`); created.push(DB); ledger(DB, 'created'); } finally { await m.end(); }
    const p = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    fx = new Client(asTest(DB)); await fx.connect();
    sys = new Client(asSystem(DB)); await sys.connect();
  });

  afterAll(async () => {
    await unload();
    for (const c of [fx, sys]) if (c) await c.end().catch(() => {});
    for (const [k, v] of Object.entries(envSaved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    const m = new Pool(asTest('postgres'));
    try {
      const { dropTestDatabase } = require('../helpers/dropTestDatabase');
      for (const d of created) {
        const r = await dropTestDatabase(m, d);
        const gone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [d])).rowCount === 0;
        ledger(d, gone ? 'dropped' : `DROP-FAILED ${JSON.stringify(r)}`);
      }
    } finally { await m.end(); }
  });

  test('RC-01 (a) correct counter: IN_SYNC with stored == exact == count(*)', async () => {
    await load();
    let r = await run();
    expect(r.out).toMatchObject({ status: 'IN_SYNC', stored: 0, exact: 0 });
    const rows = freshRows(300); await insert(rows);
    expect(await insert(rows.slice(0, 50).map((x) => ({ ...x })))).toBe(0);           // ON CONFLICT duplicates
    await fx.query('DELETE FROM audit_chain WHERE seq IN (SELECT seq FROM audit_chain ORDER BY seq DESC LIMIT 20)');
    r = await run();
    expect(r.out).toMatchObject({ status: 'IN_SYNC', stored: 280, exact: 280 });
    expect(await exact()).toBe(280);
    expect(r.ev.map((e) => `${e.level}:${e.type}`)).toEqual(['INFO:AUDIT_MIRROR_COUNT_RECONCILED']);
  });

  test('RC-02 (b) a trigger-bypassed deletion is detected: CRITICAL drift + CRITICAL alert', async () => {
    await bypassDelete(30);
    expect(await exact()).toBe(250);
    const r = await run();
    expect(r.out).toMatchObject({ status: 'DRIFT', reason: 'MISMATCH', stored: 280, exact: 250, delta: 30, consecutiveDriftRuns: 1 });
    const crit = r.ev.filter((e) => e.level === 'CRITICAL');
    expect(crit).toHaveLength(1);
    expect(crit[0].type).toBe('AUDIT_MIRROR_COUNT_DRIFT');
    const alert = mods.detector.analyze({ eventType: crit[0].type, ...crit[0].data });
    expect(alert).toMatchObject({ triggered: true, alert: { severity: 'CRITICAL', subtype: 'AUDIT_MIRROR_COUNT_DRIFT', evidence: { stored: 280, exact: 250, delta: 30 } } });
  });

  test('RC-03 (c) no auto-repair: repeated runs re-alert and escalate; the counter row is untouched', async () => {
    const before = await counterRow();
    const streak = [];
    for (let i = 0; i < 3; i++) { const r = await run(); streak.push(r.out.consecutiveDriftRuns); expect(r.ev.some((e) => e.level === 'CRITICAL')).toBe(true); }
    expect(streak).toEqual([2, 3, 4]);
    expect(await counterRow()).toEqual(before);                                       // row_count, updated_at, rebuilt_at identical
    expect(Number(before[0].row_count)).toBe(280);
    expect((await mods.lag.pgCountQuery()).rows[0].cnt).toBe(280);                    // the lag monitor still reads the drifted value
    // a fresh boot validation does not repair either
    expect((await run('BOOT')).out).toMatchObject({ status: 'DRIFT', trigger: 'BOOT' });
    expect(await counterRow()).toEqual(before);
  });

  test('RC-04 (d) owner-only rebuild: runtime roles refused; owner rebuild repairs; next run clears', async () => {
    const app = new Client(asApp(DB)); await app.connect();
    try {
      await expect(sys.query('SELECT * FROM qodiqa_audit_chain_mirror_count_rebuild()')).rejects.toThrow(/permission denied/);
      await expect(app.query('SELECT * FROM qodiqa_audit_chain_mirror_count_rebuild()')).rejects.toThrow(/permission denied/);
      await expect(sys.query('UPDATE audit_chain_mirror_count SET row_count = 250')).rejects.toThrow(/permission denied/);
    } finally { await app.end(); }
    expect(Number((await counterRow())[0].row_count)).toBe(280);
    expect(await ownerRebuild()).toEqual({ previous: 280, rebuilt: 250 });
    const r = await run();
    expect(r.out).toMatchObject({ status: 'IN_SYNC', stored: 250, exact: 250 });
    expect(r.ev.map((e) => e.type)).toEqual(['AUDIT_MIRROR_COUNT_DRIFT_CLEARED', 'AUDIT_MIRROR_COUNT_RECONCILED']);
    expect(r.ev[0].data).toMatchObject({ driftRuns: 5 });
  });

  test('RC-05 (e) rollback consistency, and a reconcile concurrent with an open transaction', async () => {
    const n = await exact();
    await fx.query('BEGIN'); await insert(freshRows(40)); await fx.query('ROLLBACK');
    await fx.query('BEGIN'); await insert(freshRows(5)); await fx.query('SAVEPOINT s'); await insert(freshRows(9)); await fx.query('ROLLBACK TO SAVEPOINT s'); await fx.query('COMMIT');
    const bad = [...freshRows(3), { hash: crypto.randomBytes(32).toString('hex'), prevHash: 'not-genesis-and-not-64' }];
    await expect(insert(bad)).rejects.toThrow(/audit_chain_prev_hash_genesis/);
    expect((await run()).out).toMatchObject({ status: 'IN_SYNC', stored: n + 5, exact: n + 5 });
    const w = new Client(asTest(DB)); await w.connect();
    try {
      await w.query('BEGIN'); await insert(freshRows(25), w);                         // uncommitted: holds the counter row lock
      expect((await run()).out).toMatchObject({ status: 'IN_SYNC', stored: n + 5, exact: n + 5 });   // not blocked, one snapshot
      await w.query('COMMIT');
    } finally { await w.end(); }
    expect((await run()).out).toMatchObject({ status: 'IN_SYNC', stored: n + 30, exact: n + 30 });
  });

  test('RC-06 (f) restart / boot: drift made while down is caught at the next BOOT; a crash mid-insert is consistent', async () => {
    await unload();                                                                    // "process stopped"
    await bypassDelete(10);
    const n = await exact();
    await load();                                                                      // "next boot": fresh module state
    let r = await run('BOOT');
    expect(r.out).toMatchObject({ status: 'DRIFT', reason: 'MISMATCH', trigger: 'BOOT', stored: n + 10, exact: n, consecutiveDriftRuns: 1 });
    expect(r.ev.filter((e) => e.level === 'CRITICAL')).toHaveLength(1);
    await ownerRebuild();
    await load();
    r = await run('BOOT');
    expect(r.out).toMatchObject({ status: 'IN_SYNC', trigger: 'BOOT', stored: n, exact: n });
    expect(r.ev.map((e) => e.type)).toEqual(['AUDIT_MIRROR_COUNT_RECONCILED']);         // nothing carried over from the previous process
    // crash: a backend killed mid-transaction rolls back its rows and the counter together
    const victim = new Client(asTest(DB)); await victim.connect(); victim.on('error', () => {});
    const pid = (await victim.query('SELECT pg_backend_pid() AS p')).rows[0].p;
    await victim.query('BEGIN'); await insert(freshRows(30), victim);
    await fx.query('SELECT pg_terminate_backend($1)', [pid]);
    await new Promise((res) => setTimeout(res, 300)); await victim.end().catch(() => {});
    await load();
    expect((await run('BOOT')).out).toMatchObject({ status: 'IN_SYNC', stored: n, exact: n });
  });

  test('RC-07 (h) missing / unreadable state: COUNTER_MISSING is CRITICAL; an unrunnable check is WARN and never thrown', async () => {
    const n = await exact();
    await fx.query('BEGIN');
    await fx.query("SELECT set_config('qodiqa.audit_chain_mirror_count_rebuild', 'on', true)");
    await fx.query('DELETE FROM audit_chain_mirror_count');
    await fx.query('COMMIT');
    let r = await run();
    expect(r.out).toMatchObject({ status: 'DRIFT', reason: 'COUNTER_MISSING', stored: null, exact: n });
    expect(r.ev.find((e) => e.level === 'CRITICAL').data.reason).toBe('COUNTER_MISSING');
    await expect(mods.lag.pgCountQuery()).rejects.toThrow('AUDIT_MIRROR_COUNT_UNAVAILABLE');   // S2 behaviour, unchanged
    expect(await counterRow()).toEqual([]);                                             // not recreated by anyone but the owner
    expect(await ownerRebuild()).toEqual({ previous: null, rebuilt: n });
    expect((await run()).out).toMatchObject({ status: 'IN_SYNC', stored: n, exact: n });
    // the check cannot run (privilege removed) → FAILED, WARN only, no throw, boot not affected
    await fx.query('REVOKE EXECUTE ON FUNCTION qodiqa_audit_chain_mirror_count_check() FROM qodiqa_system');
    try {
      r = await run();
      expect(r.out).toMatchObject({ status: 'FAILED' });
      expect(r.out.error).toMatch(/permission denied/);
      expect(r.ev.map((e) => `${e.level}:${e.type}`)).toEqual(['WARN:AUDIT_MIRROR_COUNT_RECONCILE_FAILED']);
      await expect(run('BOOT')).resolves.toMatchObject({ out: { status: 'FAILED', trigger: 'BOOT' } });
    } finally { await fx.query('GRANT EXECUTE ON FUNCTION qodiqa_audit_chain_mirror_count_check() TO qodiqa_system'); }
    expect((await run()).out).toMatchObject({ status: 'IN_SYNC' });
  });

  test('RC-08 (i) the 60 s lag path stays O(1): 200 lag reads never touch audit_chain; only the check does', async () => {
    await insert(freshRows(20_000));
    const n = await exact();
    expect(n).toBeGreaterThan(20_000);
    const stats = async (c) => (await c.query(`SELECT pg_stat_get_xact_numscans('audit_chain'::regclass)::int scans,
        pg_stat_get_xact_tuples_returned('audit_chain'::regclass)::int returned, pg_stat_get_xact_tuples_fetched('audit_chain'::regclass)::int fetched`)).rows[0];
    // a FRESH system session: pg_stat_get_xact_* also report this backend's not-yet-flushed stats of earlier statements
    // (PG >= 15), so it must not share a backend with anything that read audit_chain before
    const lagc = new Client(asSystem(DB)); await lagc.connect();
    await lagc.query('BEGIN');
    // (hosted-CI rehearsal, PG 17): a parallel scan's worker-side counters are not reported in THIS backend's
    // pg_stat_get_xact_* values, so the O(n) check could read as 0 scans. Measure it non-parallel (the plan's work is
    // identical; only its attribution to this session changes).
    await lagc.query('SET LOCAL max_parallel_workers_per_gather = 0');
    // once autovacuum has set the visibility map on the freshly inserted rows, count(*) may run
    // as an INDEX-ONLY scan, whose work is attributed to the index, not to audit_chain's table counters, so the O(n)
    // check could again read as 0 scans (reproduced on the disposable PG 17 at HEAD's own code). Pin the plan to the
    // table, exactly like the parallel-worker setting above; what is measured is unchanged.
    await lagc.query('SET LOCAL enable_indexonlyscan = off');
    await lagc.query('SET LOCAL enable_indexscan = off');
    await lagc.query('SET LOCAL enable_bitmapscan = off');
    try {
      expect(await stats(lagc)).toEqual({ scans: 0, returned: 0, fetched: 0 });          // clean baseline
      for (let i = 0; i < 200; i++) expect(Number((await lagc.query('SELECT qodiqa_audit_chain_mirror_count() AS n')).rows[0].n)).toBe(n);
      expect(await stats(lagc)).toEqual({ scans: 0, returned: 0, fetched: 0 });          // the lag statement: zero audit_chain access
      await lagc.query('SELECT * FROM qodiqa_audit_chain_mirror_count_check()');
      const after = await stats(lagc);
      expect(after.scans).toBeGreaterThanOrEqual(1);                                    // the reconciler's check is the O(n) one
      expect(after.returned + after.fetched).toBeGreaterThanOrEqual(n);
    } finally { await lagc.query('ROLLBACK'); await lagc.end(); }
    // the real lag query function issues only the counter statement (statements recorded at the pg driver)
    const sent = [];
    await load(sent);
    for (let i = 0; i < 20; i++) expect((await mods.lag.pgCountQuery()).rows[0].cnt).toBe(n);
    expect(sent).toEqual(Array(20).fill({ user: 'qodiqa_system', sql: 'SELECT qodiqa_audit_chain_mirror_count() AS n' }));
    // EXPLAIN of the counter body: one index lookup on the singleton, never audit_chain
    const plan = (await fx.query('EXPLAIN (FORMAT JSON) SELECT row_count FROM audit_chain_mirror_count WHERE id')).rows[0]['QUERY PLAN'];
    expect(JSON.stringify(plan)).not.toMatch(/"Relation Name":"audit_chain"/);
  });

  test('RC-09 the reconciler sends exactly one statement per run: the read-only check', async () => {
    const sent = [];
    await load(sent);
    for (const t of ['BOOT', 'SCHEDULED', 'SCHEDULED']) await run(t);
    expect(sent).toEqual(Array(3).fill({ user: 'qodiqa_system', sql: 'SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()' }));
  });
});
