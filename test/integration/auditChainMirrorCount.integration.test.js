'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * S2 — audit_chain_mirror_count (migration 073): an O(1) row counter that equals count(*) of audit_chain in
 * every committed state, read by the 60 s PG lag monitor (design decisions
 * 2026-10-01). After every mutation the suite asserts INVARIANT: counter == exact count(*) (and the cross-check agrees).
 *
 *   MC-01 seeded on an empty DB → 0          MC-10 app paths: mirror writer persistEntry + its replay, distributed append,
 *   MC-02 genesis-only → 1                         boot hydration getChainTail (read-only)
 *   MC-03 sequential + multi-row inserts     MC-11 an existing DB is seeded with its exact count by the migration
 *   MC-04 ON CONFLICT DO NOTHING duplicates  MC-12 lag monitor: counter path == previous full count, events identical
 *   MC-05 failed statements / rollback       MC-13 drift is REPORTED by the exact cross-check and never repaired
 *   MC-06 several statements in one tx       MC-14 permissions / guard / SECURITY DEFINER contract
 *   MC-07 prune-shaped DELETE                MC-15 16 concurrent writers (inserts, duplicates, rollbacks)
 *   MC-08 TRUNCATE → 0                       MC-16 audit-mirror-rebuild --apply (UPDATE seq) leaves the count unchanged
 *   MC-09 reconnect + killed mid-transaction MC-17 DR dump → restore: table not dumped; counter rebuilt == count(*)
 *
 * Disposable DBs qodiqa_w11cnt_<tag> (+ _dr), ledgered in %TEMP%/qodiqa-w3-ledger.jsonl before creation, dropped and
 * verified gone in afterAll. Only this suite's own fixture rows are written, in its own databases.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');
const { chainRows, seqPlan, insertRows } = require('../helpers/auditChainFixtures');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const TAG = `${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const DB = `qodiqa_w11cnt_${TAG}`;
const DB_DR = `qodiqa_w11cnt_${TAG}_dr`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const MIGRATION_073 = path.join(__dirname, '..', '..', 'src', 'infra', 'postgres', 'migrations', '073_audit_chain_mirror_count.sql');
const MIGRATION_078 = path.join(__dirname, '..', '..', 'src', 'infra', 'postgres', 'migrations', '078_definer_search_path_pg_temp_last.sql');

const conn = (database, user, password) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000,
});
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const asSystem = (db) => conn(db, 'qodiqa_system', process.env.QODIQA_PG_SYSTEM_PASSWORD);
const asApp = (db) => conn(db, process.env.QODIQA_PG_USER, process.env.QODIQA_PG_PASSWORD);
const ledger = (db, event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event, by: 'test/integration/auditChainMirrorCount.integration.test.js' }) + '\n');
const urlFor = (db) => `postgres://${encodeURIComponent(process.env.QODIQA_PG_TEST_USER)}:${encodeURIComponent(process.env.QODIQA_PG_TEST_PASSWORD)}@${process.env.QODIQA_PG_HOST || 'localhost'}:${process.env.QODIQA_PG_PORT || 5432}/${db}`;

jest.setTimeout(300_000);

describeOrSkip('S2 — audit_chain_mirror_count (migration 073)', () => {
  let fx; let sys;
  const created = [];
  const envSaved = {};
  let seq = 1;     // next explicit seq for fixture rows
  let tagN = 0;    // fixture tag counter (unique hashes)

  const counter = async (c = sys) => {
    const r = (await c.query('SELECT qodiqa_audit_chain_mirror_count() AS n')).rows[0].n;
    return r === null ? null : Number(r);
  };
  const exact = async () => Number((await fx.query('SELECT count(*) AS n FROM audit_chain')).rows[0].n);
  const check = async () => { const r = (await sys.query('SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()')).rows[0]; return { stored: Number(r.stored), exact: Number(r.exact), inSync: r.in_sync }; };
  const expectInvariant = async (expected) => {
    const [c, e, k] = [await counter(), await exact(), await check()];
    expect(c).toBe(e);
    expect(k).toEqual({ stored: e, exact: e, inSync: true });
    if (expected !== undefined) expect(e).toBe(expected);
    return e;
  };
  const freshRows = (n, parent) => { tagN++; return chainRows(n, { tag: `mc${tagN}-${TAG}`, parent: parent || crypto.randomBytes(32).toString('hex') }); };
  const insert = async (rows, client = fx) => { const seqs = rows.map(() => seq++); return insertRows(client, rows, seqs); };
  const reset = async () => { await fx.query('DELETE FROM audit_chain'); };   // this suite's own fixture rows only

  function bindModules(db) {
    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_AUDIT_ORDERING_MODE', 'QODIQA_AUDIT_LAG_COUNT']) if (!(k in envSaved)) envSaved[k] = process.env[k];
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_DATABASE = db;
    delete process.env.QODIQA_AUDIT_ORDERING_MODE;
    delete process.env.QODIQA_AUDIT_LAG_COUNT;
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    return {
      pgPool,
      backend: require('../../src/infra/postgres/pg-audit-backend'),
      entryBuilder: require('../../src/core/audit/entryBuilder'),
      lagMonitor: require('../../src/core/audit/pgLagMonitor'),
      distributed: require('../../src/core/audit/distributedOrdering'),
      rebuild: require('../../scripts/audit-mirror-rebuild'),
    };
  }

  beforeAll(async () => {
    for (const d of [DB, DB_DR]) if (!/^[a-z][a-z0-9_]{0,62}$/.test(d)) throw new Error(`unsafe db name ${d}`);
    if (!process.env.QODIQA_PG_TEST_USER || !process.env.QODIQA_PG_SYSTEM_PASSWORD) throw new Error('QODIQA_PG_TEST_USER and QODIQA_PG_SYSTEM_PASSWORD are required');
    const m = new Client(asTest('postgres')); await m.connect();
    try { for (const d of [DB, DB_DR]) { ledger(d, 'planned'); await m.query(`CREATE DATABASE "${d}"`); created.push(d); ledger(d, 'created'); } } finally { await m.end(); }
    for (const d of [DB, DB_DR]) {
      const p = new Pool(asTest(d));
      try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    }
    fx = new Client(asTest(DB)); await fx.connect();
    sys = new Client(asSystem(DB)); await sys.connect();
  });

  afterAll(async () => {
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

  test('MC-01 migration 073 applied; seeded on an empty DB → 0', async () => {
    expect((await fx.query('SELECT 1 FROM qodiqa_migrations WHERE version = 73')).rowCount).toBe(1);
    const row = (await fx.query('SELECT row_count, seeded_at FROM audit_chain_mirror_count')).rows;
    expect(row).toHaveLength(1);
    expect(row[0].seeded_at).toBeInstanceOf(Date);
    await expectInvariant(0);
  });

  test('MC-02 genesis-only → 1', async () => {
    await insert(chainRows(1, { tag: `mc-gen-${TAG}` }));
    await expectInvariant(1);
  });

  test('MC-03 sequential single-row statements and one multi-row statement', async () => {
    const before = await exact();
    const rows = freshRows(50);
    for (const r of rows) await insert([r]);
    await expectInvariant(before + 50);
    await insert(freshRows(500));
    await expectInvariant(before + 550);
  });

  test('MC-04 duplicate inserts (ON CONFLICT (hash) DO NOTHING) do not count', async () => {
    const rows = freshRows(20);
    await insert(rows);
    const n = await expectInvariant();
    const again = rows.map((r) => ({ ...r }));
    expect(await insertRows(fx, again, again.map(() => seq++))).toBe(0);
    await expectInvariant(n);
    // a statement mixing new and duplicate rows counts only the new ones
    const mixed = [...rows.slice(0, 5), ...freshRows(7)];
    expect(await insertRows(fx, mixed, mixed.map(() => seq++))).toBe(7);
    await expectInvariant(n + 7);
  });

  test('MC-05 failed statements and rolled-back transactions leave the count unchanged', async () => {
    const n = await expectInvariant();
    const r = freshRows(1)[0];
    await insert([r]);
    // PK violation without ON CONFLICT → the statement fails
    await expect(fx.query('INSERT INTO audit_chain (seq, hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time, input_hash, signature, request_hash, policy_hash, verification_result) SELECT seq + 100000, hash, prev_hash, canonical, artifact_id || \'-dup\', decision, recorded_at, high_res_time, input_hash, signature, request_hash, policy_hash, verification_result FROM audit_chain WHERE hash = $1', [r.hash])).rejects.toThrow(/duplicate key/);
    await expectInvariant(n + 1);
    // a multi-row statement with ONE bad row (CHECK violation) fails as a whole
    const bad = [...freshRows(3), { hash: crypto.randomBytes(32).toString('hex'), prevHash: 'not-genesis-and-not-64' }];
    await expect(insertRows(fx, bad, bad.map(() => seq++))).rejects.toThrow(/audit_chain_prev_hash_genesis/);
    await expectInvariant(n + 1);
    // explicit transaction rolled back
    await fx.query('BEGIN');
    await insert(freshRows(10));
    await fx.query('ROLLBACK');
    await expectInvariant(n + 1);
    // savepoint rolled back inside a committed transaction
    await fx.query('BEGIN');
    await insert(freshRows(2));
    await fx.query('SAVEPOINT s');
    await insert(freshRows(5));
    await fx.query('ROLLBACK TO SAVEPOINT s');
    await fx.query('COMMIT');
    await expectInvariant(n + 3);
  });

  test('MC-06 several statements in one transaction: invisible until COMMIT, then exact', async () => {
    const n = await expectInvariant();
    await fx.query('BEGIN');
    await insert(freshRows(1)); await insert(freshRows(10)); await insert(freshRows(100));
    expect(Number((await fx.query('SELECT row_count FROM audit_chain_mirror_count')).rows[0].row_count)).toBe(n + 111); // own tx sees it
    expect(await counter()).toBe(n);                                                                                       // others do not
    await fx.query('COMMIT');
    await expectInvariant(n + 111);
  });

  test('MC-07 prune-shaped DELETE (one statement, seq below a bound) decrements by the rows deleted', async () => {
    const n = await expectInvariant();
    const bound = Number((await fx.query('SELECT percentile_disc(0.4) WITHIN GROUP (ORDER BY seq) AS b FROM audit_chain')).rows[0].b);
    const del = await fx.query('DELETE FROM audit_chain WHERE seq < $1', [bound]);
    expect(del.rowCount).toBeGreaterThan(0);
    await expectInvariant(n - del.rowCount);
    const none = await fx.query('DELETE FROM audit_chain WHERE seq < 0');   // a no-op DELETE changes nothing
    expect(none.rowCount).toBe(0);
    await expectInvariant(n - del.rowCount);
  });

  test('MC-08 TRUNCATE → 0', async () => {
    await insert(freshRows(30));
    await fx.query('TRUNCATE audit_chain');
    await expectInvariant(0);
  });

  test('MC-09 reconnect, and a backend killed mid-transaction (crash) rolls its rows and the counter back together', async () => {
    await insert(freshRows(40));
    const n = await expectInvariant(40);
    await sys.end(); await fx.end();
    fx = new Client(asTest(DB)); await fx.connect();
    sys = new Client(asSystem(DB)); await sys.connect();
    await expectInvariant(n);
    const victim = new Client(asTest(DB)); await victim.connect();
    victim.on('error', () => {});
    const pid = (await victim.query('SELECT pg_backend_pid() AS p')).rows[0].p;
    await victim.query('BEGIN');
    await insertRows(victim, freshRows(25), Array.from({ length: 25 }, () => seq++));
    await fx.query('SELECT pg_terminate_backend($1)', [pid]);
    await new Promise((r) => setTimeout(r, 300));
    await victim.end().catch(() => {});
    await expectInvariant(n);
  });

  test('MC-10 application paths: mirror writer + replay, distributed append, hydration read', async () => {
    await fx.query('TRUNCATE audit_chain');
    await fx.query("UPDATE audit_chain_head SET tail_hash = 'GENESIS', tail_seq = 0");
    const mods = bindModules(DB);
    try {
      // single-node mirror writer (qodiqa_app via pgPool; same guarded INSERT the recovery replay uses — recoveryManager.js)
      let prev = 'GENESIS'; const entries = [];
      for (let i = 0; i < 8; i++) {
        const e = mods.entryBuilder.buildEntry(mods.entryBuilder.normalizeFields({ artifactId: `mc10-${TAG}-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
          signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, ...(i % 2 ? { tenantId: 'w11-mc10-tenant' } : {}) }), prev);
        await mods.backend.persistEntry(e); entries.push(e); prev = e.hash;
      }
      await expectInvariant(8);
      for (const e of entries) await mods.backend.persistEntry(e);   // replay: idempotent, counts nothing
      await expectInvariant(8);
      // boot hydration reads the link tail only
      expect((await mods.backend.getChainTail()).hash).toBe(prev);
      await expectInvariant(8);
      // distributed-mode append (its own INSERT path, head row FOR UPDATE): continues from the head it reads
      await fx.query('UPDATE audit_chain_head SET tail_hash = $1, tail_seq = (SELECT max(seq) FROM audit_chain)', [prev]);
      for (let i = 0; i < 3; i++) {
        await mods.distributed.appendEntry({ artifactId: `mc10d-${TAG}-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
          requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true });
      }
      await expectInvariant(11);
    } finally { await mods.pgPool.shutdown().catch(() => {}); }
  });

  test('MC-11 an EXISTING populated database is seeded with its exact count by the migration', async () => {
    // Re-running 073's SQL is idempotent: it neither re-seeds nor double-counts.
    const n = await exact();
    await fx.query(fs.readFileSync(MIGRATION_073, 'utf8'));
    // 073's CREATE OR REPLACE resets its definer functions' search_path; the chain re-asserts pg_temp-last after it
    await fx.query(fs.readFileSync(MIGRATION_078, 'utf8'));
    await expectInvariant(n);
    // Seeding proper is covered on real data: applies 073 to TEMPLATE copies of the
    // kept 5k/117k/220k/360k databases and asserts counter == count(*) right after migration.
  });

  test('MC-12 lag monitor: the counter path gives the same pgCount and the same events as the previous full count', async () => {
    await reset();
    const mods = bindModules(DB);
    try {
      const rows = freshRows(37); await insert(rows);
      const run = async (fileCount, queryFn) => {
        const ev = []; mods.lagMonitor._resetState();
        await mods.lagMonitor._checkOnce({ getFileCount: () => fileCount, queryFn, emitFn: (l, t, d) => ev.push({ t, d }), lagThreshold: 5 });
        return ev;
      };
      const previous = () => mods.backend.countChainRows().then((n) => ({ rows: [{ cnt: n }] }));   // the pre-S2 query
      for (const fileCount of [37, 40, 60, 100]) {
        expect(await run(fileCount, mods.lagMonitor.pgCountQuery)).toEqual(await run(fileCount, previous));
      }
      const lagged = await run(60, mods.lagMonitor.pgCountQuery);
      expect(lagged).toHaveLength(1);
      expect(lagged[0]).toMatchObject({ t: 'AUDIT_PG_SYNC_LAG', d: { fileCount: 60, pgCount: 37, lag: 23 } });
      // rollback switch: QODIQA_AUDIT_LAG_COUNT=exact restores the full count, same answer
      process.env.QODIQA_AUDIT_LAG_COUNT = 'exact';
      expect((await mods.lagMonitor.pgCountQuery()).rows[0].cnt).toBe(37);
      delete process.env.QODIQA_AUDIT_LAG_COUNT;
      expect((await mods.lagMonitor.pgCountQuery()).rows[0].cnt).toBe(37);
    } finally { await mods.pgPool.shutdown().catch(() => {}); }
  });

  test('MC-13 drift is REPORTED by the exact cross-check and the lag monitor; nothing repairs it silently', async () => {
    await reset(); await insert(freshRows(12));
    await expectInvariant(12);
    // simulate corruption of the derived row (owner, explicitly flagged write — the only way past the guard)
    await fx.query('BEGIN');
    await fx.query("SELECT set_config('qodiqa.audit_chain_mirror_count_rebuild', 'on', true)");
    await fx.query('UPDATE audit_chain_mirror_count SET row_count = row_count + 5');
    await fx.query('COMMIT');
    expect(await check()).toEqual({ stored: 17, exact: 12, inSync: false });
    const mods = bindModules(DB);
    try {
      const ev = []; mods.lagMonitor._resetState();
      await mods.lagMonitor._checkOnce({ getFileCount: () => 12, queryFn: mods.lagMonitor.pgCountQuery, emitFn: (l, t, d) => ev.push({ t, d }), lagThreshold: 0 });
      expect(await counter()).toBe(17);                       // read, not repaired
    } finally { await mods.pgPool.shutdown().catch(() => {}); }
    expect(await check()).toEqual({ stored: 17, exact: 12, inSync: false });   // still drifted: no silent repair anywhere
    // a counter already out of step fails a DELETE that would take it below zero, loudly
    await fx.query('BEGIN');
    await fx.query("SELECT set_config('qodiqa.audit_chain_mirror_count_rebuild', 'on', true)");
    await fx.query('UPDATE audit_chain_mirror_count SET row_count = 1');
    await fx.query('COMMIT');
    await expect(fx.query('DELETE FROM audit_chain')).rejects.toThrow(/audit_chain_mirror_count_row_count_check/);
    expect(await exact()).toBe(12);                           // the failed DELETE removed nothing
    // the only repair is the explicit owner/DR rebuild
    const rb = (await fx.query('SELECT previous, rebuilt FROM qodiqa_audit_chain_mirror_count_rebuild()')).rows[0];
    expect({ previous: Number(rb.previous), rebuilt: Number(rb.rebuilt) }).toEqual({ previous: 1, rebuilt: 12 });
    await expectInvariant(12);
  });

  test('MC-14 permissions, write guard and SECURITY DEFINER contract', async () => {
    const app = new Client(asApp(DB)); await app.connect();
    try {
      await expect(app.query('SELECT row_count FROM audit_chain_mirror_count')).rejects.toThrow(/permission denied/);
      await expect(app.query('SELECT qodiqa_audit_chain_mirror_count()')).rejects.toThrow(/permission denied/);
      await expect(app.query('SELECT * FROM qodiqa_audit_chain_mirror_count_check()')).rejects.toThrow(/permission denied/);
      await expect(app.query('SELECT * FROM qodiqa_audit_chain_mirror_count_rebuild()')).rejects.toThrow(/permission denied/);
    } finally { await app.end(); }
    await expect(sys.query('SELECT row_count FROM audit_chain_mirror_count')).rejects.toThrow(/permission denied/);
    await expect(sys.query('UPDATE audit_chain_mirror_count SET row_count = 0')).rejects.toThrow(/permission denied/);
    await expect(sys.query('SELECT * FROM qodiqa_audit_chain_mirror_count_rebuild()')).rejects.toThrow(/permission denied/);
    // even the owner cannot write it directly (guard), nor delete/truncate it
    await expect(fx.query('UPDATE audit_chain_mirror_count SET row_count = 0')).rejects.toThrow(/derived state: UPDATE refused/);
    await expect(fx.query('DELETE FROM audit_chain_mirror_count')).rejects.toThrow(/derived state: DELETE refused/);
    await expect(fx.query('INSERT INTO audit_chain_mirror_count (id, row_count, seeded_at, updated_at) VALUES (TRUE, 0, now(), now()) ON CONFLICT DO NOTHING')).rejects.toThrow(/derived state: INSERT refused/);
    await expect(fx.query('TRUNCATE audit_chain_mirror_count')).rejects.toThrow(/derived state: TRUNCATE refused/);
    const fns = (await fx.query(`SELECT p.proname, p.prosecdef, p.proconfig, has_function_privilege('public', p.oid, 'EXECUTE') pub,
        has_function_privilege('qodiqa_system', p.oid, 'EXECUTE') sys, has_function_privilege('qodiqa_app', p.oid, 'EXECUTE') app
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname LIKE 'qodiqa_audit_chain_mirror_count%' ORDER BY 1`)).rows;
    expect(fns.map((f) => [f.proname, f.prosecdef, f.pub, f.sys, f.app])).toEqual([
      ['qodiqa_audit_chain_mirror_count', true, false, true, false],
      ['qodiqa_audit_chain_mirror_count_check', true, false, true, false],
      ['qodiqa_audit_chain_mirror_count_guard', false, false, false, false],
      ['qodiqa_audit_chain_mirror_count_on_delete', true, false, false, false],
      ['qodiqa_audit_chain_mirror_count_on_insert', true, false, false, false],
      ['qodiqa_audit_chain_mirror_count_on_truncate', true, false, false, false],
      ['qodiqa_audit_chain_mirror_count_rebuild', true, false, false, false],
    ]);
    // 078: SECURITY DEFINER functions resolve pg_temp last; the invoker guard trigger keeps 073's path
    for (const f of fns) expect(f.proconfig).toEqual([f.prosecdef ? 'search_path=pg_catalog, public, pg_temp' : 'search_path=pg_catalog, public']);
    // 073 changes no RLS flag, policy or grant ON audit_chain itself (those are pinned per table by privilegeRls PM-01)
    const sql = fs.readFileSync(MIGRATION_073, 'utf8').split(/\r?\n/).filter((l) => !l.trim().startsWith('--')).join(' ');
    expect(sql).not.toMatch(/ALTER\s+TABLE\s+audit_chain\b/i);
    expect(sql).not.toMatch(/POLICY[^;]*\bON\s+audit_chain\b(?!_)/i);
    expect(sql).not.toMatch(/(GRANT|REVOKE)[^;]*\bON\s+(TABLE\s+)?audit_chain\b(?!_)/i);
    const trg = (await fx.query(`SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_chain'::regclass AND NOT tgisinternal ORDER BY 1`)).rows.map((r) => r.tgname);
    // DB-05 (migration 076) adds its append-only guard, TRUNCATE guard and maintenance log to audit_chain; 073's three
    // counter triggers are unchanged.
    expect(trg).toEqual(['audit_chain_append_only_guard', 'audit_chain_maintenance_log', 'audit_chain_mirror_count_delete',
      'audit_chain_mirror_count_insert', 'audit_chain_mirror_count_truncate', 'audit_chain_no_truncate']);
  });

  test('MC-15 16 concurrent writers (new rows, duplicates, rolled-back transactions) → exact', async () => {
    await reset();
    const W = 16; const per = 60;
    const writers = await Promise.all(Array.from({ length: W }, async () => { const c = new Client(asTest(DB)); await c.connect(); return c; }));
    let committedNew = 0;
    try {
      await Promise.all(writers.map(async (c, w) => {
        const mine = freshRows(per);
        for (let i = 0; i < per; i++) {
          const kind = i % 6;
          if (kind === 4) {                       // a transaction that rolls back
            await c.query('BEGIN'); await insertRows(c, freshRows(2), [seq++, seq++]); await c.query('ROLLBACK');
          } else if (kind === 5) {                // a duplicate of my own row committed two steps earlier (kind 3)
            const dup = await insertRows(c, [mine[i - 2]], [seq++]);
            expect(dup).toBe(0);
            committedNew += dup;
          } else {
            const k = await insertRows(c, [mine[i]], [seq++]);   // not `x += await` — that loses concurrent updates
            committedNew += k;
          }
        }
      }));
    } finally { await Promise.all(writers.map((c) => c.end())); }
    await expectInvariant(committedNew);
  });

  test('MC-16 audit-mirror-rebuild --apply re-sequences (UPDATE seq) without changing the count', async () => {
    await reset();
    const rows = chainRows(300, { tag: `mc16-${TAG}` });
    await insertRows(fx, rows, seqPlan(300, { start: seq, swaps: [10, 100, 200] }));
    seq += 400;
    await expectInvariant(300);
    const mods = bindModules(DB);
    try {
      const c = new Client(asTest(DB)); await c.connect();
      try {
        const r = await mods.rebuild.rebuild(c, { apply: true });
        expect(r.applied).toBe(true);
        expect(r.rowsResequenced).toBeGreaterThan(0);
      } finally { await c.end(); }
    } finally { await mods.pgPool.shutdown().catch(() => {}); }
    await expectInvariant(300);
  });

  test('MC-17 DR: the counter is not dumped as data; restore rebuilds it from the restored audit_chain and proves == count(*)', async () => {
    await reset();
    await insert(freshRows(250));
    const n = await expectInvariant(250);
    const { dumpPostgres, restorePostgres } = require('../../scripts/dr/postgres');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w11cnt-dr-'));
    try {
      const dump = await dumpPostgres(dir, { connectionString: urlFor(DB) });
      const tables = dump.tables.map((t) => t.table);
      expect(tables).toContain('audit_chain');
      expect(tables).not.toContain('audit_chain_mirror_count');
      expect(fs.existsSync(path.join(dir, 'pg_audit_chain_mirror_count.json'))).toBe(false);
      const res = await restorePostgres(dir, dump, { connectionString: urlFor(DB_DR) });
      expect(res.tables.find((t) => t.table === 'audit_chain')).toMatchObject({ restored: n, skipped: 0 });
      expect(res.auditChainMirrorCount).toEqual({ present: true, previous: n, rebuilt: n, stored: n, exact: n, inSync: true });
      const drSys = new Client(asSystem(DB_DR)); await drSys.connect();
      try {
        const k = (await drSys.query('SELECT stored, exact, in_sync FROM qodiqa_audit_chain_mirror_count_check()')).rows[0];
        expect({ stored: Number(k.stored), exact: Number(k.exact), inSync: k.in_sync }).toEqual({ stored: n, exact: n, inSync: true });
      } finally { await drSys.end(); }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
