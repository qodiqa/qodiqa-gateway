'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * S1 — qodiqa_audit_chain_true_tail() made indexable (migration 072), proven equal to the migration-058
 * definition.
 *
 *   TT-01  empty table → no row (oracle: no row)
 *   TT-02  GENESIS-only chain → that row
 *   TT-03  linear chain with seq gaps + idempotent replays → equal to the oracle and to the known last row
 * TT-04 earlier history: adjacent seq inversions, including the top pair (tail is NOT the max-seq row) → equal
 *   TT-05  pruned shape: the first kept row's parent is absent (prune.js leaves C's row as anchor) → equal
 *   TT-06  randomised histories (sizes, gaps, inversions, pruned roots) → equal on every one
 *   TT-07  plan shape on a 50k-row chain after ANALYZE: the INSTALLED body uses idx_audit_chain_prev_hash_unique
 *          (Index Only Scan) and has no Seq Scan on audit_chain; the function call reads a handful of buffers while
 *          the oracle body reads the table
 *   TT-08  definer contract unchanged: SECURITY DEFINER, search_path pinned, STABLE, same result type, EXECUTE for
 *          qodiqa_system only (not PUBLIC / qodiqa_app / qodiqa_read)
 *   TT-09  migration 072's premise guard refuses (and changes nothing) when a row breaks the premise: a prev_hash with
 *          a trailing blank, and a hash that is not 64 lowercase hex
 *   TT-10  the application path pg-audit-backend.getChainTail() (rolePools.system) returns the oracle tail
 *
 * Disposable DB qodiqa_w11tail_<pid>_<hex>, appended to %TEMP%/qodiqa-w3-ledger.jsonl before creation, dropped and
 * verified gone in afterAll. Only this suite's own fixture rows are inserted/deleted, in its own database.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');
const { ORACLE_TRUE_TAIL_SQL, chainRows, seqPlan, insertRows } = require('../helpers/auditChainFixtures');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const TAG = `${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const DB = `qodiqa_w11tail_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const MIGRATION_072 = path.join(__dirname, '..', '..', 'src', 'infra', 'postgres', 'migrations', '072_audit_chain_true_tail_indexed.sql');

const conn = (database, user, password) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000,
});
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const asSystem = (db) => conn(db, 'qodiqa_system', process.env.QODIQA_PG_SYSTEM_PASSWORD);
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/auditChainTrueTail.integration.test.js' }) + '\n');

jest.setTimeout(240_000);

describeOrSkip('S1 — indexed qodiqa_audit_chain_true_tail() (migration 072)', () => {
  let fx;   // qodiqa_test: fixture writes, oracle, catalog reads
  let sys;  // qodiqa_system: the role the application calls the function as
  let created = false;

  const fn = async () => (await sys.query('SELECT hash, seq FROM qodiqa_audit_chain_true_tail()')).rows[0] || null;
  const oracle = async () => (await fx.query(ORACLE_TRUE_TAIL_SQL)).rows[0] || null;
  const norm = (r) => (r ? { hash: String(r.hash).trim(), seq: String(r.seq) } : null);
  const reset = async () => { await fx.query('DELETE FROM audit_chain'); };   // this suite's own fixture rows only
  const expectEqualToOracle = async () => {
    const [a, b] = [norm(await fn()), norm(await oracle())];
    expect(a).toEqual(b);
    return a;
  };

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error(`unsafe db name ${DB}`);
    if (!process.env.QODIQA_PG_TEST_USER || !process.env.QODIQA_PG_SYSTEM_PASSWORD) throw new Error('QODIQA_PG_TEST_USER and QODIQA_PG_SYSTEM_PASSWORD are required');
    const m = new Client(asTest('postgres')); await m.connect();
    try { ledger('planned'); await m.query(`CREATE DATABASE "${DB}"`); created = true; ledger('created'); } finally { await m.end(); }
    const p = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    fx = new Client(asTest(DB)); await fx.connect();
    sys = new Client(asSystem(DB)); await sys.connect();
  });

  afterAll(async () => {
    for (const c of [fx, sys]) if (c) await c.end().catch(() => {});
    if (!created) return;
    const m = new Pool(asTest('postgres'));
    try {
      const { dropTestDatabase } = require('../helpers/dropTestDatabase');
      const r = await dropTestDatabase(m, DB);
      const gone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      ledger(gone ? 'dropped' : `DROP-FAILED ${JSON.stringify(r)}`);
    } finally { await m.end(); }
  });

  test('migration 072 is applied', async () => {
    const r = await fx.query('SELECT 1 FROM qodiqa_migrations WHERE version = 72');
    expect(r.rowCount).toBe(1);
  });

  test('TT-01 empty table → no row, like the oracle', async () => {
    await reset();
    expect(await fn()).toBeNull();
    expect(await oracle()).toBeNull();
  });

  test('TT-02 GENESIS-only chain → that row', async () => {
    await reset();
    const rows = chainRows(1, { tag: 'tt02' });
    await insertRows(fx, rows, [1]);
    const t = await expectEqualToOracle();
    expect(t).toEqual({ hash: rows[0].hash, seq: '1' });
  });

  test('TT-03 linear chain with seq gaps and idempotent replays → oracle tail = known last row', async () => {
    await reset();
    const rows = chainRows(3000, { tag: 'tt03' });
    const seqs = seqPlan(3000, { gapEvery: 97, gapSize: 5 });
    expect(await insertRows(fx, rows, seqs)).toBe(3000);
    expect(await insertRows(fx, rows.slice(1000, 1500), seqs.slice(1000, 1500))).toBe(0); // replay: ON CONFLICT no-op
    const t = await expectEqualToOracle();
    expect(t).toEqual({ hash: rows[2999].hash, seq: String(seqs[2999]) });
  });

  test('TT-04 earlier seq inversions, including the top pair (tail is not the max-seq row) → equal to the oracle', async () => {
    await reset();
    const rows = chainRows(2000, { tag: 'tt04' });
    const seqs = seqPlan(2000, { swaps: [100, 700, 1500], swapTop: true });
    await insertRows(fx, rows, seqs);
    const t = await expectEqualToOracle();
    expect(t.hash).toBe(rows[1999].hash);                                   // still the link tail
    const maxSeq = (await fx.query('SELECT max(seq) m FROM audit_chain')).rows[0].m;
    expect(t.seq).not.toBe(String(maxSeq));                                   // ...which no longer has max(seq)
  });

  test('TT-05 pruned shape: the first kept row\'s parent is absent → equal to the oracle', async () => {
    await reset();
    const all = chainRows(1500, { tag: 'tt05' });
    const kept = all.slice(1000);                                             // as if seq < C.pgSeq were deleted
    await insertRows(fx, kept, seqPlan(kept.length, { start: 1001 }));
    const anchor = (await fx.query('SELECT prev_hash FROM audit_chain WHERE seq = 1001')).rows[0].prev_hash;
    expect((await fx.query('SELECT 1 FROM audit_chain WHERE hash = $1', [anchor])).rowCount).toBe(0);
    const t = await expectEqualToOracle();
    expect(t.hash).toBe(all[1499].hash);
  });

  test('TT-06 randomised histories → equal to the oracle on every one', async () => {
    const rnd = (k) => crypto.randomInt(k);
    for (let trial = 0; trial < 12; trial++) {
      await reset();
      const n = 1 + rnd(1500);
      const pruned = rnd(3) === 0;
      const rows = chainRows(n, { tag: `tt06-${trial}`, parent: pruned ? 'f'.repeat(64) : 'GENESIS' });
      const swaps = Array.from({ length: rnd(6) }, () => rnd(Math.max(1, n - 1)));
      const seqs = seqPlan(n, { start: 1 + rnd(50), gapEvery: rnd(2) ? 1 + rnd(40) : 0, gapSize: 1 + rnd(9), swaps, swapTop: rnd(4) === 0 });
      await insertRows(fx, rows, seqs);
      const t = await expectEqualToOracle();
      expect(t.hash).toBe(rows[n - 1].hash);
    }
  });

  describe('TT-07 plan shape at 50k rows', () => {
    let rows;
    beforeAll(async () => {
      await reset();
      rows = chainRows(50_000, { tag: 'tt07' });
      await insertRows(fx, rows, seqPlan(50_000, { gapEvery: 1000, gapSize: 2 }));
      // VACUUM, not just ANALYZE — an Index Only Scan is only costed as cheap once the
      // visibility map marks the freshly inserted pages all-visible, which otherwise depends on autovacuum timing (the
      // source of this test's load-dependent flake, locally and in the hosted-CI rehearsal). A steady-state append-only
      // audit_chain is autovacuumed; the assertions below are unchanged.
      await fx.query('VACUUM ANALYZE audit_chain');
    });

    const planNodes = (plan) => { const out = []; const walk = (n) => { out.push(n); (n.Plans || []).forEach(walk); }; walk(plan); return out; };

    test('the INSTALLED body: Index Only Scan on a prev_hash index, no Seq Scan on audit_chain', async () => {
      const src = (await fx.query("SELECT prosrc FROM pg_proc WHERE proname = 'qodiqa_audit_chain_true_tail'")).rows[0].prosrc;
      expect(src).toMatch(/b\.prev_hash = a\.hash::varchar/);
      const p = (await fx.query(`EXPLAIN (FORMAT JSON) ${src}`)).rows[0]['QUERY PLAN'][0];
      const nodes = planNodes(p.Plan);
      const shape = nodes.map((n) => `${n['Node Type']}${n['Index Name'] ? `(${n['Index Name']})` : ''}${n['Relation Name'] ? `[${n['Relation Name']}]` : ''}`);
      // audit_chain carries TWO btree indexes on (prev_hash) — idx_audit_chain_prev_hash (001)
      // and idx_audit_chain_prev_hash_unique (026). Either gives the O(log n) index-only probe this asserts; the planner
      // picks between the two on cost ties (seen on PG17 in the hosted-CI rehearsal). The O(n) Seq Scan stays forbidden.
      const PREV_HASH_INDEXES = ['idx_audit_chain_prev_hash_unique', 'idx_audit_chain_prev_hash'];
      expect({ shape, indexOnly: nodes.some((n) => n['Node Type'] === 'Index Only Scan' && PREV_HASH_INDEXES.includes(n['Index Name'])) }).toEqual({ shape, indexOnly: true });
      expect(nodes.filter((n) => n['Node Type'] === 'Seq Scan' && n['Relation Name'] === 'audit_chain')).toEqual([]);
      const oracleP = (await fx.query(`EXPLAIN (FORMAT JSON) ${ORACLE_TRUE_TAIL_SQL}`)).rows[0]['QUERY PLAN'][0];
      expect(planNodes(oracleP.Plan).some((n) => n['Node Type'] === 'Seq Scan' && n['Relation Name'] === 'audit_chain')).toBe(true); // the fixture does exercise the old O(n) plan
    });

    test('the function call (as qodiqa_system) touches a handful of buffers; the oracle body reads the table', async () => {
      // The FIRST call in a backend populates catalog caches (~0.8-0.9k blocks, constant in table size — measured at
      // 5k/50k/150k rows). The application calls it on long-lived
      // qodiqa_system pool connections, so the measured call is a warm one.
      await sys.query('SELECT * FROM qodiqa_audit_chain_true_tail()');
      const fnP = (await sys.query('EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM qodiqa_audit_chain_true_tail()')).rows[0]['QUERY PLAN'][0];
      const orP = (await fx.query(`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) ${ORACLE_TRUE_TAIL_SQL}`)).rows[0]['QUERY PLAN'][0];
      const blocks = (p) => (p.Plan['Shared Hit Blocks'] || 0) + (p.Plan['Shared Read Blocks'] || 0);
      const heapBlocks = Number((await fx.query("SELECT relpages FROM pg_class WHERE relname = 'audit_chain'")).rows[0].relpages);
      expect(blocks(fnP)).toBeLessThan(50);
      expect(blocks(fnP) * 50).toBeLessThan(heapBlocks);
      expect(blocks(orP)).toBeGreaterThan(heapBlocks);
      expect(norm((await sys.query('SELECT * FROM qodiqa_audit_chain_true_tail()')).rows[0])).toEqual(norm(await oracle()));
      expect(norm(await fn())).toEqual({ hash: rows[49_999].hash, seq: norm(await oracle()).seq });
    });
  });

  test('TT-08 definer contract unchanged', async () => {
    const r = (await fx.query(`SELECT p.prosecdef, p.proconfig, p.provolatile, pg_get_function_result(p.oid) AS result,
        has_function_privilege('qodiqa_system', p.oid, 'EXECUTE') AS sys_x, has_function_privilege('qodiqa_app', p.oid, 'EXECUTE') AS app_x,
        has_function_privilege('qodiqa_read', p.oid, 'EXECUTE') AS read_x, has_function_privilege('public', p.oid, 'EXECUTE') AS public_x
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname = 'qodiqa_audit_chain_true_tail'`)).rows;
    expect(r).toHaveLength(1);
    expect(r[0]).toEqual({ prosecdef: true, proconfig: ['search_path=pg_catalog, public, pg_temp'], provolatile: 's',
      result: 'TABLE(hash character, seq bigint)', sys_x: true, app_x: false, read_x: false, public_x: false });
  });

  describe('TT-09 premise guard', () => {
    const sql = () => fs.readFileSync(MIGRATION_072, 'utf8');
    const bodyNow = async () => (await fx.query("SELECT prosrc FROM pg_proc WHERE proname = 'qodiqa_audit_chain_true_tail'")).rows[0].prosrc;

    test('a prev_hash with a trailing blank → migration refused, nothing changed', async () => {
      await reset();
      const rows = chainRows(3, { tag: 'tt09a' });
      await insertRows(fx, rows, [1, 2, 3]);
      await fx.query('INSERT INTO audit_chain (seq, hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time, input_hash, signature, request_hash, policy_hash, verification_result) VALUES (4, $1, $2, \'x\', \'tt09a-blank\', \'ALLOW\', now(), \'0\', $3, $4, $5, $6, true)',
        [crypto.createHash('sha256').update('tt09a-blank').digest('hex'), `${rows[2].hash.slice(0, 63)} `, 'a'.repeat(64), 's'.repeat(64), 'r'.repeat(64), 'p'.repeat(64)]);
      const before = await bodyNow();
      await expect(fx.query(sql())).rejects.toThrow(/migration 072 refused: 0 .* and 1 with a prev_hash/);
      await fx.query('ROLLBACK').catch(() => {});
      expect(await bodyNow()).toBe(before);
    });

    test('a hash that is not 64 lowercase hex → migration refused, nothing changed', async () => {
      await reset();
      await insertRows(fx, [{ hash: 'A'.repeat(64), prevHash: 'GENESIS' }], [1]);
      const before = await bodyNow();
      await expect(fx.query(sql())).rejects.toThrow(/migration 072 refused: 1 audit_chain row/);
      await fx.query('ROLLBACK').catch(() => {});
      expect(await bodyNow()).toBe(before);
    });

    test('on conforming data the migration re-applies cleanly (idempotent)', async () => {
      await reset();
      await insertRows(fx, chainRows(10, { tag: 'tt09c' }), seqPlan(10));
      await expect(fx.query(sql())).resolves.toBeDefined();
      await expectEqualToOracle();
    });
  });

  test('TT-10 application path: pg-audit-backend.getChainTail() (rolePools.system) returns the oracle tail', async () => {
    await reset();
    const rows = chainRows(500, { tag: 'tt10' });
    const seqs = seqPlan(500, { gapEvery: 50 });
    await insertRows(fx, rows, seqs);
    const keys = ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE'];
    const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_DATABASE = DB;
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    try {
      const tail = await require('../../src/infra/postgres/pg-audit-backend').getChainTail();
      expect(tail).toEqual({ hash: rows[499].hash, seq: seqs[499] });
      expect(norm(tail)).toEqual(norm(await oracle()));
    } finally {
      await pgPool.shutdown().catch(() => {});
      for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
  });
});
