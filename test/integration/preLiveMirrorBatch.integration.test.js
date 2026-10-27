'use strict';

/**
 * phase 9 — batched single-node audit mirror (pg-audit-backend.persistEntries +
 * chainStore._recordEvidenceBatchOrThrow) on real PostgreSQL.
 *
 *   PB-01  a contiguous batch with MIXED tenants (split into same-tenant runs) is mirrored completely: seq order = chain
 *          order, the mirror counter = count(*), and every row is visible under its own tenant context
 *   PB-02  the evidence chain built by the batched path is gap-free and correctly linked (id = prior + 1,
 *          previous_evidence_hash = the prior record's evidence_hash, head = last record) — the same chain the per-entry
 *          path builds — and it continues seamlessly into a following per-entry write
 * PB-03 replaying an already-mirrored batch inserts nothing and burns no evidence id
 *   PB-04  a NON-contiguous batch (a missing parent) falls back to the per-entry path: the parent-less entry is NOT
 *          committed out of order (AUDIT_MIRROR_PARENT_MISSING → recovery queue), everything before it is mirrored
 *
 * Disposable DB qodiqa_plbatch_<tag> on the explicitly configured (opt-in) cluster, ledgered, dropped in afterAll.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');

const RUN = process.env.QODIQA_ALLOW_PG_INTEGRATION_TESTS === 'true' && process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = RUN ? describe : describe.skip;
const TAG = `${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const DB = `qodiqa_plbatch_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const conn = (database, user, password) => ({ host: process.env.QODIQA_PG_HOST, port: parseInt(process.env.QODIQA_PG_PORT, 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000 });
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const ledger = (db, event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event, by: 'test/integration/preLiveMirrorBatch.integration.test.js' }) + '\n');

jest.setTimeout(180_000);

describeOrSkip('phase 9 — batched audit mirror on real PostgreSQL', () => {
  let fx; let mods; let created = false; const saved = {};
  let prev = 'GENESIS'; let n = 0;

  const build = (count, tenantOf = () => null) => {
    const out = [];
    for (let i = 0; i < count; i++, n++) {
      const tenantId = tenantOf(n);
      const e = mods.entryBuilder.buildEntry(mods.entryBuilder.normalizeFields({ artifactId: `plb-${TAG}-${n}`, inputHash: 'a'.repeat(64), decision: 'ALLOW',
        outputHash: mods.entryBuilder.EMPTY_OUTPUT_HASH, signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
        ...(tenantId ? { tenantId } : {}) }), prev);
      out.push(e); prev = e.hash;
    }
    return out;
  };
  const chainOk = async () => (await fx.query('SELECT bool_and(ok) ok, count(*)::int n FROM (SELECT prev_hash = lag(hash) OVER (ORDER BY seq) OR lag(hash) OVER (ORDER BY seq) IS NULL ok FROM audit_chain) s')).rows[0];
  const evidence = async () => (await fx.query('SELECT id::int, previous_evidence_hash p, evidence_hash h FROM evidence_chain_records ORDER BY id')).rows;
  const evidenceOk = async () => {
    const rows = await evidence();
    const head = (await fx.query('SELECT tail_hash, tail_id::int FROM evidence_chain_head')).rows[0];
    for (let i = 1; i < rows.length; i++) { expect(rows[i].id).toBe(rows[i - 1].id + 1); expect(rows[i].p).toBe(rows[i - 1].h); }
    if (rows.length) expect(head).toEqual({ tail_hash: rows[rows.length - 1].h, tail_id: rows[rows.length - 1].id });
    return rows.length;
  };

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    const m = new Client(asTest('postgres')); await m.connect();
    try { ledger(DB, 'planned'); await m.query(`CREATE DATABASE "${DB}"`); created = true; ledger(DB, 'created'); } finally { await m.end(); }
    const p = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    fx = new Client(asTest(DB)); await fx.connect();
    for (const k of ['QODIQA_PG_DATABASE']) saved[k] = process.env[k];
    process.env.QODIQA_PG_DATABASE = DB;
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    mods = { pgPool, backend: require('../../src/infra/postgres/pg-audit-backend'), entryBuilder: require('../../src/core/audit/entryBuilder') };
  });

  afterAll(async () => {
    if (mods) await mods.pgPool.shutdown().catch(() => {});
    if (fx) await fx.end().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (!created) return;
    const m = new Pool(asTest('postgres'));
    try {
      const { dropTestDatabase } = require('../helpers/dropTestDatabase');
      const r = await dropTestDatabase(m, DB);
      const gone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      ledger(DB, gone ? 'dropped' : `DROP-FAILED ${JSON.stringify(r)}`);
    } finally { await m.end(); }
  });

  test('PB-01/PB-02 mixed-tenant batch: complete, chain-ordered, counter exact, evidence gap-free and linked', async () => {
    const batch = build(40, (i) => (i % 7 < 3 ? null : (i % 2 ? 'plb-tenant-a' : 'plb-tenant-b')));
    await mods.backend.persistEntries(batch);
    expect(await chainOk()).toEqual({ ok: true, n: 40 });
    const counter = Number((await fx.query('SELECT row_count FROM audit_chain_mirror_count')).rows[0].row_count);
    expect(counter).toBe(40);
    expect(await evidenceOk()).toBe(40);
    // continues seamlessly into the unchanged per-entry path
    const [single] = build(1);
    await mods.backend.persistEntry(single);
    expect(await chainOk()).toEqual({ ok: true, n: 41 });
    expect(await evidenceOk()).toBe(41);
  });

  test('PB-03 replaying an already-mirrored batch inserts nothing and burns no evidence id', async () => {
    const batch = build(10);
    await mods.backend.persistEntries(batch);
    const before = { chain: await chainOk(), ev: await evidence() };
    await mods.backend.persistEntries(batch);
    expect(await chainOk()).toEqual(before.chain);
    expect(await evidence()).toEqual(before.ev);
    const [next] = build(1); await mods.backend.persistEntry(next);  // the next id is still prior + 1
    expect(await evidenceOk()).toBe(before.ev.length + 1);
  });

  test('PB-04 a non-contiguous batch falls back per entry and never commits a parent-less row', async () => {
    const all = build(6);
    const gapped = [all[0], all[1], all[3], all[4]];               // all[2] never handed over
    const rowsBefore = (await chainOk()).n;
    await mods.backend.persistEntries(gapped);
    const present = (await fx.query('SELECT hash FROM audit_chain WHERE hash = ANY($1)', [all.map((e) => e.hash)])).rows.map((r) => r.hash.trim());
    expect(present.sort()).toEqual([all[0].hash, all[1].hash].sort());     // all[3]/all[4] wait for their parent
    expect((await chainOk())).toEqual({ ok: true, n: rowsBefore + 2 });
    const queued = Number((await fx.query("SELECT count(*) n FROM persistence_recovery_queue WHERE operation_type = 'AUDIT_CHAIN_PG_SAVE'")).rows[0].n);
    expect(queued).toBeGreaterThanOrEqual(2);
  });
});
