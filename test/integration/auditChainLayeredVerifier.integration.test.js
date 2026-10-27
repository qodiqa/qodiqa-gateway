'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * S3 — layered file <-> PG divergence verifier (§9; design decisions
 * 2026-10-01). Real PostgreSQL (own disposable DB, all migrations incl. 074), real entries (entryBuilder) written with
 * the real mirror INSERT; the FILE side is a facade with real getModernChainPage cursor semantics ({m, o}: reading
 * trusts the byte offset, labels the page with m), so corrupted positions behave as on disk.
 *
 * OLD = verifyPgDivergence() — the full comparison, prune-aware after the S3 fix (LV-12).
 * NEW = verifyPgDivergenceIncremental() (60 s) + verifyPgDivergenceRolling() (15 min), run until the documented
 *       detection bound: incremental = the next run; old rows = one sweep cycle = ceil(rows / slice) rolling runs.
 * Equivalence: for every fixture, NEW reports EXACTLY OLD's violations (it hands the verdict to OLD), within its bound.
 *
 *   LV-01 empty chain                         LV-11 checkpoint anchors (match / PG-row mismatch / bad signature)
 *   LV-02 genesis-only                        LV-12 legitimate prune: no ORPHAN (pre-fix predicate shown = 1)
 *   LV-03 sequential appends, several batches LV-13 unexpected missing parent after a prune → ORPHAN
 *   LV-04 resume from the persisted position  LV-14 prune NOT recorded → the anchor's missing parent is an ORPHAN
 *         (new verifier instance = restart)  LV-15 partial verification: a crash mid-pass keeps only verified
 *   LV-05 corrupted saved position → reset           boundaries; the next run resumes without skipping anything
 *   LV-06 corrupted saved hash → reset         LV-16 concurrent verifiers: one advances, the other skips (lock)
 *   LV-07 broken prev_hash (new rows)          LV-17 fallback: NEW's violations ARE the full verifier's
 *   LV-08 modified old row (verified prefix)   LV-18 the 15-min layered run reads O(slice), never the full chain
 *   LV-09 hidden deletion (verified prefix)    LV-19 runner: 60 s tick runs PG_INCREMENTAL; MANUAL = full;
 *   LV-10 inserted fork refused by the schema         QODIQA_AUDIT_DIVERGENCE_MODE=full rollback
 *   LV-20 OLD(fixed) == NEW on every clean fixture size, unpruned and pruned
 *
 * Disposable DB qodiqa_w11lv_<tag>, ledgered in %TEMP%/qodiqa-w3-ledger.jsonl, dropped in afterAll (own fixtures only).
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const TAG = `${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const DB = `qodiqa_w11lv_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const conn = (database, user, password) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000,
});
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/auditChainLayeredVerifier.integration.test.js' }) + '\n');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const quiet = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });
const OFF = (pos) => 13 + 1000 * pos;   // facade byte offset of modern position pos

jest.setTimeout(300_000);

describeOrSkip('S3 — layered divergence verifier', () => {
  let fx; let pgPool; let backend; let entryBuilder; let ChainVerifierMod; let RunnerMod;
  let created = false;
  const envSaved = {};
  let n = 0;

  // ── file facade ───────────────────────────────────────────────────────────────────────────────────────────────────
  const file = { entries: [], start: null, hooks: {} };
  const startCount = () => (file.start ? file.start.startCount : 0);
  const facade = {
    ORDERING_MODE: 'single-node',
    getChainStart: () => file.start,
    getChainStats: () => {
      const len = startCount() + file.entries.length;
      return { modernLength: len, chainLength: len, tailHash: file.entries.length ? file.entries[file.entries.length - 1].hash : (file.start ? file.start.startHash : 'GENESIS') };
    },
    getModernChainPage: async ({ cursor, limit }) => {
      const h = file.hooks; h.pages = (h.pages || 0) + 1;
      if (h.failAfterPages != null && h.pages > h.failAfterPages) throw new Error('INJECTED_FILE_READ_FAILURE');
      if (h.delayMs) await sleep(h.delayMs);
      const viaOffset = cursor && Number.isInteger(cursor.o);
      const label = cursor && Number.isInteger(cursor.m) ? (viaOffset ? cursor.m : Math.max(cursor.m, startCount())) : startCount();
      const pos = viaOffset ? (cursor.o - 13) / 1000 : label;            // reading trusts the byte offset, like audit.log
      const idx = pos - startCount();
      const es = Number.isInteger(idx) && idx >= 0 ? file.entries.slice(idx, idx + limit) : [];
      const len = startCount() + file.entries.length;
      return { entries: es, startPos: label, nextCursor: pos + es.length < len ? { m: label + es.length, o: OFF(pos + es.length) } : null };
    },
    forEachModernChainPage: async (fn, { limit }) => { for (let i = 0; i < file.entries.length; i += limit) await fn(file.entries.slice(i, i + limit)); return file.entries.length; },
    getModernChain: async () => file.entries,
    drainMirrorWriter: async () => {},
  };

  // ── fixtures ──────────────────────────────────────────────────────────────────────────────────────────────────────
  const mk = (prev) => entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: `lv-${TAG}-${n++}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true }), prev);
  async function append(k, { toPg = true } = {}) {
    const out = []; let prev = file.entries.length ? file.entries[file.entries.length - 1].hash : (file.start ? file.start.startHash : 'GENESIS');
    for (let i = 0; i < k; i++) { const e = mk(prev); out.push(e); prev = e.hash; }
    if (toPg) {
      await pgPool.withTransaction(async (tx) => {
        for (const e of out) await backend.insertMirrorRow(tx, e, { _guardQuery: async () => ({ rows: [{ parent_ok: true, self_exists: false }] }) });
      }, { isolationLevel: 'READ COMMITTED' });
    }
    file.entries.push(...out);
    return out;
  }
  async function reset() {
    for (const t of ['audit_chain_verification_progress', 'audit_chain_prunes', 'audit_signed_checkpoints', 'audit_chain']) await fx.query(`DELETE FROM ${t}`);
    file.entries = []; file.start = null; file.hooks = {};
  }
  const seqOf = async (hash) => Number((await fx.query('SELECT seq FROM audit_chain WHERE hash = $1', [hash])).rows[0].seq);

  function verifier({ events = [], slice = 100, persistEvery = 200, intervalMs = 0, checkpointVerify } = {}) {
    return ChainVerifierMod.createChainVerifier({
      config: { batchSize: 1000, sweepSliceRows: slice, persistEveryRows: persistEvery, pgDivergenceIntervalMs: intervalMs },
      _auditLog: facade, _pgPool: pgPool, _pgBackend: backend, _metrics: quiet,
      _emit: (l, t, d) => events.push({ l, t, d }),
      _checkpointVerify: checkpointVerify || (() => ({ ok: true })),
    });
  }
  const OLD = async () => (await verifier().verifyPgDivergence('MANUAL')).violations;
  // NEW until its documented bound: incremental run, then rolling runs covering one full sweep cycle.
  async function NEW(v, { slice = 100 } = {}) {
    const inc = await v.verifyPgDivergenceIncremental('SCHEDULED');
    if (inc.violations.length) return { violations: inc.violations, layer: 'incremental', runs: 1 };
    const rows = file.entries.length;
    const bound = Math.ceil(rows / slice) + 2;
    for (let i = 0; i < bound; i++) {
      const r = await v.verifyPgDivergenceRolling('SCHEDULED');
      if (r.violations.length) return { violations: r.violations, layer: 'rolling', runs: i + 1, bound };
    }
    return { violations: [], layer: null, runs: bound, bound };
  }
  const progress = async (kind) => (await fx.query('SELECT * FROM audit_chain_verification_progress WHERE kind = $1', [kind])).rows[0] || null;
  const reasons = (vs) => vs.map((v) => v.reason).sort();

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error(`unsafe db name ${DB}`);
    const m = new Client(asTest('postgres')); await m.connect();
    try { ledger('planned'); await m.query(`CREATE DATABASE "${DB}"`); created = true; ledger('created'); } finally { await m.end(); }
    const p = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    fx = new Client(asTest(DB)); await fx.connect();
    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_AUDIT_DIVERGENCE_MODE']) envSaved[k] = process.env[k];
    process.env.QODIQA_PG_ENABLED = 'true'; process.env.QODIQA_PG_DATABASE = DB; delete process.env.QODIQA_AUDIT_DIVERGENCE_MODE;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    backend = require('../../src/infra/postgres/pg-audit-backend');
    entryBuilder = require('../../src/core/audit/entryBuilder');
    ChainVerifierMod = require('../../src/core/audit/verifier/ChainVerifier');
    RunnerMod = require('../../src/core/audit/verifier');
  });

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    try { await require('../../src/infra/postgres/rolePools').shutdownAll(); } catch { /* best effort */ }
    if (fx) await fx.end().catch(() => {});
    for (const [k, v] of Object.entries(envSaved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (!created) return;
    const m = new Pool(asTest('postgres'));
    try {
      const r = await require('../helpers/dropTestDatabase').dropTestDatabase(m, DB);
      const gone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0;
      ledger(gone ? 'dropped' : `DROP-FAILED ${JSON.stringify(r)}`);
    } finally { await m.end(); }
  });

  test('LV-01 empty chain: both verifiers clean; nothing persisted beyond the base', async () => {
    await reset();
    expect(await OLD()).toEqual([]);
    const v = verifier();
    const r = await NEW(v);
    expect(r.violations).toEqual([]);
    const inc = await v.verifyPgDivergenceIncremental('SCHEDULED');
    expect(inc).toMatchObject({ success: true, status: 'OK', entriesChecked: 0 });
  });

  test('LV-02 genesis-only', async () => {
    await reset(); await append(1);
    expect(await OLD()).toEqual([]);
    const r = await NEW(verifier());
    expect(r.violations).toEqual([]);
  });

  test('LV-03 sequential appends in several batches: the position advances by verified pages only', async () => {
    await reset();
    const v = verifier();
    await append(1500);
    const a = await v.verifyPgDivergenceIncremental('SCHEDULED');
    expect(a).toMatchObject({ status: 'OK', entriesChecked: 1500 });
    expect(Number((await progress('incremental')).pos)).toBe(1000);           // last page boundary with a byte offset
    await append(1200);
    const b = await v.verifyPgDivergenceIncremental('SCHEDULED');
    expect(b.status).toBe('OK');
    expect(b.entriesChecked).toBe(1700);                                      // resumes at 1000: 500 re-checked + 1200 new
    expect(Number((await progress('incremental')).pos)).toBe(2000);
    await append(1);
    const c = await v.verifyPgDivergenceIncremental('SCHEDULED');
    expect(c.entriesChecked).toBe(701);
    expect(await OLD()).toEqual([]);
  });

  test('LV-04 restart: a NEW verifier instance resumes from the persisted, re-validated position', async () => {
    await reset(); await append(3000);
    await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    const saved = await progress('incremental');
    expect(Number(saved.pos)).toBe(2000);
    await append(50);
    const events = [];
    const r = await verifier({ events }).verifyPgDivergenceIncremental('SCHEDULED');   // "after a restart"
    expect(r.entriesChecked).toBe(1050);
    expect(events.some((e) => e.t === 'AUDIT_CHAIN_VERIFICATION_PROGRESS_RESET')).toBe(false);
  });

  test('LV-05 corrupted saved position → discarded (reset to base), full verifier runs, then re-established', async () => {
    await reset(); await append(2500);
    await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    await fx.query("UPDATE audit_chain_verification_progress SET byte_offset = byte_offset + 1000 WHERE kind = 'incremental'");   // points at the wrong entry
    const events = [];
    const r = await verifier({ events }).verifyPgDivergenceIncremental('SCHEDULED');
    expect(events.find((e) => e.t === 'AUDIT_CHAIN_VERIFICATION_PROGRESS_RESET').d).toMatchObject({ kind: 'incremental', reason: 'FILE_POSITION_MISMATCH' });
    expect(r.fallback).toMatchObject({ ran: true });
    expect(r.violations).toEqual([]);                                         // the chain itself is fine
    expect(Number((await progress('incremental')).pos)).toBe(0);
    const again = await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    expect(again).toMatchObject({ status: 'OK', entriesChecked: 2500 });
  });

  test('LV-06 corrupted saved hash → discarded, never trusted', async () => {
    await reset(); await append(1500);
    await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    await fx.query("UPDATE audit_chain_verification_progress SET prev_hash = repeat('e', 64) WHERE kind = 'incremental'");
    const events = [];
    await verifier({ events }).verifyPgDivergenceIncremental('SCHEDULED');
    expect(events.find((e) => e.t === 'AUDIT_CHAIN_VERIFICATION_PROGRESS_RESET').d.reason).toMatch(/MISMATCH/);
    // a saved pg_seq whose row does not carry prev_hash is equally refused
    await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    await fx.query("UPDATE audit_chain_verification_progress SET pg_seq = pg_seq - 3 WHERE kind = 'incremental'");
    const ev2 = [];
    await verifier({ events: ev2 }).verifyPgDivergenceIncremental('SCHEDULED');
    expect(ev2.find((e) => e.t === 'AUDIT_CHAIN_VERIFICATION_PROGRESS_RESET').d.reason).toBe('PG_POSITION_MISMATCH');
  });

  test('LV-07 broken prev_hash among NEW rows: detected by the next incremental run; violations == OLD', async () => {
    await reset(); await append(1200);
    const v = verifier();
    await v.verifyPgDivergenceIncremental('SCHEDULED');
    const fresh = await append(300);
    await fx.query('UPDATE audit_chain SET prev_hash = $1 WHERE hash = $2', [crypto.randomBytes(32).toString('hex'), fresh[100].hash]);
    const old = await OLD();
    expect(old.length).toBeGreaterThan(0);
    const r = await v.verifyPgDivergenceIncremental('SCHEDULED');
    expect(r.violations).toEqual(old);
    expect(r.fallback.ran).toBe(true);
  });

  test('LV-08 modified old row (already verified): detected within ONE sweep cycle; violations == OLD', async () => {
    await reset(); await append(1000);
    const v = verifier();
    await v.verifyPgDivergenceIncremental('SCHEDULED');
    await append(10); await v.verifyPgDivergenceIncremental('SCHEDULED');   // position at 1000: rows 0..999 verified
    await fx.query("UPDATE audit_chain SET canonical = canonical || ' ' WHERE hash = $1", [file.entries[777].hash]);
    const old = await OLD();
    expect(old.length).toBeGreaterThan(0);
    const inc = await v.verifyPgDivergenceIncremental('SCHEDULED');         // the incremental layer does NOT re-read old rows
    expect(inc.violations).toEqual([]);
    const r = await NEW(v);
    expect(r).toMatchObject({ layer: 'rolling' });
    expect(r.runs).toBeLessThanOrEqual(r.bound);
    expect(r.violations).toEqual(old);
  });

  test('LV-09 hidden deletion (verified prefix): detected within ONE sweep cycle; violations == OLD', async () => {
    await reset(); await append(1000);
    const v = verifier();
    await append(5); await v.verifyPgDivergenceIncremental('SCHEDULED');
    await fx.query('DELETE FROM audit_chain WHERE hash = $1', [file.entries[333].hash]);
    const old = await OLD();
    expect(reasons(old)).toEqual(expect.arrayContaining(['ORPHAN_RECORD']));
    const r = await NEW(v);
    expect(r.violations).toEqual(old);
  });

  test('LV-10 an inserted fork (second child of one row) is refused by the schema; the chain stays clean', async () => {
    await reset(); await append(20);
    const child = (await fx.query('SELECT * FROM audit_chain WHERE hash = $1', [file.entries[10].hash])).rows[0];
    await expect(fx.query('INSERT INTO audit_chain (hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time, input_hash, signature, request_hash, policy_hash, verification_result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
      [crypto.randomBytes(32).toString('hex'), child.prev_hash, 'fork', `fork-${TAG}`, 'ALLOW', new Date(), '0', 'a'.repeat(64), 's', 'r'.repeat(64), 'p'.repeat(64), true])).rejects.toThrow(/idx_audit_chain_prev_hash_unique/);
    expect(await OLD()).toEqual([]);
    expect((await NEW(verifier())).violations).toEqual([]);
  });

  test('LV-11 checkpoint anchors: matching rows pass; a PG row that changed, or a bad signature, hands over to the full verifier', async () => {
    await reset(); await append(1200);
    const v = verifier();
    await append(5); await v.verifyPgDivergenceIncremental('SCHEDULED');
    const put = async (pos, headHash, pgSeq) => fx.query(`INSERT INTO audit_signed_checkpoints (checkpoint_id, chain_length, head_hash, pg_seq, payload, payload_hash, signature, key_id, key_version, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, 'sig', 'cp-test:key_v1', 1, 'lv11')`, [crypto.randomUUID(), pos + 1, headHash, pgSeq,
      JSON.stringify({ v: 1, chainLength: pos + 1, headHash, pgSeq, checkpointId: crypto.randomUUID() }), crypto.randomBytes(32).toString('hex')]);
    await put(499, file.entries[499].hash, await seqOf(file.entries[499].hash));
    await put(999, file.entries[999].hash, await seqOf(file.entries[999].hash));
    const ok = await v.verifyPgDivergenceRolling('SCHEDULED');
    expect(ok).toMatchObject({ layered: true, anchorsChecked: 2, anchorMismatches: 0, violations: [] });
    // the PG row at a checkpoint changed → anchor mismatch → full verifier is the verdict (here it also sees the change)
    await fx.query("UPDATE audit_chain SET canonical = canonical || 'x' WHERE hash = $1", [file.entries[499].hash]);
    await fx.query('UPDATE audit_chain SET hash = $1 WHERE hash = $2', ['f'.repeat(64), file.entries[999].hash]);
    const old = await OLD();
    const events = [];
    const bad = await verifier({ events }).verifyPgDivergenceRolling('SCHEDULED');
    expect(events.find((e) => e.t === 'AUDIT_CHAIN_VERIFIER_ANCHOR_MISMATCH').d.mismatches[0]).toMatchObject({ reason: 'PG_ROW_HASH_MISMATCH' });
    expect(bad.violations).toEqual(old);
    // a checkpoint whose signature does not verify is an anchor mismatch too
    await reset(); await append(300); await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    await put(99, file.entries[99].hash, await seqOf(file.entries[99].hash));
    const ev2 = [];
    const sig = await verifier({ events: ev2, checkpointVerify: () => ({ ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' }) }).verifyPgDivergenceRolling('SCHEDULED');
    expect(ev2.find((e) => e.t === 'AUDIT_CHAIN_VERIFIER_ANCHOR_MISMATCH').d.mismatches[0].reason).toBe('CHECKPOINT_SIGNATURE_INVALID');
    expect(sig.fallback.ran).toBe(true);
    expect(sig.violations).toEqual([]);                                       // the chain itself is intact
    // a signature that cannot be CHECKED here (key not in this process) is reported, NOT a fallback: the sweep proceeds
    await append(1000); await verifier().verifyPgDivergenceIncremental('SCHEDULED');   // a verified prefix (page boundary 1000)
    const ev3 = [];
    const unv = await verifier({ events: ev3, checkpointVerify: () => ({ ok: false, reason: 'CHECKPOINT_KEY_UNAVAILABLE: CheckpointKeyStore: unknown checkpoint keyId "x"' }) }).verifyPgDivergenceRolling('SCHEDULED');
    expect(ev3.some((e) => e.t === 'AUDIT_CHAIN_VERIFIER_ANCHOR_UNVERIFIABLE')).toBe(true);
    expect(ev3.some((e) => e.t === 'AUDIT_CHAIN_VERIFIER_ANCHOR_MISMATCH')).toBe(false);
    expect(unv.fallback).toBeNull();
    expect(unv.sweep.status).toBe('OK');
  });

  // A legitimate M3/M4 prune at checkpoint C (chain position k): PG keeps seq >= C.pgSeq (C's row = the anchor, its
  // parent deleted), the prune is recorded, the file is rebased onto the signed base (startCount = k + 1).
  async function prunedFixture({ total = 1500, k = 599, record = true } = {}) {
    await reset(); await append(total);
    const C = file.entries[k];
    const pgSeq = await seqOf(C.hash);
    const checkpointId = crypto.randomUUID();
    await fx.query('DELETE FROM audit_chain WHERE seq < $1', [pgSeq]);
    // the signed base checkpoint the prune stopped at (audit_chain_prunes.checkpoint_id references it)
    await fx.query(`INSERT INTO audit_signed_checkpoints (checkpoint_id, chain_length, head_hash, pg_seq, payload, payload_hash, signature, key_id, key_version, created_by)
      VALUES ($1, $2, $3, $4, $5, $6, 'sig', 'cp-test:key_v1', 1, 'lv-prune')`, [checkpointId, k + 1, C.hash, pgSeq,
      JSON.stringify({ v: 1, chainLength: k + 1, headHash: C.hash, pgSeq, checkpointId }), crypto.randomBytes(32).toString('hex')]);
    if (record) {
      await fx.query(`INSERT INTO audit_chain_prunes (prune_id, checkpoint_id, from_count, to_count, audit_rows_deleted, evidence_rows_deleted, transparency_rows_deleted,
        archive_manifest_sha256, archive_location, base_record, pruned_by) VALUES ($1,$2,0,$3,$4,0,0,$5,'lv-archive','{}'::jsonb,'lv')`,
      [crypto.randomUUID(), checkpointId, k + 1, k, 'a'.repeat(64)]);
    }
    file.start = { state: 'rebased', startHash: C.hash, startCount: k + 1, checkpoint: { payload: { checkpointId, pgSeq, headHash: C.hash, chainLength: k + 1 } } };
    file.entries = file.entries.slice(k + 1);
    return { C, pgSeq, checkpointId, k };
  }

  test('LV-12 legitimate recorded prune: no ORPHAN_RECORD from either verifier (pre-fix predicate shown = 1)', async () => {
    await prunedFixture();
    expect(await backend.validateChainLinks()).toEqual({ valid: false, brokenLinks: 1 });   // what the old check counted
    const events = [];
    const old = (await verifier({ events }).verifyPgDivergence('MANUAL')).violations;
    expect(old).toEqual([]);
    expect(events.some((e) => e.t === 'AUDIT_CHAIN_VERIFIER_PRUNE_ANCHOR_EXCUSED')).toBe(true);
    const r = await NEW(verifier());
    expect(r.violations).toEqual([]);
  });

  test('LV-13 unexpected missing parent after a prune (a kept row deleted) → ORPHAN_RECORD; NEW == OLD', async () => {
    await prunedFixture();
    const v = verifier();
    await append(3); await v.verifyPgDivergenceIncremental('SCHEDULED');
    await fx.query('DELETE FROM audit_chain WHERE hash = $1', [file.entries[200].hash]);
    const old = await OLD();
    expect(old.find((x) => x.reason === 'ORPHAN_RECORD')).toMatchObject({ brokenLinks: 1 });   // the anchor excused, this one not
    const r = await NEW(v);
    expect(r.violations).toEqual(old);
  });

  test('LV-14 a prune that is NOT recorded: the anchor\'s missing parent stays an ORPHAN_RECORD', async () => {
    await prunedFixture({ record: false });
    const old = await OLD();
    expect(old.find((x) => x.reason === 'ORPHAN_RECORD')).toMatchObject({ brokenLinks: 1 });
  });

  test('LV-15 partial verification: a crash mid-pass keeps only verified boundaries; the next run resumes without a gap', async () => {
    await reset(); await append(3500);
    file.hooks = { failAfterPages: 2 };                                       // dies while reading the 3rd page
    await expect(verifier({ persistEvery: 1000 }).verifyPgDivergenceIncremental('SCHEDULED')).rejects.toThrow('INJECTED_FILE_READ_FAILURE');
    const saved = await progress('incremental');
    expect(Number(saved.pos)).toBe(2000);                                     // pages 1-2 verified and persisted (every 1000 rows); page 3 never read
    file.hooks = {};
    const r = await verifier().verifyPgDivergenceIncremental('SCHEDULED');
    expect(r).toMatchObject({ status: 'OK', entriesChecked: 1500 });          // 2000..3499: nothing skipped
    expect(Number((await progress('incremental')).pos)).toBe(3000);
  });

  test('LV-16 concurrent verifiers: one holds the advisory lock and advances; the other skips', async () => {
    await reset(); await append(2500);
    file.hooks = { delayMs: 150 };
    const [a, b] = await Promise.all([verifier().verifyPgDivergenceIncremental('SCHEDULED'), (async () => { await sleep(50); return verifier().verifyPgDivergenceIncremental('SCHEDULED'); })()]);
    file.hooks = {};
    const outcomes = [a, b].map((x) => (x.skipped ? x.reason : x.status)).sort();
    expect(outcomes).toEqual(['LOCK_NOT_ACQUIRED', 'OK']);
    expect(Number((await progress('incremental')).pos)).toBe(2000);
  });

  test('LV-17 fallback: on any disagreement NEW reports the full verifier\'s own violations, rate-limited to its interval', async () => {
    await reset(); await append(1100);
    const v = verifier({ intervalMs: 60_000 });
    await v.verifyPgDivergenceIncremental('SCHEDULED');
    await append(50);
    await fx.query('DELETE FROM audit_chain WHERE hash = $1', [file.entries[1120].hash]);
    const r1 = await v.verifyPgDivergenceIncremental('SCHEDULED');
    expect(r1.fallback.ran).toBe(true);
    expect(r1.violations).toEqual(await OLD());
    const r2 = await v.verifyPgDivergenceIncremental('SCHEDULED');            // still disagreeing, inside the interval
    expect(r2.fallback).toMatchObject({ ran: false, rateLimited: true });
    expect(r2.status).toBe('DISAGREE');
  });

  test('LV-18 the 15-min layered run reads O(slice): no full-chain read, rows read bounded by the slice', async () => {
    await reset(); await append(5000);
    const v = verifier({ slice: 1000 });
    await v.verifyPgDivergenceIncremental('SCHEDULED');
    const calls = {};
    const spy = new Proxy(backend, { get: (t, k) => { const f = t[k]; return typeof f === 'function' ? (...a) => { calls[k] = (calls[k] || 0) + 1; return f.apply(t, a); } : f; } });
    const v2 = ChainVerifierMod.createChainVerifier({ config: { sweepSliceRows: 1000, pgDivergenceIntervalMs: 0 }, _auditLog: facade, _pgPool: pgPool, _pgBackend: spy,
      _metrics: quiet, _emit: () => {}, _checkpointVerify: () => ({ ok: true }) });
    const r = await v2.verifyPgDivergenceRolling('SCHEDULED');
    expect(r).toMatchObject({ layered: true, sweep: { status: 'OK', rows: 1000 } });
    for (const full of ['validateChainLinks', 'loadChainFromPg', 'loadChainFromPgCompact', 'forEachChainPageCompactInSnapshot', 'countChainRows', 'listChainLinkOrphans']) expect(calls[full] || 0).toBe(0);
    expect(calls.fetchChainBatch).toBe(1);                                    // one 2,000-row page covers the 1,000-row slice
    // a full sweep cycle completes and restarts from the base
    let done = false;
    for (let i = 0; i < 6 && !done; i++) done = (await v2.verifyPgDivergenceRolling('SCHEDULED')).sweep.cycleCompleted;
    expect(done).toBe(true);
    expect(Number((await progress('sweep')).cycles_completed)).toBe(1);
  });

  test('LV-19 runner: the 60 s tick runs INCREMENTAL then PG_INCREMENTAL; MANUAL divergence = full; mode=full rollback', async () => {
    await reset(); await append(1200);
    const modes = [];
    const runner = RunnerMod.createVerifierRunner({
      config: { enabled: true, incrementalIntervalMs: 100, fullIntervalMs: 0, pgDivergenceIntervalMs: 0, maxRetries: 0, retryDelayMs: 0, startupScan: false, trackCompletion: false },
      _onRunStart: (m) => modes.push(m), _emit: () => {}, _metrics: quiet,
      _auditLog: { ...facade, getModernChainSlice: async () => [], verifyAuditChainDetailedChunked: async () => ({ valid: true, entriesVerified: 0 }) },
      _pgPool: pgPool, _pgBackend: backend, _verifierState: { loadFileState: async () => null, saveFileState: async () => {} }, _checkpointVerify: () => ({ ok: true }),
    });
    await runner.start();
    for (let i = 0; i < 50 && !modes.includes('PG_INCREMENTAL'); i++) await sleep(100);
    runner.stop();
    for (let i = 0; i < 100 && runner.isScanning(); i++) await sleep(50);   // the tick in flight finishes (shared mutex)
    expect(modes.slice(0, 2)).toEqual(['INCREMENTAL', 'PG_INCREMENTAL']);
    const manual = await runner.verifyPgDivergenceNow();
    expect(manual.layered).toBeUndefined();                                  // MANUAL = the full comparison
    expect(manual.success).toBe(true);
    process.env.QODIQA_AUDIT_DIVERGENCE_MODE = 'full';
    try { expect(require('../../src/core/audit/verifier/verifierConfig').load().divergenceMode).toBe('full'); } finally { delete process.env.QODIQA_AUDIT_DIVERGENCE_MODE; }
    const rolled = await verifier().verifyPgDivergenceRolling.call(null, 'SCHEDULED');
    expect(rolled.layered).toBe(true);
    const fullMode = ChainVerifierMod.createChainVerifier({ config: { divergenceMode: 'full' }, _auditLog: facade, _pgPool: pgPool, _pgBackend: backend, _metrics: quiet, _emit: () => {} });
    expect((await fullMode.verifyPgDivergenceRolling('SCHEDULED')).layered).toBeUndefined();
    expect(await fullMode.verifyPgDivergenceIncremental('SCHEDULED')).toMatchObject({ skipped: true, reason: 'DIVERGENCE_MODE_FULL' });
  });

  test('LV-20 OLD(fixed) == NEW on clean fixtures of several sizes, unpruned and pruned', async () => {
    for (const size of [1, 999, 1000, 1001, 4321]) {
      await reset(); await append(size);
      expect({ size, old: await OLD() }).toEqual({ size, old: [] });
      expect({ size, new: (await NEW(verifier())).violations }).toEqual({ size, new: [] });
    }
    for (const k of [0, 999, 1499]) {
      await prunedFixture({ total: 2000, k });
      expect({ k, old: await OLD() }).toEqual({ k, old: [] });
      expect({ k, new: (await NEW(verifier())).violations }).toEqual({ k, new: [] });
    }
  });
});
