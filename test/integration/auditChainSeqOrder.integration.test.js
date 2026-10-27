'use strict';

/**
 * the auditor's seq-order experiment, as a permanent test.
 *
 * The REAL audit-log.append() with 500 concurrent
 * callers in single-node mode + PG mirror produced 7 seq-order link breaks and
 * 1 child-before-parent inversion, because the mirror INSERT was fired per
 * entry without awaiting and seq = nextval() is drawn at INSERT time.
 *
 * A — live: 3 rounds x 500 concurrent real appends through the real module,
 *     runtime role qodiqa_app, disposable DB. After each round: 0 seq breaks,
 *     0 inversions, PG row count == file chain length, nothing parked in the
 *     recovery queue, and a POSITIONAL (seq-order) walk of the mirror is valid.
 * B — historical fixture: the same real rows copied into a second disposable
 *     DB with 7 adjacent seq pairs swapped (the auditor's S2 shape). Proves:
 *     the old positional walk breaks on it (the fixture is real); the
 *     hash-link reads (loadChainFromPg) and the distributed-mode verifier walk
 *     it WITHOUT a false CRITICAL; audit-mirror-rebuild --check reports "not
 *     ready"; --apply re-sequences it with every hash/prev_hash/canonical
 *     unchanged, after which it is ready and positionally valid.
 *
 * Disposable DBs: qodiqa_w3seq_<pid>_<hex> / qodiqa_w3seqfx_<pid>_<hex>, names
 * appended to %TEMP%/qodiqa-w3-ledger.jsonl BEFORE creation, dropped and
 * verified gone in afterAll.
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
const DB_A = `qodiqa_w3seq_${TAG}`;
const DB_B = `qodiqa_w3seqfx_${TAG}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const SAFE = /^[a-z][a-z0-9_]{0,62}$/;
const ROUNDS = 3;
const PER_ROUND = 500;

const APP_USER = process.env.QODIQA_PG_USER;
const APP_PASSWORD = process.env.QODIQA_PG_PASSWORD;
const conn = (database, user, password) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user, password, ssl: false, connectionTimeoutMillis: 5000,
});
const asTest = (db) => conn(db, process.env.QODIQA_PG_TEST_USER, process.env.QODIQA_PG_TEST_PASSWORD);
const ledger = (db, event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db, event, by: 'test/integration/auditChainSeqOrder.integration.test.js' }) + '\n');

jest.setTimeout(240_000);

async function seqRows(db) {
  const c = new Client(asTest(db)); await c.connect();
  try {
    const r = await c.query('SELECT seq, hash, prev_hash, canonical FROM audit_chain ORDER BY seq ASC');
    return r.rows.map((x) => ({ seq: Number(x.seq), hash: x.hash.trim(), prevHash: x.prev_hash.trim(), canonical: x.canonical }));
  } finally { await c.end(); }
}

describeOrSkip('single-node PG mirror: seq order = hash-chain order', () => {
  let tmpDir; const created = [];
  let mods; // modules bound to DB_A
  const saved = {};

  function bindModules(db) {
    for (const k of ['QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_AUDIT_LOG', 'QODIQA_PRQ_JOURNAL_DIR', 'QODIQA_AUDIT_ORDERING_MODE', 'QODIQA_PG_ENABLED']) {
      if (!(k in saved)) saved[k] = process.env[k];
    }
    process.env.QODIQA_PG_ENABLED = 'true';
    process.env.QODIQA_PG_DATABASE = db;
    process.env.QODIQA_PG_USER = APP_USER;              // runtime role, like the auditor
    process.env['QODIQA_PG_PASSWORD'] = APP_PASSWORD;
    delete process.env.QODIQA_AUDIT_ORDERING_MODE;       // single-node
    jest.resetModules();
    const pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    return {
      pgPool,
      audit: require('../../src/core/audit/audit-log'),
      pgAuditBackend: require('../../src/infra/postgres/pg-audit-backend'),
      rebuild: require('../../scripts/audit-mirror-rebuild'),
      verifier: require('../../src/core/audit/verifier/ChainVerifier'),
    };
  }

  beforeAll(async () => {
    for (const db of [DB_A, DB_B]) if (!SAFE.test(db)) throw new Error(`unsafe db name ${db}`);
    if (!process.env.QODIQA_PG_TEST_USER || !APP_USER) throw new Error('QODIQA_PG_TEST_USER and QODIQA_PG_USER are required');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w3seq-'));
    const m = new Client(asTest('postgres')); await m.connect();
    try {
      for (const db of [DB_A, DB_B]) {
        ledger(db, 'planned');
        await m.query(`CREATE DATABASE "${db}"`);
        created.push(db); ledger(db, 'created');
      }
    } finally { await m.end(); }
    for (const db of [DB_A, DB_B]) {
      const p = new Pool(asTest(db));
      try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: p }); } finally { await p.end(); }
    }
    process.env.QODIQA_AUDIT_LOG = path.join(tmpDir, 'audit.log');
    process.env.QODIQA_PRQ_JOURNAL_DIR = path.join(tmpDir, 'prq-journal');
    mods = bindModules(DB_A);
  });

  afterAll(async () => {
    if (mods) await mods.pgPool.shutdown().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    const m = new Client(asTest('postgres')); await m.connect();
    try {
      for (const db of created) {
        try { await m.query(`DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`); } catch { await m.query(`DROP DATABASE IF EXISTS "${db}" WITH (FORCE)`); }
        const gone = (await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [db])).rowCount === 0;
        ledger(db, gone ? 'dropped' : 'DROP-FAILED');
      }
    } finally { await m.end(); }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const params = () => ({
    artifactId: crypto.randomUUID(), inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 's'.repeat(64),
    requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true,
  });

  describe('A — 500 concurrent real appends, 3 rounds', () => {
    for (let round = 1; round <= ROUNDS; round++) {
      test(`round ${round}: 0 seq breaks, 0 inversions, mirror complete, nothing queued, positional walk valid`, async () => {
        const { audit, rebuild } = mods;
        await Promise.all(Array.from({ length: PER_ROUND }, () => audit.append(params())));
        await audit.drainPendingWrites();
        await audit.drainMirrorWriter();

        const rows = await seqRows(DB_A);
        const a = rebuild._analyse(rows);
        expect(rows.length).toBe(PER_ROUND * round);
        expect(rows.length).toBe((await audit.getModernChain()).length);
        expect(a.linear).toBe(true);
        expect({ round, seqBreaks: a.seqBreaks, inversions: a.inversions }).toEqual({ round, seqBreaks: 0, inversions: 0 });

        // positional walk of the mirror in SEQ order — exactly what failed
        const walk = audit.verifyAuditChainDetailed(await mods.pgAuditBackend.loadChainFromPg(), 'GENESIS');
        expect(walk.valid).toBe(true);
        expect(walk.entriesVerified).toBe(PER_ROUND * round);

        const c = new Client(asTest(DB_A)); await c.connect();
        try {
          const q = await c.query('SELECT count(*)::int AS n FROM persistence_recovery_queue');
          expect(q.rows[0].n).toBe(0);
        } finally { await c.end(); }
        expect(audit.mirrorWriterDepth()).toBe(0);
      });
    }
  });

  describe('B — fixture with the audit\'s historical inversions (7 swapped seq pairs)', () => {
    const SWAPS = 7;
    let beforeSet;

    beforeAll(async () => {
      // copy the real, valid chain from DB_A into DB_B with 7 adjacent seq pairs swapped
      const src = new Client(asTest(DB_A)); await src.connect();
      const dst = new Client(asTest(DB_B)); await dst.connect();
      try {
        const rows = (await src.query('SELECT * FROM audit_chain ORDER BY seq ASC')).rows;
        const seqs = rows.map((r) => Number(r.seq));
        const step = Math.floor(rows.length / (SWAPS + 1));
        for (let k = 1; k <= SWAPS; k++) { const i = k * step; [seqs[i], seqs[i + 1]] = [seqs[i + 1], seqs[i]]; }
        const cols = Object.keys(rows[0]);
        for (let i = 0; i < rows.length; i++) {
          const vals = cols.map((c) => (c === 'seq' ? seqs[i] : (rows[i][c] !== null && typeof rows[i][c] === 'object' && !(rows[i][c] instanceof Date) ? JSON.stringify(rows[i][c]) : rows[i][c])));
          await dst.query(`INSERT INTO audit_chain (${cols.join(',')}) VALUES (${cols.map((_, j) => `$${j + 1}`).join(',')})`, vals);
        }
        // explicit seq values do not advance the BIGSERIAL sequence; a real
        // mirror's sequence is always past max(seq), so put the copy in that state
        await dst.query("SELECT setval(pg_get_serial_sequence('audit_chain', 'seq'), (SELECT max(seq) FROM audit_chain))");
        beforeSet = new Set(rows.map((r) => `${r.hash}|${r.prev_hash}|${r.canonical}`));
      } finally { await src.end(); await dst.end(); }
      await mods.pgPool.shutdown().catch(() => {});
      mods = bindModules(DB_B);
    });

    test('the fixture is real: SWAPS inversions and a positional (seq-order) walk breaks', async () => {
      const rows = await seqRows(DB_B);
      const a = mods.rebuild._analyse(rows);
      expect(a.linear).toBe(true);
      expect(a.inversions).toBe(SWAPS);
      expect(a.seqBreaks).toBeGreaterThan(0);
      // FULL entries in seq order (the verifier's own read shape) — a partial row
      // would fail the hash recomputation for the wrong reason.
      const seqOrdered = await mods.pgAuditBackend.fetchChainBatch(0, 100000);
      expect(seqOrdered.map((r) => Number(r.seq))).toEqual(rows.map((r) => r.seq));
      const positional = mods.audit.verifyAuditChainDetailed(seqOrdered, 'GENESIS');
      expect(positional.valid).toBe(false);
      expect(positional.reason).toMatch(/PREV_HASH|MISMATCH|BROKEN/i);
      // and the SAME rows, in link order, are a valid chain — it is only the order
      expect(mods.audit.verifyAuditChainDetailed(await mods.pgAuditBackend.loadChainFromPg(), 'GENESIS').valid).toBe(true);
    });

    test('loadChainFromPg follows hash links: the whole chain verifies', async () => {
      const rows = await mods.pgAuditBackend.loadChainFromPg();
      const walk = mods.audit.verifyAuditChainDetailed(rows, 'GENESIS');
      expect(walk.valid).toBe(true);
      expect(walk.entriesVerified).toBe(PER_ROUND * ROUNDS);
    });

    test('distributed-mode verifier (FULL, batched): no violation, inversions reported as WARN, no watermark persisted', async () => {
      const emitted = [];
      const v = mods.verifier.createChainVerifier({
        config: { batchSize: 97 },
        _auditLog: { ...mods.audit, ORDERING_MODE: 'distributed' },
        _consentStore: { verifyConsentAuditIntegrity: async () => ({ mismatches: [] }) },
        _emit: (sev, type, fields) => emitted.push({ sev, type, fields }),
      });
      const r = await v.verify({ mode: 'FULL', trigger: 'TEST' });
      expect(r.success).not.toBe(false);
      const critical = emitted.filter((e) => e.sev === 'CRITICAL');
      expect(critical).toEqual([]);
      const inv = emitted.find((e) => e.type === 'AUDIT_CHAIN_SEQ_INVERSIONS_PRESENT');
      expect(inv && inv.fields.inversions).toBe(SWAPS);
    });

    test('rebuild --check: not ready; --apply: re-sequenced, every hash/link/canonical unchanged, ready, positional walk valid', async () => {
      const c = new Client(asTest(DB_B)); await c.connect();
      try {
        const check = await mods.rebuild.rebuild(c, { apply: false });
        expect(check).toMatchObject({ linearChainFromGenesis: true, inversions: SWAPS, readyForDistributed: false, applied: false });
        const applied = await mods.rebuild.rebuild(c, { apply: true });
        expect(applied.applied).toBe(true);
        expect(applied.rowsResequenced).toBe(SWAPS * 2);
        expect(applied.after).toMatchObject({ inversions: 0, seqBreaks: 0 });
        expect(applied.readyForDistributed).toBe(true);
      } finally { await c.end(); }
      const rows = await seqRows(DB_B);
      expect(new Set(rows.map((r) => `${r.hash}|${r.prevHash}|${r.canonical}`))).toEqual(beforeSet);
      expect(mods.audit.verifyAuditChainDetailed(await mods.pgAuditBackend.fetchChainBatch(0, 100000), 'GENESIS').valid).toBe(true);
    });

    test('after the rebuild the deployment can switch to distributed: hydrate, append 25 concurrently, chain valid in seq order', async () => {
      await mods.pgPool.shutdown().catch(() => {});
      process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
      jest.resetModules();
      const pgPool = require('../../src/infra/postgres/pool');
      pgPool.initialize();
      const audit = require('../../src/core/audit/audit-log');
      const pgAuditBackend = require('../../src/infra/postgres/pg-audit-backend');
      try {
        expect(audit.ORDERING_MODE).toBe('distributed');
        await audit.hydrateFromPgIfDistributed();
        await Promise.all(Array.from({ length: 25 }, () => audit.append(params())));
        const seqOrdered = await pgAuditBackend.fetchChainBatch(0, 100000);
        expect(seqOrdered.length).toBe(PER_ROUND * ROUNDS + 25);
        const walk = audit.verifyAuditChainDetailed(seqOrdered, 'GENESIS');
        expect(walk.valid).toBe(true);
        const a = mods.rebuild._analyse((await seqRows(DB_B)));
        expect({ seqBreaks: a.seqBreaks, inversions: a.inversions }).toEqual({ seqBreaks: 0, inversions: 0 });
      } finally {
        await pgPool.shutdown().catch(() => {});
        delete process.env.QODIQA_AUDIT_ORDERING_MODE;
        mods = bindModules(DB_B);
      }
    });

    test('after the rebuild the verifier emits no inversion warning', async () => {
      const emitted = [];
      const v = mods.verifier.createChainVerifier({
        config: { batchSize: 97 },
        _auditLog: { ...mods.audit, ORDERING_MODE: 'distributed' },
        _consentStore: { verifyConsentAuditIntegrity: async () => ({ mismatches: [] }) },
        _emit: (sev, type, fields) => emitted.push({ sev, type, fields }),
      });
      await v.verify({ mode: 'FULL', trigger: 'TEST' });
      expect(emitted.filter((e) => e.sev === 'CRITICAL')).toEqual([]);
      expect(emitted.find((e) => e.type === 'AUDIT_CHAIN_SEQ_INVERSIONS_PRESENT')).toBeUndefined();
    });
  });
});
