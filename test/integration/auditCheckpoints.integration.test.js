'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * checkpoints on real PostgreSQL (disposable DB).
 *
 * A — startup mirror check (mirrorConsistencyCheck): first run does the full
 *     check and records a checkpoint; the next run verifies from it
 *     ("checkpoint" mode). Tampering is still fatal: a row deleted from the
 *     PREFIX (caught by the server-side count) and a modified SUFFIX row both
 *     make the fast path fall back to the full check, which exits.
 * B — transparency proofs from Merkle block checkpoints (block size 16):
 *     proofs for entries across the log verify against a correct root, blocks
 *     are stored once and reused.
 *
 * DB qodiqa_w3ckpt_<pid>_<hex>, name appended to %TEMP%/qodiqa-w3-ledger.jsonl
 * BEFORE creation, dropped and verified gone in afterAll.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

process.env.QODIQA_TRANSPARENCY_MERKLE_BLOCK_SIZE = '16';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Pool, Client } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;
const DB = `qodiqa_w3ckpt_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const LEDGER = path.join(os.tmpdir(), 'qodiqa-w3-ledger.jsonl');
const APP_USER = process.env.QODIQA_PG_USER;
const APP_PASSWORD = process.env.QODIQA_PG_PASSWORD;
const asTest = (database) => ({
  host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
  database, user: process.env.QODIQA_PG_TEST_USER, password: process.env.QODIQA_PG_TEST_PASSWORD, ssl: false,
});
const ledger = (event) => fs.appendFileSync(LEDGER, JSON.stringify({ at: new Date().toISOString(), db: DB, event, by: 'test/integration/auditCheckpoints.integration.test.js' }) + '\n');

jest.setTimeout(180_000);

describeOrSkip('audit and transparency checkpoints (real PostgreSQL)', () => {
  let created = false; const saved = {}; let tmpDir;
  let pgPool, pgAuditBackend, audit, mirrorCheck, proofLookup, entryBuilder, merkle;
  let entries; let leafHashes;
  const N = 2000; const T = 300;

  beforeAll(async () => {
    if (!/^[a-z][a-z0-9_]{0,62}$/.test(DB)) throw new Error('unsafe db name');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-w3ckpt-'));
    ledger('planned');
    const m = new Client(asTest('postgres')); await m.connect();
    try { await m.query(`CREATE DATABASE "${DB}"`); } finally { await m.end(); }
    created = true; ledger('created');
    const mp = new Pool(asTest(DB));
    try { jest.resetModules(); await require('../../src/infra/postgres/migrate').runMigrations({ pool: mp }); } finally { await mp.end(); }

    for (const k of ['QODIQA_PG_ENABLED', 'QODIQA_PG_DATABASE', 'QODIQA_PG_USER', 'QODIQA_PG_PASSWORD', 'QODIQA_AUDIT_LOG', 'QODIQA_PRQ_JOURNAL_DIR']) saved[k] = process.env[k];
    Object.assign(process.env, { QODIQA_PG_ENABLED: 'true', QODIQA_PG_DATABASE: DB, QODIQA_PG_USER: APP_USER,
      QODIQA_AUDIT_LOG: path.join(tmpDir, 'audit.log'), QODIQA_PRQ_JOURNAL_DIR: path.join(tmpDir, 'prq') });
    process.env['QODIQA_PG_PASSWORD'] = APP_PASSWORD;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool'); pgPool.initialize();
    pgAuditBackend = require('../../src/infra/postgres/pg-audit-backend');
    audit = require('../../src/core/audit/audit-log');
    mirrorCheck = require('../../src/core/audit/mirrorConsistencyCheck');
    proofLookup = require('../../src/core/transparency/proofLookup');
    entryBuilder = require('../../src/core/audit/entryBuilder');
    merkle = require('../../src/core/transparency/merkle');

    // seed N real chained audit entries through the REAL guarded insert, and T transparency entries
    entries = []; let prev = 'GENESIS';
    for (let i = 0; i < N; i++) {
      const e = entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: `ck-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
        signature: 's'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true }), prev);
      entries.push(e); prev = e.hash;
    }
    for (const e of entries) await pgPool.withTransaction((tx) => pgAuditBackend.insertMirrorRow(tx, e), { isolationLevel: 'READ COMMITTED' });
    const seed = new Client(asTest(DB)); await seed.connect();
    try {
      leafHashes = [];
      for (let i = 0; i < T; i++) {
        const eh = crypto.createHash('sha256').update(`tle-${i}`).digest('hex'); leafHashes.push(eh);
        await seed.query("INSERT INTO transparency_log_entries (entry_type, payload_hash, entry_hash, signer_key_id, signature) VALUES ('SYSTEM', $1, $2, 'k', 'SIG')", ['b'.repeat(64), eh]);
      }
      await seed.query("INSERT INTO transparency_roots (seq_from, seq_to, entry_count, root_hash, signature, signer_key_id) VALUES (1, $1, $2, $3, 'SIG', 'k')", [T, T, merkle.merkleRoot(leafHashes)]);
    } finally { await seed.end(); }
  });

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    if (created) {
      const m = new Client(asTest('postgres')); await m.connect();
      try {
        try { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); } catch { await m.query(`DROP DATABASE IF EXISTS "${DB}" WITH (FORCE)`); }
        ledger((await m.query('SELECT 1 FROM pg_database WHERE datname = $1', [DB])).rowCount === 0 ? 'dropped' : 'DROP-FAILED');
      } finally { await m.end(); }
    }
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const fileLog = () => ({
    getChainStats: () => ({ chainLength: entries.length, modernLength: entries.length, headHash: entries[0].hash, tailHash: entries[entries.length - 1].hash }),
    getModernChain: async () => entries,
    verifyAuditChainDetailed: (list, start) => audit.verifyAuditChainDetailed(list, start),
    getModernEntryAt: async (i) => entries[i] ?? null,
    getModernChainSlice: async (from) => entries.slice(from),
  });
  async function check() {
    const events = []; const exit = jest.fn();
    const ok = await mirrorCheck.verifyMirrorConsistency({ _auditLog: fileLog(), _pgPool: pgPool, _pgAuditBackend: pgAuditBackend,
      _exit: exit, _emit: (s, e, f) => events.push({ s, e, f }) });
    return { ok, exit, events, verified: events.find((x) => x.e === 'AUDIT_MIRROR_CONSISTENCY_VERIFIED'), fallback: events.find((x) => x.e === 'AUDIT_MIRROR_CHECKPOINT_FALLBACK') };
  }

  describe('A — startup mirror check from a checkpoint', () => {
    test('first run: full check (no checkpoint yet), records a checkpoint at the tail', async () => {
      const r = await check();
      expect(r.ok).toBe(true);
      expect(r.fallback.f.reason).toBe('NO_CHECKPOINT');
      expect(r.verified.f.mode).toBeUndefined();
      const cp = await pgAuditBackend.getLatestAuditCheckpoint();
      expect(cp).toMatchObject({ chainLength: N, hash: entries[N - 1].hash });
    });

    test('next run: verified from the checkpoint', async () => {
      const r = await check();
      expect(r.ok).toBe(true);
      expect(r.verified.f).toMatchObject({ mode: 'checkpoint', checkpointLength: N, suffixChecked: 0 });
    });

    test('with new entries after the checkpoint, only the suffix is checked, and a new checkpoint is recorded', async () => {
      let prev = entries[entries.length - 1].hash;
      for (let i = 0; i < 25; i++) {
        const e = entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: `ck-more-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
          signature: 's'.repeat(64), requestHash: 'r'.repeat(64), policyHash: 'p'.repeat(64), verificationResult: true }), prev);
        await pgPool.withTransaction((tx) => pgAuditBackend.insertMirrorRow(tx, e), { isolationLevel: 'READ COMMITTED' });
        entries.push(e); prev = e.hash;
      }
      const r = await check();
      expect(r.verified.f).toMatchObject({ mode: 'checkpoint', checkpointLength: N, suffixChecked: 25 });
      expect((await pgAuditBackend.getLatestAuditCheckpoint()).chainLength).toBe(N + 25);
    });

    test('a SUFFIX row modified in PG: fast path falls back, full check is fatal', async () => {
      const c = new Client(asTest(DB)); await c.connect();
      const target = entries[entries.length - 3];
      try {
        // make the latest checkpoint older than the suffix first (so the row is in the suffix)
        await c.query('DELETE FROM audit_chain_checkpoints WHERE chain_length > $1', [N]);
        await c.query("UPDATE audit_chain SET canonical = canonical || ' ' WHERE hash = $1", [target.hash]);
        const r = await check();
        expect(r.fallback).toBeDefined();
        expect(r.ok).toBe(false);
        expect(r.exit).toHaveBeenCalledWith(1);
      } finally {
        await c.query("UPDATE audit_chain SET canonical = rtrim(canonical) WHERE hash = $1", [target.hash]);
        await c.end();
      }
    });

    test('a PREFIX row deleted in PG: the count no longer matches, fast path falls back, full check is fatal', async () => {
      const c = new Client(asTest(DB)); await c.connect();
      const victim = entries[10];
      const row = (await c.query('SELECT * FROM audit_chain WHERE hash = $1', [victim.hash])).rows[0];
      try {
        await c.query('DELETE FROM audit_chain WHERE hash = $1', [victim.hash]);
        const r = await check();
        expect(r.fallback.f.reason).toBe('COUNT_MISMATCH');
        expect(r.ok).toBe(false);
        expect(r.exit).toHaveBeenCalledWith(1);
      } finally {
        const cols = Object.keys(row);
        const vals = cols.map((k) => (row[k] !== null && typeof row[k] === 'object' && !(row[k] instanceof Date) ? JSON.stringify(row[k]) : row[k]));
        await c.query(`INSERT INTO audit_chain (${cols.join(',')}) VALUES (${cols.map((_, i) => `$${i + 1}`).join(',')})`, vals);
        await c.end();
      }
    });
  });

  describe('B — transparency proofs from Merkle block checkpoints (block size 16)', () => {
    test('proofs across the log verify against the correct root; blocks stored once, then reused', async () => {
      // the app role can no longer read full transparency rows;
      // take the entry exactly as the public /proof route does — the minimized
      // lookup (logStore.getByTransparencyId, app role) — keyed by the
      // transparency_id read as qodiqa_test (ground truth).
      const logStore = require('../../src/core/transparency/logStore');
      const gt = new Client(asTest(DB)); await gt.connect();
      const tids = {};
      try {
        for (const r of (await gt.query('SELECT id, transparency_id FROM transparency_log_entries')).rows) tids[Number(r.id)] = r.transparency_id;
      } finally { await gt.end(); }
      for (const id of [1, 2, 16, 17, 150, 287, 288, 299, T]) {
        const entry = await logStore.getByTransparencyId(tids[id]);
        expect(entry).not.toHaveProperty('tenant_id');
        expect(entry).not.toHaveProperty('payload');
        const r = await proofLookup.getInclusionProofForEntry(entry);
        expect({ id, valid: r.proofVerification.valid }).toEqual({ id, valid: true });
        expect(r.proof.proof.treeSize).toBe(T);
        expect(r.proof.proof.merklePath).toEqual(merkle.inclusionPath(leafHashes, id - 1));
      }
      const c = new Client(asTest(DB)); await c.connect();
      try {
        const blocks = await c.query('SELECT count(*)::int AS n FROM transparency_merkle_checkpoints WHERE block_size = 16');
        expect(blocks.rows[0].n).toBe(Math.floor(T / 16));
      } finally { await c.end(); }
    });
  });
});
