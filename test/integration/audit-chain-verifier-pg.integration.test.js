'use strict';

// DB-05 (migration 076): this suite mutates audit_chain on its own disposable database (tamper simulation /
// fixture reset), which now requires the declared maintenance intent for its connections.
const _auditFixture = require('../helpers/auditMaintenance');
beforeAll(_auditFixture.enter);
afterAll(_auditFixture.leave);

/**
 * CHAIN-2 — Live Audit Chain Integrity Verifier: PostgreSQL-mode integration tests
 *
 * Requires a real, reachable local PostgreSQL (QODIQA_PG_ENABLED=true) with
 * CREATEDB privilege on the connecting role — skipped entirely otherwise,
 * same convention as test/integration/audit-chain-distributed.integration.test.js and
 * src/infra/postgres/__tests__/rls.test.js's RLS-91..100.
 *
 * Unlike those two suites (which reuse the already-configured QODIQA_PG_DATABASE),
 * this file creates its own freshly-named, disposable database for the
 * duration of the run — full-table structural checks (duplicate-seq,
 * genesis-count, orphan-link detection) need a table with nothing in it but
 * this test's own deterministic fixtures, or assertions on exact counts
 * would be flaky against whatever else happens to be in a shared dev
 * database. Follows the exact check/create pattern already established by
 * scripts/lib/devConsent.js's ensureDatabaseExists() (maintenance-database
 * connection, SAFE_IDENTIFIER-validated name, CREATE DATABASE). The
 * database this test creates is dropped again in afterAll — safe because
 * it is a brand-new, uniquely-named, disposable database this same test
 * run created a few seconds earlier, not any pre-existing developer data.
 *
 * PGV-01  FULL scan of a freshly seeded, valid chain: no violations,
 *         entriesChecked matches seed count, watermark persisted
 * PGV-02  INCREMENTAL scan after a prior FULL only re-walks the new tail
 * PGV-03  SEQUENCE_GAP (MEDIUM, not AUDIT_CHAIN_CORRUPTED) from a genuine
 *         rolled-back BIGSERIAL nextval() (ON CONFLICT DO NOTHING burning
 *         a seq value) — the exact mechanism pg-audit-backend.js's
 *         persistEntry() uses in production
 * PGV-04  DUPLICATE_SEQUENCE (CRITICAL) from a directly seeded duplicate
 *         seq value (bypassing the app layer — proves the schema itself
 *         allows it, per migration 001's seq column having no UNIQUE
 *         constraint, and that the verifier still catches it)
 * PGV-05  MULTIPLE_GENESIS (CRITICAL) from a second row with prev_hash='GENESIS'
 * PGV-06  ORPHAN_RECORD (CRITICAL) via validateChainLinks() — a row whose
 *         prev_hash matches no existing hash
 * PGV-06B CHAIN-5: the SAME validateChainLinks() orphan check also fires from
 *         verifyPgDivergence() — the single-node + PG-dual-write path, which
 *         previously never ran it at all (only the distributed-mode FULL
 *         scan above did)
 * PGV-06C Layer 3: the verifier RUNNER's public verifyPgDivergenceNow()
 *         detects the same orphan on demand (POST /chain/verifier/verify
 *         {mode:"PG_DIVERGENCE"}), independent of the scheduled 15-minute
 *         tick and without the background scheduler running at all
 * PGV-07  Advisory transaction lock: a second holder cannot acquire the
 *         same lock key while the first transaction is open
 * PGV-08  Batch-boundary pagination: seeding more rows than one batch
 *         correctly threads prevHash continuity across the boundary
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_acv_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

// follow-up: PGV-09/PGV-10's own appPool below used to authenticate
// with `_originalPasswordEnv` (the pre-elevation QODIQA_PG_PASSWORD) on the
// documented assumption that it IS qodiqa_app's own real password — true
// only in an environment where the ambient QODIQA_PG_USER/PASSWORD are
// ALREADY qodiqa_app's own credentials. None of test.yml's actual jobs set
// them that way (QODIQA_PG_USER is the container's own superuser, 'qodiqa',
// throughout), so on a genuinely fresh container this always authenticated
// with the WRONG password. Same fallback idiom test/retentionRoleSeparation.
// integration.test.js already uses correctly for the identical problem:
// migration 002's own CREATE ROLE qodiqa_app LOGIN PASSWORD statement is a
// literal, not env-templated, so 'REPLACE_WITH_VAULT_SECRET_APP' is the
// correct password on a fresh container whenever the ambient user isn't
// already qodiqa_app itself.
const APP_PASSWORD = process.env.QODIQA_PG_USER === 'qodiqa_app'
  ? process.env.QODIQA_PG_PASSWORD
  : 'REPLACE_WITH_VAULT_SECRET_APP';

let _originalDatabaseEnv;
let _originalUserEnv;
let _originalPasswordEnv;
let _maintenancePool;
let _fixturePool = null; // DB-05
let pgPool, pgAuditBackend, verifierState, ChainVerifierMod, VerifierRunnerMod, entryBuilder, realAuditLog;

// every mirror INSERT is parent-guarded
// (pg-audit-backend.js insertMirrorRow), so persistEntry() correctly refuses a
// row whose parent is not in audit_chain (it is queued, never written as an
// orphan). The fixtures below that must model ALREADY-PRESENT earlier or
// tampered state (an orphan row; standalone rows for an RLS check) write it the
// earlier way: the real insertMirrorRow() INSERT with its parent guard answered
// 'ok', i.e. unguarded. Normal chained seeds keep using the real persistEntry().
async function legacyInsert(entry) {
  // the parent/self guard now runs as qodiqa_system; a simulated
  // earlier (unguarded) writer injects its answer via _guardQuery instead of a fake tx.
  await pgPool.withTransaction((tx) => pgAuditBackend.insertMirrorRow(tx, entry, {
    _guardQuery: async () => ({ rows: [{ parent_ok: true, self_exists: false }] }),
  }), { isolationLevel: 'READ COMMITTED' });
}

async function _seedEntry(prevHash, artifactId) {
  const normalized = entryBuilder.normalizeFields({
    artifactId,
    inputHash:           'a'.repeat(64),
    decision:            'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:           `sig-${artifactId}`,
    requestHash:          'b'.repeat(64),
    policyHash:           'c'.repeat(64),
    verificationResult:  true,
  });
  const entry = entryBuilder.buildEntry(normalized, prevHash);
  await pgAuditBackend.persistEntry(entry);
  return entry;
}

// A fake audit-log module exposing only what ChainVerifier's PG-authoritative
// path needs (ORDERING_MODE + the pure, ordering-mode-agnostic hash walker) —
// reusing the real verifyAuditChainDetailed() rather than reimplementing it,
// without needing to boot audit-log.js itself in distributed mode (which
// would additionally require multiInstanceGuard's preconditions and a real
// server.js startup sequence).
function _distributedAuditLogFacade() {
  return {
    ORDERING_MODE: 'distributed',
    verifyAuditChainDetailed: realAuditLog.verifyAuditChainDetailed,
  };
}

describeOrSkip('CHAIN-2 — Live Audit Chain Integrity Verifier (PG mode, integration)', () => {
  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }

    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) — falls back to the pre-existing chain so CI's ephemeral
    // postgres:17-alpine superuser container (QODIQA_PG_USER=qodiqa there)
    // is unaffected.
    _maintenancePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: process.env.QODIQA_PG_MAINTENANCE_DATABASE || 'postgres',
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    const existing = await _maintenancePool.query('SELECT 1 FROM pg_database WHERE datname = $1', [TEST_DB_NAME]);
    if (existing.rows.length === 0) {
      // Safe: TEST_DB_NAME is generator-controlled (timestamp + random hex,
      // validated against SAFE_IDENTIFIER above), never derived from
      // external/user input.
      await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);
    }

    // DB-05 (migration 076): the product pool's own startup options override PGOPTIONS, so this suite's audit_chain
    // resets and tamper simulations go through this fixture pool (same test identity, same disposable database), which
    // carries the declared fixture intent from test/helpers/auditMaintenance.js.
    _fixturePool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD || undefined,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
      max:      2,
    });

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    // pgPool below runs runMigrations() against this fresh database, which
    // includes migration 002 (CREATE ROLE) and 018 (ALTER ROLE ... BYPASSRLS)
    // — both require the connecting role to hold CREATEROLE+BYPASSRLS itself.
    // Elevate for the duration of this suite; restored in afterAll.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    jest.resetModules();
    pgPool         = require('../../src/infra/postgres/pool');
    pgAuditBackend = require('../../src/infra/postgres/pg-audit-backend');
    verifierState  = require('../../src/core/audit/verifier/verifierState');
    ChainVerifierMod = require('../../src/core/audit/verifier/ChainVerifier');
    VerifierRunnerMod = require('../../src/core/audit/verifier');
    entryBuilder   = require('../../src/core/audit/entryBuilder');
    realAuditLog   = require('../../src/core/audit/audit-log');

    pgPool.initialize();
    await pgPool.runMigrations();
  }, 60_000);

  afterAll(async () => { if (_fixturePool) await _fixturePool.end().catch(() => {}); });
  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // Best-effort cleanup only — a leftover uniquely-named disposable
        // test DB is a minor annoyance, never a reason to fail the suite.
        // eslint-disable-next-line no-console
        console.warn(`[audit-chain-verifier-pg.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  function freshVerifier(overrides = {}) {
    const metrics = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });
    return ChainVerifierMod.createChainVerifier({
      config: { batchSize: 3 },
      _auditLog:      _distributedAuditLogFacade(),
      _pgPool:        pgPool,
      _pgBackend:     pgAuditBackend,
      _verifierState: verifierState,
      _metrics:       metrics,
      _emit:          () => {},
      ...overrides,
    });
  }

  test('PGV-01 FULL scan of a freshly seeded valid chain finds no violations', async () => {
    let prevHash = 'GENESIS';
    for (let i = 0; i < 5; i++) {
      const entry = await _seedEntry(prevHash, `pgv01-${i}`);
      prevHash = entry.hash;
    }

    const verifier = freshVerifier();
    const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    expect(result.success).toBe(true);
    expect(result.violations).toHaveLength(0);
    expect(result.entriesChecked).toBe(5);

    const state = await verifierState.loadPgState();
    expect(Number(state.last_verified_seq)).toBe(5);
  });

  test('PGV-02 INCREMENTAL scan after a FULL scan only re-walks the new tail', async () => {
    const stateBefore = await verifierState.loadPgState();
    const seqBefore = Number(stateBefore.last_verified_seq);

    let prevHash = stateBefore.last_verified_hash;
    for (let i = 0; i < 3; i++) {
      const entry = await _seedEntry(prevHash, `pgv02-${i}`);
      prevHash = entry.hash;
    }

    const verifier = freshVerifier();
    const result = await verifier.verify({ mode: 'INCREMENTAL', trigger: 'MANUAL' });

    expect(result.violations).toHaveLength(0);
    expect(result.entriesChecked).toBe(3); // only the 3 new rows, not seqBefore + 3

    const stateAfter = await verifierState.loadPgState();
    expect(Number(stateAfter.last_verified_seq)).toBe(seqBefore + 3);
  });

  test('PGV-03 a rolled-back BIGSERIAL insert produces a SEQUENCE_GAP, not AUDIT_CHAIN_CORRUPTED', async () => {
    const stateBefore = await verifierState.loadPgState();
    let prevHash = stateBefore.last_verified_hash;

    const good1 = await _seedEntry(prevHash, 'pgv03-good-1');
    prevHash = good1.hash;

    // Directly burn a sequence value via nextval(), the same non-transactional
    // primitive a rolled-back INSERT triggers in production (e.g. a retried
    // ON CONFLICT/constraint-violation elsewhere in the same statement) —
    // see diagnostics.js's SEQUENCE_GAP comment. Calling nextval() directly
    // is more deterministic for this test than trying to engineer a real
    // rolled-back INSERT, and proves the same downstream fact: a gap in
    // `seq` values alone, with no missing/broken row, must not be treated as
    // tampering.
    const seqNameRes = await pgPool.query(`SELECT pg_get_serial_sequence('audit_chain', 'seq') AS name`);
    await pgPool.query(`SELECT nextval($1)`, [seqNameRes.rows[0].name]);

    const good2 = await _seedEntry(prevHash, 'pgv03-good-2');

    const verifier = freshVerifier();
    const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    const gapViolations = result.violations.filter(v => v.reason === 'SEQUENCE_GAP');
    expect(gapViolations.length).toBeGreaterThanOrEqual(1);
    expect(gapViolations[0].severity).toBe('MEDIUM');
    // The chain itself is still perfectly valid — a sequence gap alone must
    // never also produce a CRITICAL hash/prevHash finding.
    const criticalReasons = result.violations.filter(v => v.severity === 'CRITICAL').map(v => v.reason);
    expect(criticalReasons).not.toContain('HASH_MISMATCH');
    expect(criticalReasons).not.toContain('PREV_HASH_MISMATCH');
  });

  // PGV-04 and PGV-05 both fabricate a row that shares a `prev_hash` value
  // with an existing row (a duplicate-seq row that reuses the tail's own
  // prevHash; a second GENESIS-linked row). Migration 026's
  // idx_audit_chain_prev_hash_unique index — added specifically as a
  // defense-in-depth fork guard — refuses exactly this class of write in a
  // normally migrated deployment (confirmed directly: attempting either
  // insert with the index in place raises 23505 on that index, not the
  // `hash` primary key ON CONFLICT clause targets). That is a genuinely
  // good thing, and it means DUPLICATE_SEQUENCE/MULTIPLE_GENESIS, as found
  // by detectDuplicateSequences()/countGenesisRows(), are unreachable via
  // the schema alone once migration 026 is applied — the two checks remain
  // valuable defense-in-depth for states the constraint cannot rule out
  // (a table that predates migration 026, or where the index has been
  // manually dropped/bypassed by a superuser) rather than for states normal
  // application writes could ever produce. Both tests below temporarily
  // drop and recreate that index to simulate exactly that "constraint
  // predates or was bypassed" scenario — not a state reachable through
  // pg-audit-backend.js's own persistEntry() path.
  test('PGV-04 a genuine duplicate seq is DUPLICATE_SEQUENCE (CRITICAL)', async () => {
    const row = await pgPool.query('SELECT seq, hash FROM audit_chain ORDER BY seq DESC LIMIT 1');
    const existingSeq = Number(row.rows[0].seq);
    const fakePrevHash = crypto.randomBytes(32).toString('hex'); // never claimed by any other row

    const fakeEntry = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv04-duplicate-seq',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
      }),
      fakePrevHash
    );

    await pgPool.query('DROP INDEX IF EXISTS idx_audit_chain_prev_hash_unique');
    try {
      await pgPool.query(`
        INSERT INTO audit_chain (
          seq, hash, prev_hash, canonical, artifact_id, decision, recorded_at, high_res_time,
          input_hash, signature, request_hash, policy_hash, verification_result, nonce, tenant_id,
          execution_context, public_key_id, schema_version
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NULL, NULL, NULL, $14)
      `, [
        existingSeq, fakeEntry.hash, fakeEntry.prevHash, fakeEntry.canonical, fakeEntry.artifactId,
        fakeEntry.decision, new Date(fakeEntry.timestamp), fakeEntry.highResTime, fakeEntry.inputHash,
        fakeEntry.signature, fakeEntry.requestHash, fakeEntry.policyHash, fakeEntry.verificationResult,
        fakeEntry.schemaVersion,
      ]);
    } finally {
      await pgPool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_prev_hash_unique ON audit_chain (prev_hash)');
    }

    const dupes = await pgAuditBackend.detectDuplicateSequences();
    expect(dupes.some(d => d.seq === existingSeq)).toBe(true);

    const verifier = freshVerifier();
    // Start fresh from seq 0 for this assertion so the FULL-only duplicate
    // check definitely runs regardless of the persisted watermark.
    await verifierState.savePgState({ lastVerifiedSeq: 0, lastVerifiedHash: null });
    const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    const dupViolation = result.violations.find(v => v.reason === 'DUPLICATE_SEQUENCE');
    expect(dupViolation).toBeTruthy();
    expect(dupViolation.severity).toBe('CRITICAL');

    // Clean up the injected row so later tests' seq/genesis assumptions hold.
    await _fixturePool.query('DELETE FROM audit_chain WHERE artifact_id = $1', ['pgv04-duplicate-seq']);
  });

  test('PGV-05 a second GENESIS-linked row is MULTIPLE_GENESIS (CRITICAL)', async () => {
    const secondGenesis = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv05-second-genesis',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
      }),
      'GENESIS'
    );

    // Unlike PGV-04 (whose fabricated row uses a never-colliding random
    // prevHash, so the index can be safely recreated immediately after
    // inserting it), the duplicate GENESIS-linked row here must still be
    // present — and still colliding — when the index would be recreated, so
    // recreation is deferred until after this test has removed the row again.
    await pgPool.query('DROP INDEX IF EXISTS idx_audit_chain_prev_hash_unique');
    try {
      await pgAuditBackend.persistEntry(secondGenesis);

      const genesisCount = await pgAuditBackend.countGenesisRows();
      expect(genesisCount).toBeGreaterThanOrEqual(2);

      const verifier = freshVerifier();
      await verifierState.savePgState({ lastVerifiedSeq: 0, lastVerifiedHash: null });
      const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

      const genesisViolation = result.violations.find(v => v.reason === 'MULTIPLE_GENESIS');
      expect(genesisViolation).toBeTruthy();
      expect(genesisViolation.severity).toBe('CRITICAL');
    } finally {
      await _fixturePool.query('DELETE FROM audit_chain WHERE artifact_id = $1', ['pgv05-second-genesis']);
      await pgPool.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_prev_hash_unique ON audit_chain (prev_hash)');
    }
  });

  test('PGV-06 a row whose prev_hash matches nothing is an ORPHAN_RECORD via validateChainLinks', async () => {
    const orphan = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv06-orphan',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
      }),
      'f'.repeat(64) // a hash that does not exist anywhere in audit_chain
    );
    await legacyInsert(orphan);

    const linkCheck = await pgAuditBackend.validateChainLinks();
    expect(linkCheck.valid).toBe(false);
    expect(linkCheck.brokenLinks).toBeGreaterThanOrEqual(1);

    const verifier = freshVerifier();
    await verifierState.savePgState({ lastVerifiedSeq: 0, lastVerifiedHash: null });
    const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    const orphanViolation = result.violations.find(v => v.reason === 'ORPHAN_RECORD');
    expect(orphanViolation).toBeTruthy();
    expect(orphanViolation.severity).toBe('CRITICAL');

    await _fixturePool.query('DELETE FROM audit_chain WHERE artifact_id = $1', ['pgv06-orphan']);
  });

  test('PGV-06B CHAIN-5: verifyPgDivergence() (single-node + PG-dual-write path) also reports ORPHAN_RECORD', async () => {
    const orphan = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv06b-orphan',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
      }),
      'e'.repeat(64) // a hash that does not exist anywhere in audit_chain
    );
    await legacyInsert(orphan);

    // Stub out file-vs-PG cross-validation so this test isolates CHAIN-5's
    // orphan-link check from unrelated mirror-consistency noise against
    // whatever else PGV-01..06 already seeded into this shared test DB —
    // verifyPgDivergence() calls both checks, but only the orphan-link one
    // is under test here.
    const verifier = ChainVerifierMod.createChainVerifier({
      config:         { batchSize: 3 },
      _auditLog:      { ORDERING_MODE: 'single-node', getModernChain: () => [] },
      _pgPool:        pgPool,
      _pgBackend:     pgAuditBackend,
      _mirrorCheck:   { crossValidateRecords: () => ({ recordsChecked: 0, firstMismatch: null, lastCommonRecord: null }) },
      _verifierState: verifierState,
      _metrics:       new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) }),
      _emit:          () => {},
    });

    const result = await verifier.verifyPgDivergence('MANUAL');

    expect(result.success).toBe(true);
    const orphanViolation = result.violations.find(v => v.reason === 'ORPHAN_RECORD');
    expect(orphanViolation).toBeTruthy();
    expect(orphanViolation.severity).toBe('CRITICAL');
    expect(orphanViolation.brokenLinks).toBeGreaterThanOrEqual(1);

    await _fixturePool.query('DELETE FROM audit_chain WHERE artifact_id = $1', ['pgv06b-orphan']);
  });

  test('PGV-06C Layer 3: the runner\'s public verifyPgDivergenceNow() detects an orphan on demand, without waiting for the scheduled 15-minute tick', async () => {
    const orphan = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv06c-orphan',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
      }),
      'd'.repeat(64) // a hash that does not exist anywhere in audit_chain
    );
    await legacyInsert(orphan);

    // Exercises the RUNNER's public API (verifier/index.js), not
    // ChainVerifier.js's createChainVerifier() directly like PGV-06B above —
    // this is what the new POST /chain/verifier/verify {mode:"PG_DIVERGENCE"}
    // route actually calls. The background tickers are never started
    // (runner.start() is not called) — verifyPgDivergenceNow() must work
    // on-demand independent of whether the scheduled runner is running,
    // exactly the operator scenario (mid-incident, no restart) this fix
    // exists for.
    const runner = VerifierRunnerMod.createVerifierRunner({
      config:         { enabled: true, batchSize: 3 },
      _auditLog:      { ORDERING_MODE: 'single-node', getModernChain: () => [] },
      _pgPool:        pgPool,
      _pgBackend:     pgAuditBackend,
      _mirrorCheck:   { crossValidateRecords: () => ({ recordsChecked: 0, firstMismatch: null, lastCommonRecord: null }) },
      _verifierState: verifierState,
      _metrics:       new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) }),
      _emit:          () => {},
    });

    expect(runner.isRunning()).toBe(false); // never started — proves this works without the background scheduler

    const result = await runner.verifyPgDivergenceNow();

    expect(result.success).toBe(true);
    const orphanViolation = result.violations.find(v => v.reason === 'ORPHAN_RECORD');
    expect(orphanViolation).toBeTruthy();
    expect(orphanViolation.severity).toBe('CRITICAL');

    await _fixturePool.query('DELETE FROM audit_chain WHERE artifact_id = $1', ['pgv06c-orphan']);
  });

  test('PGV-07 the advisory transaction lock excludes a concurrent holder', async () => {
    const LOCK_KEY = 'qodiqa_audit_chain_verifier';

    const connOpts = {
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_USER || 'qodiqa_app',
      password: process.env.QODIQA_PG_PASSWORD || undefined,
    };
    // Two entirely separate Pools (not just two checked-out clients from one
    // pool) so each genuinely holds its own PostgreSQL backend connection —
    // an advisory transaction lock is connection-scoped, and reusing a
    // single pool could coincidentally hand both "clients" the same
    // underlying connection.
    const poolA = new Pool(connOpts);
    const poolB = new Pool(connOpts);

    try {
      const clientA = await poolA.connect();
      const clientB = await poolB.connect();
      try {
        await clientA.query('BEGIN');
        const acquiredA = await clientA.query('SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired', [LOCK_KEY]);
        expect(acquiredA.rows[0].acquired).toBe(true);

        await clientB.query('BEGIN');
        const acquiredB = await clientB.query('SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired', [LOCK_KEY]);
        expect(acquiredB.rows[0].acquired).toBe(false); // excluded while A holds it

        await clientA.query('COMMIT'); // releases A's lock

        const acquiredB2 = await clientB.query('SELECT pg_try_advisory_xact_lock(hashtext($1)::bigint) AS acquired', [LOCK_KEY]);
        expect(acquiredB2.rows[0].acquired).toBe(true); // now available
        await clientB.query('COMMIT');
      } finally {
        clientA.release();
        clientB.release();
      }
    } finally {
      await poolA.end().catch(() => {});
      await poolB.end().catch(() => {});
    }
  });

  test('PGV-08 batch-boundary pagination threads prevHash continuity correctly', async () => {
    // freshVerifier() uses batchSize: 3 — seed 7 rows (spans 3 batches:
    // 3 + 3 + 1) starting from a clean slate to make the assertion exact.
    await _fixturePool.query('DELETE FROM audit_chain');
    await verifierState.savePgState({ lastVerifiedSeq: null, lastVerifiedHash: null });
    // savePgState uses COALESCE, so NULLs above are no-ops; reset via raw SQL instead.
    await pgPool.query('UPDATE audit_chain_verifier_state SET last_verified_seq = NULL, last_verified_hash = NULL WHERE id = 1');

    let prevHash = 'GENESIS';
    for (let i = 0; i < 7; i++) {
      const entry = await _seedEntry(prevHash, `pgv08-${i}`);
      prevHash = entry.hash;
    }

    const verifier = freshVerifier();
    const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    expect(result.violations.filter(v => v.reason !== 'SEQUENCE_GAP')).toHaveLength(0);
    expect(result.entriesChecked).toBe(7);
  });

  // ── remediation (migration 048) ────────────────────────────────────────
  //
  // Every seed above (PGV-01..08) writes tenant_id: NULL rows — ac_tenant_select's
  // RLS policy (`tenant_id IS NULL OR tenant_id = qodiqa_current_tenant()`) always
  // makes NULL-tenant rows visible regardless of session context, so none of
  // PGV-01..08 could have caught's RLS-blind-spot even though several of
  // them exercise the exact functions (validateChainLinks, detectDuplicateSequences,
  // countGenesisRows, fetchChainBatch) migration 048 rewired. PGV-09/10 close
  // that coverage gap directly, with a real, non-NULL tenant_id.

  test('PGV-09 a tenant-scoped chain is correctly seen end-to-end by the distributed-mode FULL scan', async () => {
    await _fixturePool.query('DELETE FROM audit_chain');
    await pgPool.query('UPDATE audit_chain_verifier_state SET last_verified_seq = NULL, last_verified_hash = NULL WHERE id = 1');

    const TENANT = 'f26-pgv09-tenant';
    let prevHash = 'GENESIS';
    for (let i = 0; i < 4; i++) {
      const entry = entryBuilder.buildEntry(
        entryBuilder.normalizeFields({
          artifactId: `pgv09-${i}`,
          inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
          requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
          tenantId: TENANT,
        }),
        prevHash
      );
      await pgAuditBackend.persistEntry(entry);
      prevHash = entry.hash;
    }

    // Sanity: confirm the seeded rows really do carry a non-NULL tenant_id
    // (not silently dropped somewhere in the write path) — the whole point
    // of this test is that these rows are the kind ac_tenant_select would
    // hide from a plain, un-bypassed qodiqa_app read.
    const seeded = await pgPool.query('SELECT tenant_id FROM audit_chain WHERE artifact_id LIKE $1', ['pgv09-%']);
    expect(seeded.rows.every(r => r.tenant_id === TENANT)).toBe(true);

    // Pre-fix, this FULL scan (fetchChainBatch + detectDuplicateSequences +
    // countGenesisRows + validateChainLinks, all previously plain RLS-scoped
    // queries) would have seen zero rows and reported the chain as empty —
    // or, worse, reported a false ORPHAN_RECORD/false gap depending on what
    // else was concurrently visible in the shared test database.
    const verifier = freshVerifier();
    const result = await verifier.verify({ mode: 'FULL', trigger: 'MANUAL' });

    expect(result.violations).toHaveLength(0);
    expect(result.entriesChecked).toBe(4);

    // The assertions above run through this file's shared pgPool, which
    // this suite's own beforeAll elevates to QODIQA_PG_TEST_USER (superuser)
    // for the whole file so migrations can run — a superuser connection
    // bypasses RLS unconditionally, so by itself the above would pass
    // whether or not migration 048's fix is actually in effect (caught
    // live: this is the same class of test-methodology gap PGV-10's own
    // first draft had). The real question is about — does the REAL
    // production role (qodiqa_app) see these rows — needs its own,
    // separately-authenticated connection, calling the exact SECURITY
    // DEFINER functions migration 048 added by name.
    const appPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: 'qodiqa_app',
      // _originalPasswordEnv — the pre-elevation QODIQA_PG_PASSWORD, i.e.
      // qodiqa_app's own real password, not QODIQA_PG_TEST_PASSWORD (the
      // superuser's) — this suite's own beforeAll elevates QODIQA_PG_USER/
      // PASSWORD for its shared pgPool so migrations can run; deliberately
      // undoing that here since this pool exists specifically to exercise
      // the real, non-elevated role. undefined is correct (not a bug) for a
      // trust-auth throwaway cluster; a SCRAM-authenticated cluster (e.g.
      // the shared postgresql-x64-17 instance test:component runs against)
      // requires the real password (caught live: the first version of this
      // test omitted it entirely and failed there with a SASL error).
      password: APP_PASSWORD,
      connectionTimeoutMillis: 5000,
    });
    // the request-serving role no longer holds EXECUTE on any
    // cross-tenant SECURITY DEFINER function — the same reads are now proven
    // through the only sanctioned role for them, qodiqa_system.
    const sysPool = new Pool({
      host: process.env.QODIQA_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user: process.env.QODIQA_PG_SYSTEM_USER || 'qodiqa_system',
      password: process.env.QODIQA_PG_SYSTEM_PASSWORD,
      connectionTimeoutMillis: 5000,
    });
    try {
      for (const sql of ['SELECT qodiqa_audit_chain_max_seq()', 'SELECT count(*) FROM qodiqa_audit_chain_full_read()',
        'SELECT qodiqa_audit_chain_fetch_row_by_seq(1)', 'SELECT count(*) FROM qodiqa_audit_chain_fetch_batch(0, 10)']) {
        await expect(appPool.query(sql)).rejects.toThrow(/permission denied for function/);
      }
      const linkCheck = await sysPool.query(`
        SELECT count(*) AS broken
        FROM qodiqa_audit_chain_full_read() a
        WHERE a.prev_hash != 'GENESIS'
          AND NOT EXISTS (SELECT 1 FROM qodiqa_audit_chain_full_read() b WHERE b.hash = a.prev_hash)
      `);
      expect(Number(linkCheck.rows[0].broken)).toBe(0); // validateChainLinks()'s exact query, as qodiqa_system

      const maxSeqRow = await sysPool.query('SELECT qodiqa_audit_chain_max_seq() AS "maxSeq"');
      expect(Number(maxSeqRow.rows[0].maxSeq)).toBeGreaterThanOrEqual(4);

      const tailRow = await pgPool.query('SELECT seq FROM audit_chain WHERE artifact_id = $1', ['pgv09-3']);
      const tailHashRow = await sysPool.query(
        'SELECT qodiqa_audit_chain_fetch_row_by_seq($1) AS hash',
        [Number(tailRow.rows[0].seq)]
      );
      expect(tailHashRow.rows[0].hash).toBe(prevHash);

      const batchRows = await sysPool.query(
        'SELECT artifact_id AS "artifactId" FROM qodiqa_audit_chain_fetch_batch($1, $2) ORDER BY seq ASC',
        [0, 100]
      );
      expect(batchRows.rows.map(r => r.artifactId)).toEqual(['pgv09-0', 'pgv09-1', 'pgv09-2', 'pgv09-3']);
    } finally {
      await appPool.end().catch(() => {});
      await sysPool.end().catch(() => {});
    }
  });

  test('PGV-10 no cross-tenant leakage — a plain, non-bypassed tenant-scoped read still isolates tenant data', async () => {
    const TENANT_A = 'f26-pgv10-tenant-a';
    const TENANT_B = 'f26-pgv10-tenant-b';

    const entryA = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv10-tenant-a-row',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
        tenantId: TENANT_A,
      }),
      // Standalone — only RLS visibility is under test here, not chain
      // linkage — but migration 026's idx_audit_chain_prev_hash_unique fork
      // guard still requires distinct prevHash values per row, or the
      // second insert silently fails (23505) and this test would prove
      // nothing (caught live: the first version of this test shared one
      // prevHash between both rows, so tenant B's row was never actually
      // written — the "no leakage" assertion passed vacuously).
      'f'.repeat(64)
    );
    const entryB = entryBuilder.buildEntry(
      entryBuilder.normalizeFields({
        artifactId: 'pgv10-tenant-b-row',
        inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig',
        requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
        tenantId: TENANT_B,
      }),
      'e'.repeat(64)
    );
    await legacyInsert(entryA);
    await legacyInsert(entryB);

    //'s fix (migration 048) only bypasses RLS for the nine specific
    // global-integrity functions it names — it must NOT have weakened
    // ac_tenant_select itself. Proven here the same way persistEntry()'s own
    // write path does it for real: setLocal() inside a transaction, then a
    // PLAIN (non-bypassed) query against the raw table, exactly the shape
    // queryByTenant() uses and was deliberately left unmodified.
    //
    // Deliberately a SEPARATE connection, not the suite's shared pgPool:
    // this file's own beforeAll elevates QODIQA_PG_USER to
    // QODIQA_PG_TEST_USER (superuser) for the whole suite, specifically so
    // migrations (CREATEROLE/BYPASSRLS-granting DDL) can run — a superuser
    // connection bypasses RLS unconditionally regardless of setLocal(), so
    // asserting against pgPool here would prove nothing (caught live: the
    // first version of this test used pgPool directly and "tenant B's row
    // stays invisible" failed — not a real leak, but this test asserting
    // against a connection that was never subject to RLS in the first
    // place). A real qodiqa_app-authenticated connection is required to
    // exercise the policy at all.
    const { setLocal } = require('../../src/infra/postgres/tenantContext');
    const appPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     'qodiqa_app',
      // See the identical PGV-09 pool's own comment above for why this must
      // be the pre-elevation password (qodiqa_app's real one), not left
      // undefined — caught live: this second pool had slightly different
      // whitespace than PGV-09's, so an earlier replace_all edit missed it
      // and only PGV-09 got the fix on the first pass.
      password: APP_PASSWORD,
      connectionTimeoutMillis: 5000,
    });
    try {
      const client = await appPool.connect();
      try {
        await client.query('BEGIN');
        await setLocal(client, TENANT_A);

        const ownRow = await client.query('SELECT artifact_id FROM audit_chain WHERE tenant_id = $1', [TENANT_A]);
        expect(ownRow.rows.map(r => r.artifact_id)).toContain('pgv10-tenant-a-row');

        const otherTenantsRow = await client.query('SELECT artifact_id FROM audit_chain WHERE tenant_id = $1', [TENANT_B]);
        expect(otherTenantsRow.rows).toHaveLength(0); // tenant B's row stays invisible to tenant A's session

        const otherTenantsRowUnfiltered = await client.query('SELECT artifact_id FROM audit_chain');
        expect(otherTenantsRowUnfiltered.rows.map(r => r.artifact_id)).not.toContain('pgv10-tenant-b-row');

        await client.query('COMMIT');
      } finally {
        client.release();
      }
    } finally {
      await appPool.end().catch(() => {});
    }

    await _fixturePool.query('DELETE FROM audit_chain WHERE artifact_id IN ($1, $2)', ['pgv10-tenant-a-row', 'pgv10-tenant-b-row']);
  });

  test('PGV-11 loadChainFromPgCompact() == loadChainFromPg() compacted, same order, from ONE snapshot', async () => {
    // Extend the chain this shared test DB already holds (a second GENESIS-linked chain is refused — PGV-05).
    const tail = (await pgAuditBackend.loadChainFromPg()).slice(-1)[0];
    let prevHash = tail ? tail.hash : 'GENESIS';
    for (let i = 0; i < 7; i++) prevHash = (await _seedEntry(prevHash, `pgv11-${i}`)).hash;
    const { _compactForDivergence } = ChainVerifierMod;

    const expected = (await pgAuditBackend.loadChainFromPg()).map(_compactForDivergence);
    const pageSizes = [];
    const got = await pgAuditBackend.loadChainFromPgCompact(_compactForDivergence, { pageSize: 2, onPage: async (p) => { pageSizes.push(p.length); } });
    expect(expected.filter((r) => /^pgv11-/.test(r.artifactId))).toHaveLength(7);
    expect(got).toEqual(expected);
    expect(pageSizes.length).toBeGreaterThan(1);
    expect(Math.max(...pageSizes)).toBeLessThanOrEqual(2);

    // One snapshot: a row committed while the pages are being read is not part of this read (as with the single
    // query it replaces), and IS part of the next one.
    const before = expected.length;
    let inserted = false;
    const during = await pgAuditBackend.loadChainFromPgCompact(_compactForDivergence, {
      pageSize: 2,
      onPage: async () => { if (!inserted) { inserted = true; await _seedEntry(prevHash, 'pgv11-late'); } },
    });
    expect(inserted).toBe(true);
    expect(during).toHaveLength(before);
    expect(during.some((r) => r.artifactId === 'pgv11-late')).toBe(false);
    const after = await pgAuditBackend.loadChainFromPgCompact(_compactForDivergence);
    expect(after).toHaveLength(before + 1);
    expect(after).toEqual((await pgAuditBackend.loadChainFromPg()).map(_compactForDivergence));

    await _fixturePool.query("DELETE FROM audit_chain WHERE artifact_id LIKE 'pgv11-%'");
  });

  test('PGV-12 an entry whose PG dual-write is still in flight at read time is rechecked, not reported CORRUPTED', async () => {
    const current = await pgAuditBackend.loadChainFromPg();
    const tail = current.slice(-1)[0];
    const inFlight = entryBuilder.buildEntry(entryBuilder.normalizeFields({
      artifactId: 'pgv12-inflight', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig-pgv12',
      requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
    }), tail ? tail.hash : 'GENESIS');
    const fileEntries = [...current, inFlight]; // the file already has it; PG does not yet
    const facade = (drain) => ({ ORDERING_MODE: 'single-node', forEachModernChainPage: async (onPage) => { await onPage(fileEntries); return fileEntries.length; }, drainMirrorWriter: drain });
    const quiet = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });
    const mk = (drain, emitted) => ChainVerifierMod.createChainVerifier({ config: { batchSize: 3 }, _auditLog: facade(drain), _pgPool: pgPool,
      _pgBackend: pgAuditBackend, _verifierState: verifierState, _metrics: quiet, _emit: (l, t, d) => emitted.push({ t, d }) });

    // The mirror writer commits the in-flight entry while the verifier waits on it → no violation.
    const ev1 = [];
    const r1 = await mk(async () => { await pgAuditBackend.persistEntry(inFlight); }, ev1).verifyPgDivergence('MANUAL');
    expect(r1.violations.filter((v) => /MISSING_IN_PG/.test(v.reason))).toEqual([]);
    expect(ev1.find((e) => e.t === 'AUDIT_CHAIN_VERIFIER_TAIL_RECHECKED').d).toMatchObject({ tailLength: 1, foundOnRecheck: 1, resolved: true });

    // An entry that never reaches PG is still reported CRITICAL.
    const neverWritten = entryBuilder.buildEntry(entryBuilder.normalizeFields({
      artifactId: 'pgv12-never', inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH, signature: 'sig-pgv12n',
      requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true,
    }), inFlight.hash);
    fileEntries.push(neverWritten);
    const ev2 = [];
    const r2 = await mk(async () => {}, ev2).verifyPgDivergence('MANUAL');
    const miss = r2.violations.find((v) => v.reason === 'PG_MIRROR_MISSING_IN_PG');
    expect(miss).toBeTruthy();
    expect(miss.severity).toBe('CRITICAL');

    await _fixturePool.query("DELETE FROM audit_chain WHERE artifact_id LIKE 'pgv12-%'");
  });

  test('PGV-13 amendment 8: the verifier WORKER uses the same roles and sees the FULL chain, not an RLS slice', async () => {
    // Own fixture (this suite's disposable DB): a tenant-scoped chain, the kind ac_tenant_select hides from an unscoped app read.
    await _fixturePool.query('DELETE FROM audit_chain');
    let prevHash = 'GENESIS';
    for (let i = 0; i < 5; i++) {
      const entry = entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: `pgv13-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
        signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 'w10-pgv13-tenant' }), prevHash);
      await pgAuditBackend.persistEntry(entry);
      prevHash = entry.hash;
    }
    const total = (await pgPool.query('SELECT count(*)::int n FROM audit_chain')).rows[0].n;   // elevated (BYPASSRLS) suite pool
    expect(total).toBe(5);
    const appPool = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME, user: 'qodiqa_app', password: APP_PASSWORD, connectionTimeoutMillis: 5000 });
    let rlsSlice;
    try { rlsSlice = (await appPool.query('SELECT count(*)::int n FROM audit_chain')).rows[0].n; } finally { await appPool.end(); }
    expect(rlsSlice).toBeLessThan(total);            // an unscoped app-role count IS an RLS slice here
    const { createWorkerRunner } = require('../../src/core/audit/verifier/workerHost');
    const host = createWorkerRunner({ _emit: () => {}, config: { incrementalIntervalMs: 0, fullIntervalMs: 0, pgDivergenceIntervalMs: 0 } });
    try {
      const sc = await host.selfCheck();
      expect(sc.follower).toBe(true);
      expect(sc.pgEnabled).toBe(true);
      expect(sc.roles.system).toBe(process.env.QODIQA_PG_SYSTEM_USER || 'qodiqa_system');
      expect(sc.chainRowsSeenBySystemRole).toBe(total);  // the full chain
    } finally { await host._terminateForTests(); }
  }, 60_000);

  test('PGV-14 amendment 6: the bounded-memory divergence merge decides a healthy chain on real PG alone', async () => {
    const rows = await pgAuditBackend.loadChainFromPg();
    expect(rows.length).toBeGreaterThan(0);
    const events = [];
    const facade = {
      ORDERING_MODE: 'single-node',
      getChainStats: () => ({ modernLength: rows.length }),
      getModernChainPage: async ({ cursor, limit }) => { const from = cursor ? cursor.m : 0; const es = rows.slice(from, from + limit); return { entries: es, startPos: from, nextCursor: from + es.length < rows.length ? { m: from + es.length } : null }; },
      forEachModernChainPage: async (fn, { limit }) => { for (let i = 0; i < rows.length; i += limit) await fn(rows.slice(i, i + limit)); return rows.length; },
      drainMirrorWriter: async () => {},
    };
    const quiet = new Proxy({}, { get: () => ({ inc: () => {}, set: () => {}, observe: () => {} }) });
    const v = ChainVerifierMod.createChainVerifier({ config: { batchSize: 3 }, _auditLog: facade, _pgPool: pgPool, _pgBackend: pgAuditBackend,
      _verifierState: verifierState, _metrics: quiet, _emit: (l, t, d) => events.push({ t, d }) });
    const r = await v.verifyPgDivergence('MANUAL');
    expect(r.success).toBe(true);
    expect(events.some((e) => e.t === 'AUDIT_CHAIN_VERIFIER_DIVERGENCE_FULL_COMPARE')).toBe(false);
    expect(r.violations.filter((x) => /MIRROR/.test(x.reason))).toEqual([]);
    expect(r.entriesChecked).toBe(rows.length);
  });

  test('PGV-15 the PG lag monitor counts the whole mirror, not an RLS slice, and detects an injected lag', async () => {
    await _fixturePool.query('DELETE FROM audit_chain');
    let prevHash = 'GENESIS';
    for (let i = 0; i < 6; i++) {
      const entry = entryBuilder.buildEntry(entryBuilder.normalizeFields({ artifactId: `pgv15-${i}`, inputHash: 'a'.repeat(64), decision: 'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
        signature: 'sig', requestHash: 'b'.repeat(64), policyHash: 'c'.repeat(64), verificationResult: true, tenantId: 'w10-pgv15-tenant' }), prevHash);
      await pgAuditBackend.persistEntry(entry);
      prevHash = entry.hash;
    }
    const lagMonitor = require('../../src/core/audit/pgLagMonitor');
    const run = async (fileCount, queryFn) => {
      const ev = []; lagMonitor._resetState();
      await lagMonitor._checkOnce({ getFileCount: () => fileCount, queryFn, emitFn: (l, t, d) => ev.push({ t, d }), lagThreshold: 5 });
      return ev.filter((e) => e.t === 'AUDIT_PG_SYNC_LAG');
    };
    // Pre-fix query, as the request-serving role: an RLS slice → a FALSE lag at perfect parity (the symptom).
    const appPool = new Pool({ host: process.env.QODIQA_PG_HOST || 'localhost', port: parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME, user: 'qodiqa_app', password: APP_PASSWORD, connectionTimeoutMillis: 5000 });
    let preFix;
    try { preFix = await run(6, () => appPool.query('SELECT count(*) AS cnt FROM audit_chain')); } finally { await appPool.end(); }
    expect(preFix).toHaveLength(1);
    expect(preFix[0].d.pgCount).toBe(0);
    // Fixed query: parity → no lag event.
    expect(await run(6, lagMonitor.pgCountQuery)).toEqual([]);
    // Injected lag: the file is 20 entries ahead of the mirror → detected, with the true PG count.
    const lagged = await run(26, lagMonitor.pgCountQuery);
    expect(lagged).toHaveLength(1);
    expect(lagged[0].d).toMatchObject({ fileCount: 26, pgCount: 6, lag: 20 });
  });
});
