'use strict';

/**
 * Layer 1 — real end-to-end recovery test for a write dropped while the
 * PostgreSQL circuit breaker is OPEN.
 *
 * Mirrors test/integration/audit-chain-verifier-pg.integration.test.js's disposable-
 * database pattern (real PostgreSQL, no mocking of pool.js/pg-audit-
 * backend.js/the persistence-recovery queue).
 *
 * What this proves that a unit test of isPersistenceFailure() alone cannot:
 * Layer 1, an audit_chain write attempted while pool.js's circuit
 * breaker was OPEN was classified as a non-retryable data error and silently
 * dropped — no enqueue, no journal entry, permanently missing from the PG
 * mirror even after PostgreSQL recovered (
 *). A test asserting only "isPersistenceFailure(circuitOpenError) ===
 * true" would not catch a regression in the surrounding wiring (persistEntry
 * not calling enqueue, enqueue not reaching the real queue table, the real
 * worker's real handler not actually performing the INSERT). This test
 * exercises the real chain end to end: force the breaker OPEN via its public
 * API -> real persistEntry() attempt -> assert the row is durably queued
 * (not lost) -> reset the breaker (PG healthy again) -> drain the real queue
 * through the real registered handler -> assert the row now exists for real
 * in audit_chain with the correct hash/prevHash, and is gone from the queue.
 *
 * ACOR-01  A write attempted while the breaker is OPEN is NOT lost. In this
 *          scenario the recovery-queue INSERT itself is ALSO gated by the
 *          same shared breaker (recoveryManager.enqueue() -> queue.enqueue()
 *          -> pgPool.query()), so it fails too — recoveryManager's own
 *          documented FAILOVER-1 fallback engages: the operation is durably
 *          written to the local filesystem journal instead of being lost.
 * ACOR-02  Once PostgreSQL is healthy again: the journal entry replays into
 *          the real PostgreSQL-backed queue (journalWorker's own replay
 *          path), and draining that queue through the real worker handler
 *          backfills the row into audit_chain with the exact hash/prevHash
 *          the original entry carried — removed from both the queue and the
 *          journal once complete.
 * ACOR-03 A recovered schemaVersion-6 entry, chained after a normally
 *          written one, re-verifies from its STORED COLUMNS via
 *          loadChainFromPg() — the path the single-node boot mirror check
 * uses. the replay INSERT wrote 15 of 27 columns, so the
 *          row read back as schemaVersion 1 and failed as AUDIT_CHAIN_TAMPERED.
 * ACOR-04 Same recovery under the real unprivileged pooled role
 *          (qodiqa_app, positive-controlled non-BYPASSRLS) for a
 * tenant-scoped entry. the replay INSERT carried no
 *          tenant context, so ON CONFLICT's RLS check rejected it and the
 *          entry never reached the mirror.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto   = require('crypto');
const fs       = require('fs');
const os       = require('os');
const path     = require('path');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_acor_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

let _originalDatabaseEnv;
let _originalUserEnv;
let _originalPasswordEnv;
let _maintenancePool;
let _verifyPool; // raw pg Pool, bypasses pgPool.js's circuit breaker entirely — for assertions only
let pgPool, pgCircuitBreaker, pgAuditBackend, entryBuilder, queue, worker, recoveryManager, journal, journalWorker;

jest.setTimeout(60_000);

describeOrSkip('Layer 1 — audit_chain write survives a circuit-open outage (real disposable Postgres)', () => {
  beforeAll(async () => {
    if (!SAFE_IDENTIFIER.test(TEST_DB_NAME)) {
      throw new Error(`Generated test DB name "${TEST_DB_NAME}" failed identifier validation — refusing to proceed.`);
    }

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

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    // Dedicated, per-run journal directory — the fallback path exercised
    // below (ACOR-01/02) writes real files; must never touch the real
    // data/prq-journal directory shared by an actual running server.
    const journalDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qodiqa-test-prq-journal-'));
    process.env.QODIQA_PRQ_JOURNAL_DIR = journalDir;

    jest.resetModules();
    pgPool           = require('../../src/infra/postgres/pool');
    pgCircuitBreaker  = require('../../src/infra/postgres/pgCircuitBreaker');
    pgAuditBackend    = require('../../src/infra/postgres/pg-audit-backend');
    entryBuilder      = require('../../src/core/audit/entryBuilder');
    queue             = require('../../src/core/persistenceRecovery/queue');
    worker            = require('../../src/core/persistenceRecovery/worker');
    recoveryManager   = require('../../src/core/persistenceRecovery/recoveryManager');
    journal           = require('../../src/core/persistenceRecovery/journal');
    journalWorker     = require('../../src/core/persistenceRecovery/journalWorker');

    pgPool.initialize();
    await pgPool.runMigrations();

    // Assertions in this suite deliberately go through a SEPARATE raw pg
    // connection, not pgPool.query() — pgPool.query() is itself gated by the
    // same circuit breaker this test forces OPEN, so using it for read-only
    // verification queries would throw PG_CIRCUIT_OPEN on the assertion
    // itself, not just on the write path under test.
    _verifyPool = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: TEST_DB_NAME,
      user:     process.env.QODIQA_PG_USER,
      password: process.env.QODIQA_PG_PASSWORD,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
      connectionTimeoutMillis: 5000,
    });

    // Register the REAL production handler for AUDIT_CHAIN_PG_SAVE — the
    // exact function persistEntry()'s own retry path relies on in
    // production, not a test stand-in — so draining the queue below proves
    // genuine backfill, not merely that some handler ran.
    worker.registerHandler(
      recoveryManager.OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE,
      recoveryManager._builtinHandlers[recoveryManager.OPERATION_TYPES.AUDIT_CHAIN_PG_SAVE],
    );
  }, 60_000);

  afterAll(async () => {
    pgCircuitBreaker?.reset();
    if (_verifyPool) await _verifyPool.end().catch(() => {});
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn(`[auditChainCircuitOpenRecovery.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }

    if (process.env.QODIQA_PRQ_JOURNAL_DIR) {
      fs.rmSync(process.env.QODIQA_PRQ_JOURNAL_DIR, { recursive: true, force: true });
    }
  }, 30_000);

  afterEach(() => {
    pgCircuitBreaker.reset();
  });

  function buildTestEntry(artifactId) {
    const normalized = entryBuilder.normalizeFields({
      artifactId,
      inputHash:          'a'.repeat(64),
      decision:           'BLOCK',
      signature:          `sig-${artifactId}`,
      requestHash:        'b'.repeat(64),
      policyHash:         'c'.repeat(64),
      verificationResult: false,
    });
    return entryBuilder.buildEntry(normalized, 'GENESIS');
  }

  async function forceBreakerOpen() {
    const breaker = pgCircuitBreaker.getCircuitBreaker();
    // Public API only — reproduces the real CLOSED -> OPEN transition
    // (cbFailureThreshold consecutive failures) rather than reaching into
    // the breaker's private state.
    const threshold = 5; // default QODIQA_PG_CB_FAILURE_THRESHOLD
    for (let i = 0; i < threshold; i++) breaker.onFailure();
    expect(breaker.state).toBe(pgCircuitBreaker.STATE_OPEN);
  }

  test('ACOR-01: a write attempted while the breaker is OPEN is durably journaled, not lost', async () => {
    await forceBreakerOpen();

    const entry = buildTestEntry('acor-01-artifact');
    await pgAuditBackend.persistEntry(entry); // real code path — breaker OPEN, real _circuitOpenError() throw

    // Not in audit_chain yet — the write genuinely never reached PostgreSQL.
    const chainRow = await _verifyPool.query(
      'SELECT hash FROM audit_chain WHERE artifact_id = $1',
      [entry.artifactId],
    );
    expect(chainRow.rows).toHaveLength(0);

    // The recovery-queue INSERT itself is also gated by the same shared
    // breaker, so it fails too — not in the PG-backed queue table yet.
    const queueRow = await _verifyPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [`acpg:${entry.artifactId}`],
    );
    expect(queueRow.rows).toHaveLength(0);

    // But durably journaled to disk instead — recoveryManager's own
    // FAILOVER-1 fallback. This is the fix: Layer 1, this entry
    // would not exist anywhere (isPersistenceFailure returned false,
    // persistEntry never called enqueue() at all, so this fallback never
    // even engaged).
    const journalEntries = await journal.listEntries();
    const journaled = journalEntries.find(e => e.operation.operationId === `acpg:${entry.artifactId}`);
    expect(journaled).toBeDefined();
    expect(journaled.operation.operationType).toBe('AUDIT_CHAIN_PG_SAVE');
    expect(journaled.operation.payload.hash).toBe(entry.hash);
  });

  test('ACOR-02: once PostgreSQL is healthy again, journal replay + queue drain backfills the exact row into audit_chain', async () => {
    await forceBreakerOpen();

    const entry = buildTestEntry('acor-02-artifact');
    await pgAuditBackend.persistEntry(entry);

    const journalEntriesBefore = await journal.listEntries();
    const journaled = journalEntriesBefore.find(e => e.operation.operationId === `acpg:${entry.artifactId}`);
    expect(journaled).toBeDefined();

    // "PostgreSQL is healthy again" — reset the breaker to CLOSED (public,
    // documented test API), independent of the breaker's own recovery-timer
    // behavior, which is a separate concern from whether a journaled write
    // actually gets backfilled once queries succeed again.
    pgCircuitBreaker.reset();

    // Real journal replay path — journalWorker._replayOne() calls the real
    // queue.enqueue() (now succeeds) and removes the journal file.
    const replayed = await journalWorker._replayOne(journaled);
    expect(replayed).toBe(true);

    const journalEntriesAfter = await journal.listEntries();
    expect(journalEntriesAfter.find(e => e.operation.operationId === `acpg:${entry.artifactId}`)).toBeUndefined();

    const queuedAfterReplay = await _verifyPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [`acpg:${entry.artifactId}`],
    );
    expect(queuedAfterReplay.rows).toHaveLength(1);

    // Drain the queue through the REAL claim -> real handler -> real
    // markComplete path — no shortcuts, this is the exact production flow
    // worker.js's poll loop runs.
    const claimed = await queue.claimNext();
    expect(claimed).not.toBeNull();
    expect(claimed.operationId).toBe(`acpg:${entry.artifactId}`);
    await worker._processOne(claimed);

    // Now genuinely present in audit_chain, with the exact hash/prevHash
    // the original (dropped) write attempt carried.
    const chainRow = await _verifyPool.query(
      'SELECT hash, prev_hash FROM audit_chain WHERE artifact_id = $1',
      [entry.artifactId],
    );
    expect(chainRow.rows).toHaveLength(1);
    expect(chainRow.rows[0].hash).toBe(entry.hash);
    expect(chainRow.rows[0].prev_hash).toBe(entry.prevHash);

    // And removed from the queue (worker.js markComplete() deletes on success).
    const queuedAfter = await _verifyPool.query(
      `SELECT 1 FROM persistence_recovery_queue WHERE operation_id = $1`,
      [`acpg:${entry.artifactId}`],
    );
    expect(queuedAfter.rows).toHaveLength(0);
  });

  // ACOR-02 asserts only hash/prev_hash, which the handler copies
  // verbatim — it never re-derives the entry from the stored columns the way
  // the single-node boot mirror check (mirrorConsistencyCheck.js ->
  // loadChainFromPg() -> verifyAuditChainDetailed()) does. This drives a
  // schemaVersion-6 entry carrying the fields a real /ai/chat decision writes
  // through the same real outage -> journal -> replay -> queue -> production
  // handler path, then re-verifies what actually landed in PostgreSQL.
  test('ACOR-03: a recovered schemaVersion-6 entry re-verifies from its stored columns, chained after a normally-written one', async () => {
    const richFields = (artifactId) => ({
      artifactId,
      inputHash:          crypto.createHash('sha256').update(`${artifactId}:in`).digest('hex'),
      decision:           'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
      signature:          `sig-${artifactId}`,
      requestHash:        crypto.createHash('sha256').update(`${artifactId}:req`).digest('hex'),
      policyHash:         'c'.repeat(64),
      verificationResult: true,
      tenantId:           'h124-tenant',
      publicKeyId:        'h124-tenant:key_v1',
      consentProvenance:  { consentId: `consent-${artifactId}`, state: 'ACTIVE' },
      policyDecision:     { decision: 'EXECUTE', reason: 'ALL_CHECKS_PASSED' },
      callerContext:      { callerId: 'caller-1', callerName: 'h124', environment: 'production', credentialType: 'api-key' },
      provider:           'local',
      model:              'llama3.2:1b',
      stage:              'PROVIDER_EXECUTION',
      semantic:           { decision: 'ALLOW', score: 0.1 },
      tokenUsage:         { inputTokens: 3, outputTokens: 5, totalTokens: 8 },
      responseId:         `resp-${artifactId}`,
    });

    // 1. Written normally (breaker CLOSED) — the regular dual-write INSERT.
    // Anchored on the chain's current tail: this suite's earlier tests already
    // used GENESIS, and audit_chain.prev_hash is UNIQUE. a mirror row
    // is inserted only after its parent is committed, so the anchor must be a
    // row that really exists (a made-up anchor is correctly refused and queued).
    const anchor = (await pgAuditBackend.getChainTail())?.hash ?? 'GENESIS';
    const first = entryBuilder.buildEntry(entryBuilder.normalizeFields(richFields('acor-03-first')), anchor);
    expect(first.schemaVersion).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)
    await pgAuditBackend.persistEntry(first);

    // 2. Next link in the chain, written during an outage -> recovered.
    const second = entryBuilder.buildEntry(entryBuilder.normalizeFields(richFields('acor-03-second')), first.hash);
    await forceBreakerOpen();
    await pgAuditBackend.persistEntry(second);
    const journaled = (await journal.listEntries()).find(e => e.operation.operationId === `acpg:${second.artifactId}`);
    expect(journaled).toBeDefined();
    pgCircuitBreaker.reset();
    expect(await journalWorker._replayOne(journaled)).toBe(true);
    const claimed = await queue.claimNext();
    expect(claimed.operationId).toBe(`acpg:${second.artifactId}`);
    await worker._processOne(claimed);

    // 3. Re-derive both rows exactly as the boot mirror check does.
    const hydrated = (await pgAuditBackend.loadChainFromPg())
      .filter(r => r.artifactId === first.artifactId || r.artifactId === second.artifactId);
    expect(hydrated.map(r => r.artifactId)).toEqual([first.artifactId, second.artifactId]);
    const recovered = hydrated[1];
    expect(recovered.schemaVersion).toBe(7); // CURRENT_SCHEMA_VERSION 6 -> 7 (audit schema v7)
    expect(recovered.publicKeyId).toBe('h124-tenant:key_v1');
    expect(recovered.provider).toBe('local');
    expect(recovered.stage).toBe('PROVIDER_EXECUTION');
    expect(recovered.responseId).toBe(`resp-${second.artifactId}`);

    const detail = require('../../src/core/audit/audit-log').verifyAuditChainDetailed(hydrated, anchor);
    expect(detail.reason).toBeNull();
    expect(detail.valid).toBe(true);
    expect(detail.entriesVerified).toBe(2);
  });

  // ACOR-01..03 run the pool as QODIQA_PG_TEST_USER (BYPASSRLS), which
  // hides the second half's defect: the production pooled role is
  // qodiqa_app, and ON CONFLICT makes PostgreSQL apply ac_tenant_select to
  // the proposed row — without qodiqa.tenant_id context, a tenant-scoped
  // recovered row was rejected as an RLS violation and never reached the
  // mirror. Same harness pattern as crossTenantAdversarial.integration.test.js
  // (migrations as the test role, pooled code as QODIQA_PG_USER, with a
  // positive control so this cannot pass vacuously under a BYPASSRLS role).
  test('ACOR-04: under the unprivileged pooled role, a recovered tenant-scoped entry lands and re-verifies', async () => {
    await pgPool.shutdown();
    process.env.QODIQA_PG_USER     = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    pgPool.initialize();
    try {
      const who = await pgPool.query(
        'SELECT current_user AS u, (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user) AS bypass',
      );
      expect(who.rows[0].bypass).toBe(false); // positive control

      // anchored on the real chain tail — see ACOR-03.
      const anchor = (await pgAuditBackend.getChainTail())?.hash ?? 'GENESIS';
      const entry = entryBuilder.buildEntry(entryBuilder.normalizeFields({
        artifactId:         'acor-04-tenant',
        inputHash:          'd'.repeat(64),
        decision:           'BLOCK',
        signature:          'sig-acor-04',
        requestHash:        'e'.repeat(64),
        policyHash:         'c'.repeat(64),
        verificationResult: true,
        tenantId:           'h124-tenant',
        publicKeyId:        'h124-tenant:key_v1',
        provider:           'local',
        stage:              'PROVIDER_EXECUTION',
        reason:             'PROVIDER_ERROR',
      }), anchor);

      await forceBreakerOpen();
      await pgAuditBackend.persistEntry(entry);
      const journaled = (await journal.listEntries()).find(e => e.operation.operationId === `acpg:${entry.artifactId}`);
      expect(journaled).toBeDefined();
      pgCircuitBreaker.reset();
      expect(await journalWorker._replayOne(journaled)).toBe(true);
      const claimed = await queue.claimNext();
      expect(claimed.operationId).toBe(`acpg:${entry.artifactId}`);
      await worker._processOne(claimed);

      const landed = await _verifyPool.query('SELECT tenant_id, schema_version FROM audit_chain WHERE artifact_id = $1', [entry.artifactId]);
      expect(landed.rows).toEqual([{ tenant_id: 'h124-tenant', schema_version: 7 }]); // CURRENT_SCHEMA_VERSION 6 -> 7

      const hydrated = (await pgAuditBackend.loadChainFromPg()).filter(r => r.artifactId === entry.artifactId);
      const detail = require('../../src/core/audit/audit-log').verifyAuditChainDetailed(hydrated, anchor);
      expect(detail.reason).toBeNull();
      expect(detail.valid).toBe(true);
      expect(detail.entriesVerified).toBe(1);
    } finally {
      await pgPool.shutdown();
      process.env.QODIQA_PG_USER     = process.env.QODIQA_PG_TEST_USER || _originalUserEnv;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD || _originalPasswordEnv;
      pgPool.initialize();
    }
  });
});
