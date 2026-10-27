'use strict';

/**
 * PG-authoritative mode keeps DURABLE replay/duplicate uniqueness,
 * regardless of the in-memory window size.
 *
 * The other half's pin (file-mode half:
 * src/core/audit/__tests__/replayHorizon.test.js). In single-node FILE
 * mode the audit-chain dedup horizon is the bounded window — a documented
 * limitation. In distributed (PG-authoritative)
 * mode there is no horizon: uniqueness is enforced by PostgreSQL UNIQUE
 * indexes (idx_audit_chain_nonce / idx_audit_chain_artifact_id, mapped back
 * to `replay_detected` / `already_executed` by distributedOrdering.js), so a
 * nonce or artifactId reuse OLDER than the window is still rejected. This
 * suite proves that against real PostgreSQL with a deliberately tiny window
 * (QODIQA_AUDIT_WINDOW_SIZE=3) so the reuse is guaranteed to be beyond the
 * in-memory horizon when it happens.
 *
 * Requires real PostgreSQL (QODIQA_PG_ENABLED=true) — skipped entirely
 * otherwise. Database lifecycle: uniquely-named disposable database created
 * in beforeAll, dropped in afterAll — the exact pattern of
 * test/integration/audit-chain-distributed.integration.test.js (FINDING-AUDIT-MIRROR-
 * RECURRENCE-REPORT.md §8 prevention layer 1); never touches a pre-existing
 * database.
 */

const { EMPTY_OUTPUT_HASH: W7_EMPTY_OUTPUT_HASH } = require('../../src/core/audit/entryBuilder'); // v7 (R-5): synthetic ALLOW fixtures deliver nothing
// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto   = require('crypto');
const { Pool } = require('pg');
const { dropTestDatabase } = require('../helpers/dropTestDatabase');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_f30_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

function allowFields(label, overrides = {}) {
  return {
    artifactId:  `f30-${label}-${crypto.randomBytes(4).toString('hex')}`,
    inputHash:   crypto.createHash('sha256').update(`f30-${label}`).digest('hex'),
    decision:    'ALLOW', outputHash: W7_EMPTY_OUTPUT_HASH,
    signature:   'test-signature',
    requestHash: crypto.createHash('sha256').update(`f30-${label}:req`).digest('hex'),
    policyHash:  crypto.createHash('sha256').update('f30-policy').digest('hex'),
    verificationResult: true,
    ...overrides,
  };
}

describeOrSkip('distributed mode: durable uniqueness beyond the in-memory window (real PostgreSQL)', () => {
  let pgPool;
  let auditLog;
  let _maintenancePool;
  let _originalDatabaseEnv;
  let _originalUserEnv;
  let _originalPasswordEnv;
  let _originalOrderingModeEnv;
  let _originalWindowEnv;

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
    await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    // Elevate only for migrating the fresh database (002/018 require
    // CREATEROLE+BYPASSRLS) — restored below before any test runs.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    _originalOrderingModeEnv = process.env.QODIQA_AUDIT_ORDERING_MODE;
    process.env.QODIQA_AUDIT_ORDERING_MODE = 'distributed';
    // The point: make the in-memory window smaller than the append run
    // below, so the reuse is unambiguously OUTSIDE the window when rejected.
    _originalWindowEnv = process.env.QODIQA_AUDIT_WINDOW_SIZE;
    process.env.QODIQA_AUDIT_WINDOW_SIZE = '3';

    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
    await pgPool.runMigrations();

    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    auditLog = require('../../src/core/audit/audit-log');
    expect(auditLog.WINDOW_SIZE).toBe(3);
  }, 60_000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;
    if (_originalOrderingModeEnv === undefined) delete process.env.QODIQA_AUDIT_ORDERING_MODE;
    else process.env.QODIQA_AUDIT_ORDERING_MODE = _originalOrderingModeEnv;
    if (_originalWindowEnv === undefined) delete process.env.QODIQA_AUDIT_WINDOW_SIZE;
    else process.env.QODIQA_AUDIT_WINDOW_SIZE = _originalWindowEnv;

    if (_maintenancePool) {
      // a late fire-and-forget write can re-create a foreign-role pool after the
      // shutdown above; the helper re-runs the shutdown before each forced-drop attempt.
      const r = await dropTestDatabase(_maintenancePool, TEST_DB_NAME, { shutdown: () => (pgPool ? pgPool.shutdown() : Promise.resolve()) });
      // eslint-disable-next-line no-console
      if (!r.dropped) console.warn(`[replayHorizonPgUniqueness] failed to drop ${TEST_DB_NAME}: ${r.error} — attached: ${JSON.stringify(r.attached)}`);
      await _maintenancePool.end().catch(() => {});
    }
  }, 30_000);

  test('a nonce OLDER than the window is still rejected (replay_detected) — PG UNIQUE, no in-memory horizon', async () => {
    const nonce = `f30-pg-nonce-${crypto.randomBytes(6).toString('hex')}`;
    await auditLog.append(allowFields('seed', { nonce }));

    // Push the nonce's entry far outside the 3-entry in-memory window.
    for (let i = 0; i < 5; i++) await auditLog.append(allowFields(`filler-${i}`));
    expect(auditLog.getWindowStats().windowLength).toBeLessThanOrEqual(3);

    // File mode would accept this (the documented limitation, pinned in
    // src/core/audit/__tests__/replayHorizon.test.js H2). Distributed
    // mode must reject it: uniqueness is PostgreSQL's, not the window's.
    await expect(auditLog.append(allowFields('reuse', { nonce })))
      .rejects.toThrow(/^replay_detected/);
  }, 30_000);

  test('an artifactId OLDER than the window is still rejected (already_executed)', async () => {
    const first = await auditLog.append(allowFields('aid-seed'));
    for (let i = 0; i < 5; i++) await auditLog.append(allowFields(`aid-filler-${i}`));

    await expect(auditLog.append(allowFields('aid-reuse', { artifactId: first.artifactId })))
      .rejects.toThrow(/^already_executed/);
  }, 30_000);
});
