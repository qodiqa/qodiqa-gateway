'use strict';

/**
 * BLOCK-01 regression — consent `action` key semantics.
 *
 * Root cause: docs/api/overview.md's
 * only `POST /consent` example granted consent with a human-readable action
 * name (`"ai-chat-execute"`), but the real enforcement path
 * (src/validation/checkPolicy.js -> services/policy/evaluators/requireConsent.js)
 * resolves the consent lookup's `action` as `artifact.payload.provider` (e.g.
 * "openai") — an exact string match, by design (ConsentStore.findByKey() has
 * no aliasing). A consent record granted with any other action string can
 * never be found by /ai/chat, and is denied CONSENT_NOT_FOUND even though the
 * record is correctly persisted and ACTIVE. The fix was documentation-only
 * (docs/api/overview.md now uses a provider string in its example); this
 * test locks in BOTH directions of that exact-match contract so it cannot
 * silently regress into either "aliasing was added" or "the documented flow
 * stopped working" without a test failure.
 *
 * Requires a real, reachable local PostgreSQL + Redis (QODIQA_PG_ENABLED=true)
 * — skipped entirely otherwise, same convention as
 * test/integration/audit-chain-verifier-pg.integration.test.js.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const crypto = require('crypto');
const { Pool } = require('pg');
const { trackInFlight } = require('../helpers/inFlight');
let verificationWrites = null;

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

// prevention layer 1 — this suite previously ran against whatever
// QODIQA_PG_DATABASE resolved to, which for any local run was the real,
// persistent `qodiqa` database: 306 orphan block01-* consent rows accumulated
// there across 81 gate runs before it was caught. Layer 2 (test/support/jest.setup.js) now
// makes a local un-opted-in run skip this suite entirely, but an opted-in
// local run or a CI run still executes it — so it must not write to a shared
// database either. Same disposable-database lifecycle as this suite's sibling
// test/integration/audit-chain-verifier-pg.integration.test.js, which had it from the
// start; the report that named both layers proposed exactly this for exactly
// this class of suite.
const SAFE_IDENTIFIER = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const TEST_DB_NAME = `qodiqa_block01_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

describeOrSkip('BLOCK-01 — consent action key must exact-match artifact.payload.provider', () => {
  let pool, registry, cache;
  let _maintenancePool = null;
  let _originalDatabaseEnv, _originalUserEnv, _originalPasswordEnv;

  function freshActorId(label) {
    return `block01-${label}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  }

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
      // Safe: generator-controlled name (timestamp + random hex), validated
      // against SAFE_IDENTIFIER above, never derived from external input.
      await _maintenancePool.query(`CREATE DATABASE "${TEST_DB_NAME}"`);
    }

    _originalDatabaseEnv = process.env.QODIQA_PG_DATABASE;
    _originalUserEnv     = process.env.QODIQA_PG_USER;
    _originalPasswordEnv = process.env.QODIQA_PG_PASSWORD;
    process.env.QODIQA_PG_DATABASE = TEST_DB_NAME;
    // Migrations 002/018 CREATE ROLE / ALTER ROLE ... BYPASSRLS, which need
    // CREATEROLE+BYPASSRLS on the connecting role — same elevation the sibling
    // suite performs, restored in afterAll.
    if (process.env.QODIQA_PG_TEST_USER) {
      process.env.QODIQA_PG_USER     = process.env.QODIQA_PG_TEST_USER;
      process.env.QODIQA_PG_PASSWORD = process.env.QODIQA_PG_TEST_PASSWORD;
    }

    jest.resetModules();
    pool     = require('../../src/infra/postgres/pool');
    // ConsentVerifier writes its verification log fire-and-forget
    // (store.logVerification(...).catch(...)); afterAll waits for those writes
    // before shutting the pool.
    verificationWrites = trackInFlight(require('../../src/core/consent/ConsentStore'), 'logVerification');
    registry = require('../../src/core/consent');
    cache    = require('../../src/core/consent/ConsentCache');
    pool.initialize();
    await pool.runMigrations();
  }, 120_000);

  afterAll(async () => {
    if (verificationWrites) { await verificationWrites.settle(); verificationWrites.restore(); }
    if (cache) await cache.disconnect().catch(() => {});
    // (NF-6): grant() now publishes a signed cross-node invalidation, which
    // opens the revocation publisher's Redis client — close it like the cache
    // (server shutdown does the same, server/startup.js REVOCATION_PUBLISHER).
    await require('../../src/core/consent/revocation/RevocationPublisher').disconnect().catch(() => {});
    if (pool) await pool.shutdown().catch(() => {});
    process.env.QODIQA_PG_DATABASE = _originalDatabaseEnv;
    process.env.QODIQA_PG_USER     = _originalUserEnv;
    process.env.QODIQA_PG_PASSWORD = _originalPasswordEnv;

    if (_maintenancePool) {
      try {
        await _maintenancePool.query(`DROP DATABASE IF EXISTS "${TEST_DB_NAME}" WITH (FORCE)`);
      } catch (err) {
        // Best-effort cleanup only — a leftover uniquely-named disposable test
        // DB is a minor annoyance, never a reason to fail the suite. Note this
        // drops only a database this suite itself created moments earlier.
        // eslint-disable-next-line no-console
        console.warn(`[consentActionSemantics.integration] failed to drop ${TEST_DB_NAME}: ${err.message}`);
      }
      await _maintenancePool.end().catch(() => {});
    }
  }, 60_000);

  // Run 3x with fresh actor_ids per iteration to rule out timing flake and
  // avoid interference between iterations (each grant/verify pair is fully
  // isolated by construction, not by shared cleanup).
  for (let i = 1; i <= 3; i++) {
    test(`[run ${i}/3] documented flow: action = provider string ("openai") is found and ALLOWS`, async () => {
      const actorId = freshActorId(`match-${i}`);

      const record = await registry.grant({
        actor_id:   actorId,
        action:     'openai', // provider string — the corrected docs/api/overview.md example
        tenant_id:  null,
        granted_by: 'consentActionSemantics.integration.test.js',
      });
      expect(record.state).toBe('ACTIVE');

      // Exactly what checkPolicy.js derives for a real /ai/chat request signed
      // with artifact.payload.provider === 'openai'.
      const result = await registry.verify({ actor_id: actorId, action: 'openai', tenant_id: null });

      expect(result.pass).toBe(true);
      expect(result.reason).toBe('CONSENT_VERIFIED');
      expect(result.consentId).toBe(record.id);
    });

    test(`[run ${i}/3] inverse lock-in: action = non-provider name ("ai-chat-execute") is NEVER found (exact-match semantics, not a bug)`, async () => {
      const actorId = freshActorId(`mismatch-${i}`);

      const record = await registry.grant({
        actor_id:   actorId,
        action:     'ai-chat-execute', // the OLD, incorrect docs example — must still fail to enforce
        tenant_id:  null,
        granted_by: 'consentActionSemantics.integration.test.js',
      });
      expect(record.state).toBe('ACTIVE');

      // Same actor_id/tenant_id, but the action /ai/chat would actually derive
      // (the real provider string) does not match what was granted.
      const result = await registry.verify({ actor_id: actorId, action: 'openai', tenant_id: null });

      expect(result.pass).toBe(false);
      expect(result.reason).toBe('CONSENT_NOT_FOUND');
    });
  }
});
