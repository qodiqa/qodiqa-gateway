'use strict';

/**
 * Regression coverage for NEW-1 (final verification audit):
 * src/infra/postgres/pool.js's withAdvisoryLock() must roll back any
 * dangling transaction state before attempting pg_advisory_unlock, or the
 * unlock is itself rejected (silently, via its own .catch()) by PostgreSQL's
 * "current transaction is aborted, commands ignored until end of
 * transaction block" (SQLSTATE 25P02) — leaving the advisory lock held by
 * the session even after the connection is released back to the pool.
 *
 * Mocks are deliberately NOT used here: the defect is entirely a matter of
 * real PostgreSQL transaction-abort semantics (a mocked pg client has no
 * such state machine to get wrong), so this suite requires a real
 * PostgreSQL connection — same gating convention as the other
 * integration tests in this directory. Creates and drops its own
 * uniquely-named scratch database; never touches any pre-existing one.
 *
 * PLA-01  Success path: lock acquired, callback succeeds, lock released,
 *         connection left clean (a fresh session can immediately acquire
 *         the same key, and a subsequent unrelated query on the pool
 *         succeeds).
 * PLA-02  Failure path: callback throws mid-transaction (BEGIN; <bad
 *         statement>; COMMIT; — the exact shape migrate.js's own migration
 *         files use), withAdvisoryLock rejects with that error, AND the
 *         advisory lock is still fully released — a fresh, independent
 *         session can acquire the same key immediately afterward. This is
 *         the test that fails against the pre-fix implementation (verified
 *         manually during remediation: without the ROLLBACK, the backend is
 *         left in "idle in transaction (aborted)" holding the lock, and
 *         pg_try_advisory_lock from a fresh session returns false) and
 *         passes with it.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { Pool } = require('pg');
const crypto = require('crypto');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

function connectionConfig(database) {
  return {
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database,
    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) for the admin connection that creates/drops this suite's
    // scratch database — falls back to the pre-existing chain so CI's
    // ephemeral postgres:17-alpine superuser container (QODIQA_PG_USER=
    // qodiqa there) is unaffected.
    user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres',
    password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD,
    ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  };
}

// Distinct lock keys per test so PLA-01/PLA-02 can never interfere with each
// other even if run concurrently by a future test-runner change.
const SUCCESS_LOCK_KEY = 700100100;
const FAILURE_LOCK_KEY = 700100200;

describeOrSkip('final remediation — pool.js withAdvisoryLock() transaction-abort recovery (NEW-1)', () => {
  let admin;
  let dbName;
  let pgPool;

  beforeAll(async () => {
    admin = new Pool(connectionConfig(process.env.QODIQA_PG_DATABASE || 'qodiqa'));
    dbName = `qodiqa_advisory_lock_recovery_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);

    process.env.QODIQA_PG_DATABASE = dbName;
    jest.resetModules();
    pgPool = require('../../src/infra/postgres/pool');
    pgPool.initialize();
  }, 30000);

  afterAll(async () => {
    if (pgPool) await pgPool.shutdown();
    if (admin && dbName) {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      ).catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
      await admin.end();
    }
  }, 30000);

  /** A fresh, independent connection — never touched by pgPool itself — for observing real server-side state. */
  async function observe(query, params) {
    const observer = new Pool(connectionConfig(dbName));
    try {
      return await observer.query(query, params);
    } finally {
      await observer.end();
    }
  }

  test('PLA-01 success path: lock acquired, callback succeeds, lock fully released, connection left clean', async () => {
    const result = await pgPool.withAdvisoryLock(SUCCESS_LOCK_KEY, async (client) => {
      const r = await client.query('SELECT 1 AS ok');
      return r.rows[0].ok;
    });
    expect(result).toBe(1);

    // A fresh, independent session must be able to acquire the same key
    // immediately — proves the lock was actually released, not merely that
    // withAdvisoryLock returned.
    const tryLock = await observe('SELECT pg_try_advisory_lock($1) AS could_acquire', [SUCCESS_LOCK_KEY]);
    expect(tryLock.rows[0].could_acquire).toBe(true);
    await observe('SELECT pg_advisory_unlock($1)', [SUCCESS_LOCK_KEY]);

    // The pool itself must still be usable afterward (connection was
    // returned clean, not poisoned).
    const followUp = await pgPool.query('SELECT 2 AS ok', [], 'pla01_followup');
    expect(followUp.rows[0].ok).toBe(2);
  }, 20000);

  test('PLA-02 failure path: callback throws mid-transaction, lock is still fully released (fails without the ROLLBACK fix)', async () => {
    const failingCallback = async (client) => {
      // Exactly the shape a real migration file uses (migrate.js): a
      // self-contained multi-statement string with its own BEGIN/COMMIT.
      // The middle statement fails, leaving the session mid-transaction —
      // there is no application-level catch/rollback inside this callback,
      // matching how migrate.js itself behaves on a bad migration.
      await client.query('BEGIN; SELECT this_function_does_not_exist_xyz(); COMMIT;');
    };

    await expect(
      pgPool.withAdvisoryLock(FAILURE_LOCK_KEY, failingCallback)
    ).rejects.toThrow(/this_function_does_not_exist_xyz/);

    // The critical assertion: a fresh, independent session must be able to
    // acquire the SAME lock key immediately. Against the pre-fix
    // implementation (no ROLLBACK before the unlock attempt), this fails —
    // the connection is left "idle in transaction (aborted)", the unlock
    // attempt is itself silently rejected by PostgreSQL (SQLSTATE 25P02),
    // and the lock remains held by that session indefinitely.
    const tryLock = await observe('SELECT pg_try_advisory_lock($1) AS could_acquire', [FAILURE_LOCK_KEY]);
    expect(tryLock.rows[0].could_acquire).toBe(true);
    await observe('SELECT pg_advisory_unlock($1)', [FAILURE_LOCK_KEY]);

    // Independently confirm the connection itself was returned to the pool
    // in a clean, non-aborted state — the pool must still be able to serve
    // an ordinary query afterward.
    const followUp = await pgPool.query('SELECT 3 AS ok', [], 'pla02_followup');
    expect(followUp.rows[0].ok).toBe(3);

    // And, most directly: observe the actual backend's state via
    // pg_stat_activity — must never be "idle in transaction (aborted)".
    const activity = await observe(`
      SELECT state FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()
    `, [dbName]);
    for (const row of activity.rows) {
      expect(row.state).not.toBe('idle in transaction (aborted)');
    }
  }, 20000);
});
