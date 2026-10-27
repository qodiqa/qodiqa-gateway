'use strict';

/**
 * remediation — real multi-process regression coverage for audit
 * findings #2 (concurrent auto-migrate race) and #4 (missing distributed
 * startup integration tests).
 *
 * Requires real PostgreSQL (same gating convention as
 * test/integration/audit-chain-distributed.integration.test.js) with CREATE DATABASE /
 * DROP DATABASE privilege on the configured connection — true both for a
 * local superuser connection (see this repo's memory: local Postgres uses
 * the `postgres` superuser directly) and for CI's postgres:17-alpine
 * service container (POSTGRES_USER is that container's superuser — see
 * .github/workflows/test.yml).
 *
 * MDR-01  Five real, independent server-process-equivalent workers, started
 *         concurrently against a genuinely virgin (never-migrated) database
 *         with QODIQA_DEPLOYMENT_MODE=distributed + QODIQA_PG_AUTO_MIGRATE=
 *         true, ALL succeed — none crash-loop, none observe a torn/partial
 *         schema — and the resulting database has exactly the same single,
 *         consistent state a single successful run would have produced
 *         (one qodiqa_migrations row per migration — no duplicate/partial
 *         tracking rows a genuine race would produce — and exactly one
 *         audit_chain_head row). This is the real reproduction the
 *         code-review audit asked for: actual OS processes, actual
 *         PostgreSQL, the actual unmocked
 *         src/infra/config/deploymentMode.js -> pool.js ->
 *         multiInstanceGuard.js chain — not mocks standing in for
 *         concurrency. This does NOT separately assert that exactly one
 *         worker was the one to apply the migrations (attributing that
 *         deterministically from outside the lock is inherently racy to
 *         assert on); the property that actually matters and that
 *         withAdvisoryLock() exists to guarantee — no corruption, no crash,
 *         one consistent final state — is what is asserted below. See
 *         src/infra/postgres/__tests__/pool.runMigrations.test.js for a
 *         mocked, deterministic proof that the lock is acquired for the
 *         whole run and released even on failure.
 *
 * Database lifecycle: this suite creates ONE uniquely-named scratch database
 * in beforeAll and drops that exact same database (never any other) in
 * afterAll — standard, expected test hygiene for a suite that specifically
 * needs a disposable, never-migrated database; this is unrelated to (and
 * does not conflict with) the separate practice of never dropping an
 * existing developer/shared database during ad hoc manual validation.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const { fork } = require('child_process');
const path      = require('path');
const crypto    = require('crypto');
const { Pool }  = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const WORKER_PATH = path.resolve(__dirname, '..', 'helpers', 'audit-chain-distributed-migration-worker.js');
const NUM_WORKERS = 5;

function adminPool() {
  return new Pool({
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database: process.env.QODIQA_PG_DATABASE || 'qodiqa',
    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) for CREATE DATABASE — falls back to the pre-existing chain
    // so CI's ephemeral postgres:17-alpine superuser container
    // (QODIQA_PG_USER=qodiqa there) is unaffected.
    user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres',
    password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD,
    ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  });
}

/**
 * Spawns one worker as a real child process, resolving with its parsed
 * final stdout JSON line and exit code. A worker that FATAL-exits from
 * inside checkDistributedPreconditions() never prints its own success line
 * — that shows up here as `result: null, code: 1`, which callers treat as
 * a failure exactly like a parsed `{ ok: false }`.
 */
function spawnMigrationWorker(env) {
  return new Promise((resolve) => {
    const proc = fork(WORKER_PATH, [], {
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      env,
    });

    let stdout = '';
    proc.stdout.on('data', (chunk) => { stdout += chunk.toString('utf8'); });
    const stderrChunks = [];
    proc.stderr.on('data', (chunk) => stderrChunks.push(chunk));

    let exitCode = null;
    proc.on('exit', (code) => { exitCode = code; });
    // 'close' (not 'exit') — fires only once stdout/stderr have both been
    // fully flushed and closed. 'exit' can fire first, before the child's
    // final stdout.write() chunk has finished being delivered to this
    // process, which non-deterministically truncated the last JSON line.
    proc.on('close', () => {
      let result = null;
      // Search for the WORKER_RESULT: tagged line specifically, not just
      // "the last line" — the worker's own production code path emits
      // ordinary structured log lines (services/logger.js's emit(), e.g.
      // pgPool.shutdown()'s PG_POOL_SHUTDOWN event) to the same stdout both
      // before AND after the tagged result line.
      const resultLine = stdout.split('\n').reverse().find(l => l.startsWith('WORKER_RESULT:'));
      if (resultLine) {
        try { result = JSON.parse(resultLine.slice('WORKER_RESULT:'.length)); } catch { /* leave null */ }
      }
      resolve({ code: exitCode, result, stderr: Buffer.concat(stderrChunks).toString('utf8') });
    });
  });
}

describeOrSkip('remediation — concurrent distributed-mode auto-migrate (real multi-process)', () => {
  let admin;
  let dbName;

  beforeAll(async () => {
    admin = adminPool();
    dbName = `qodiqa_migration_race_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
  }, 30000);

  afterAll(async () => {
    if (admin && dbName) {
      // Terminate any lingering connections to the scratch database before
      // dropping it — a worker that already exited should have closed its
      // pool via pgPool.shutdown(), but this is defensive.
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      ).catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
    }
    if (admin) await admin.end();
  }, 30000);

  test('MDR-01/02: 5 concurrent workers against a virgin database all succeed with one consistent final schema', async () => {
    const workerEnv = {
      ...process.env,
      QODIQA_PG_DATABASE: dbName,
      // each worker auto-migrates this virgin database itself (that's
      // the race under test), which requires CREATEROLE+BYPASSRLS (migrations
      // 002/018) — override to the dedicated qodiqa_test role rather than
      // whatever ambient QODIQA_PG_USER the parent process inherited (e.g.
      // the low-privilege qodiqa_app from a local .env). No-op in CI, where
      // QODIQA_PG_TEST_USER isn't set and the ambient user is already the
      // ephemeral container's superuser.
      QODIQA_PG_USER: process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER,
      QODIQA_PG_PASSWORD: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD,
      // Each worker sets QODIQA_DEPLOYMENT_MODE/QODIQA_PG_AUTO_MIGRATE itself
      // (see the worker file) — cleared here so the worker's own resolution
      // is exercised fresh, not inherited from this test process.
      QODIQA_DEPLOYMENT_MODE: '',
      QODIQA_PG_AUTO_MIGRATE: '',
    };

    const outcomes = await Promise.all(
      Array.from({ length: NUM_WORKERS }, () => spawnMigrationWorker(workerEnv))
    );

    for (const [i, outcome] of outcomes.entries()) {
      if (outcome.code !== 0) {
        throw new Error(`worker ${i} exited with code ${outcome.code}, stderr: ${outcome.stderr}`);
      }
    }
    expect(outcomes.every(o => o.result?.ok === true)).toBe(true);

    // ── Final schema state must be exactly what one successful run produces ──
    const target = new Pool({
      host:     process.env.QODIQA_PG_HOST || 'localhost',
      port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
      database: dbName,
      user:     process.env.QODIQA_PG_USER || 'postgres',
      password: process.env.QODIQA_PG_PASSWORD,
      ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
    });
    try {
      const migrationRows = await target.query('SELECT version FROM qodiqa_migrations WHERE version = 26');
      expect(migrationRows.rows).toHaveLength(1); // no duplicate/corrupted tracking row

      const headRows = await target.query('SELECT count(*) AS c FROM audit_chain_head');
      expect(Number(headRows.rows[0].c)).toBe(1); // singleton row, never forked/duplicated

      // Every migration file on disk must be recorded exactly once.
      const fs = require('fs');
      const migrationsDir = path.resolve(__dirname, '..', '..', 'src', 'infra', 'postgres', 'migrations');
      const fileCount = fs.readdirSync(migrationsDir).filter(f => /^\d+_.+\.sql$/.test(f)).length;
      const allApplied = await target.query('SELECT count(*) AS c FROM qodiqa_migrations');
      expect(Number(allApplied.rows[0].c)).toBe(fileCount);
    } finally {
      await target.end();
    }
  }, 60000);
});
