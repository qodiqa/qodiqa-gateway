'use strict';

/**
 * Migration atomicity / crash window.
 *
 * migrate.js applies each migration file's own self-contained SQL (with its
 * own internal BEGIN/COMMIT) and THEN, as a separate subsequent statement,
 * records the applied version + checksum into qodiqa_migrations. Those two
 * writes are not atomic with each other: a process crash between a
 * migration's own COMMIT and migrate.js's tracking INSERT would leave the
 * schema change fully applied but NOT recorded as applied — so a restart
 * would see that migration as still "pending" and re-run its raw SQL
 * content again, for real, against a database where it already fully
 * succeeded.
 *
 * Restructuring all 36 existing migration files so the tracking write is
 * atomic with each migration's own transaction (removing their independent
 * BEGIN/COMMIT) would be a wide-blast-radius change unrelated to's
 * actual scope, touching migration history this WP does not own. Instead,
 * this crash window is accepted as safe BECAUSE every migration file is
 * required to be genuinely idempotent (migrate.js's own header comment:
 * "Idempotent: uses IF NOT EXISTS / ON CONFLICT") — a real re-execution of
 * an already-applied migration's raw SQL must be a safe no-op. This test
 * proves that is actually true for migration 026 specifically — the one
 * migration's distributed mode depends on — rather than asserting it
 * by convention alone. See docs/protocol/AUDIT-SCHEMA-V8.md's
 * Decision Update for the documented acceptance of this window.
 *
 * Requires real PostgreSQL (same gating convention as the other
 * integration tests in this directory). Creates and drops its own
 * uniquely-named scratch database — never touches any pre-existing one.
 */

// phase 17: no .env loading — the PostgreSQL/Redis target and credentials come only from the explicit process env (pl-env.sh / CI); test/support/jest.setup.js refuses an opted-in local run without one (test/guards/testEnvIsolation.guard.test.js).

const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { Pool } = require('pg');

const REAL_PG = process.env.QODIQA_PG_ENABLED === 'true';
const describeOrSkip = REAL_PG ? describe : describe.skip;

const MIGRATIONS_DIR = path.resolve(__dirname, '..', '..', 'src', 'infra', 'postgres', 'migrations');

function connectionConfig(database) {
  return {
    host:     process.env.QODIQA_PG_HOST || 'localhost',
    port:     parseInt(process.env.QODIQA_PG_PORT || '5432', 10),
    database,
    // prefer the dedicated qodiqa_test role (CREATEDB/CREATEROLE/
    // BYPASSRLS) — both CREATE DATABASE and running the full migration set
    // (002/018 require CREATEROLE+BYPASSRLS) need it. Falls back to the
    // pre-existing chain so CI's ephemeral postgres:17-alpine superuser
    // container (QODIQA_PG_USER=qodiqa there) is unaffected.
    user:     process.env.QODIQA_PG_TEST_USER || process.env.QODIQA_PG_USER || 'postgres',
    password: process.env.QODIQA_PG_TEST_PASSWORD || process.env.QODIQA_PG_PASSWORD,
    ssl:      process.env.QODIQA_PG_SSL === 'true' ? { rejectUnauthorized: true } : false,
  };
}

describeOrSkip('remediation — migration 026 idempotency (real PostgreSQL, finding #7)', () => {
  let admin;
  let dbName;
  let target;

  beforeAll(async () => {
    admin = new Pool(connectionConfig(process.env.QODIQA_PG_DATABASE || 'qodiqa'));
    dbName = `qodiqa_migration026_idempotency_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    await admin.query(`CREATE DATABASE ${dbName}`);

    target = new Pool(connectionConfig(dbName));

    // Apply the real, full migration set once, normally — migration 026's
    // pre-flight integrity check requires audit_chain (created earlier in
    // the sequence) to already exist.
    const { runMigrations } = require('../../src/infra/postgres/migrate');
    await runMigrations({ pool: target });
  }, 60000);

  afterAll(async () => {
    if (target) await target.end();
    if (admin && dbName) {
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [dbName],
      ).catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
      await admin.end();
    }
  }, 30000);

  test('migration 026\'s raw SQL content can be re-executed against an already-fully-migrated database with no error', async () => {
    const migration026Path = path.join(MIGRATIONS_DIR, '026_audit_chain_distributed_ordering.sql');
    const migration026Content = fs.readFileSync(migration026Path, 'utf8');

    const before = await target.query('SELECT tail_hash, tail_seq FROM audit_chain_head');
    expect(before.rows).toHaveLength(1);

    // The real crash-window reproduction: run the migration's own raw SQL
    // AGAIN, exactly as migrate.js would if a crash had prevented the
    // tracking-table bookkeeping from recording that it already succeeded.
    await expect(target.query(migration026Content)).resolves.toBeDefined();

    const after = await target.query('SELECT tail_hash, tail_seq FROM audit_chain_head');
    expect(after.rows).toHaveLength(1); // still a singleton — no duplicate/forked row
    expect(after.rows[0].tail_hash).toBe(before.rows[0].tail_hash); // untouched by the re-run
    expect(after.rows[0].tail_seq).toBe(before.rows[0].tail_seq);

    const indexCheck = await target.query(
      `SELECT count(*) AS c FROM pg_indexes WHERE indexname = 'idx_audit_chain_prev_hash_unique'`
    );
    expect(Number(indexCheck.rows[0].c)).toBe(1); // exactly one, not duplicated/erroring
  }, 30000);

  test('every migration file is self-declared idempotent (uses IF NOT EXISTS / ON CONFLICT, per migrate.js\'s documented contract)', () => {
    // A lightweight, repo-wide sanity check for the OTHER 35 files, since
    // the test above only exercises 026 directly against a live database.
    // This does not prove runtime safety the way the test above does — it
    // is a structural spot-check that every migration at least follows the
    // documented idempotency convention, catching an obviously-missing
    // guard rather than a subtle logic error.
    const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => /^\d+_.+\.sql$/.test(f));
    expect(files.length).toBeGreaterThan(0);

    const missingGuard = [];
    for (const f of files) {
      const content = fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8');
      const hasCreateGuard = /CREATE (TABLE|INDEX|UNIQUE INDEX)\s+IF NOT EXISTS/i.test(content)
        || /ON CONFLICT/i.test(content)
        || /DROP .+ IF EXISTS/i.test(content)
        || /ALTER TABLE/i.test(content) // ALTER TABLE ... ADD COLUMN IF NOT EXISTS or similar grant/RLS-only files
        // COMMENT ON (TABLE|COLUMN|...) needs no IF EXISTS guard to be
        // idempotent: it unconditionally overwrites the object's comment
        // metadata (or sets it if unset) and cannot error from being
        // re-run against a database where it already applied — see
        // migration 040's header for the doc-only-fix pattern this covers.
        || /COMMENT ON /i.test(content);
      if (!hasCreateGuard) missingGuard.push(f);
    }

    if (missingGuard.length > 0) {
      throw new Error(
        `${missingGuard.length} migration file(s) have no visible idempotency guard ` +
        `(IF NOT EXISTS / ON CONFLICT / IF EXISTS / ALTER TABLE): ${missingGuard.join(', ')}. ` +
        'Every migration must be safe to re-execute — see this file\'s header comment.'
      );
    }
  });
});
