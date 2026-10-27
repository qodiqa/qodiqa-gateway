'use strict';

/**
 * QODIQA PostgreSQL Migration Runner
 *
 * Idempotent, transactional schema migration tool.
 *
 * Usage:
 *   node src/infra/postgres/migrate.js            # run pending migrations
 *   node src/infra/postgres/migrate.js --status   # show migration status
 *   node src/infra/postgres/migrate.js --dry-run  # show what would run
 *
 * Each migration file in migrations/ is:
 *   - Named: NNN_description.sql  (NNN = zero-padded integer)
 *   - Idempotent: uses IF NOT EXISTS / ON CONFLICT
 *   - Transactional: wrapped in BEGIN/COMMIT
 *   - Checksummed: SHA-256 of file content stored in qodiqa_migrations
 *
 * If a migration file's checksum changes after being applied, the runner
 * aborts — this prevents accidental mutation of applied migrations.
 *
 * Checksums are computed over CRLF/CR-normalized-to-LF content, not raw file
 * bytes: migration files are committed to git as LF, but a checkout with
 * core.autocrlf=true (the common default on Windows) rewrites them to CRLF on
 * disk. Hashing raw bytes would make the integrity check fire on every
 * migration for every Windows contributor, indistinguishable from a genuine
 * edit to an applied migration. Normalizing first makes the checksum reflect
 * logical SQL content, matching what's actually version-controlled.
 *
 * Connects using its own dedicated identity, deliberately not shared with
 * pool.js's request-serving connection:
 *   QODIQA_PG_MIG_USER      — Username (default 'qodiqa_mig')
 *   QODIQA_PG_MIG_PASSWORD  — Password (falls back to QODIQA_PG_PASSWORD if
 *                              unset, for environments that haven't
 *                              provisioned a distinct migration credential)
 *   QODIQA_PG_MIG_LOCK_TIMEOUT_MS — CLI path only: lock_timeout per migration
 *                              session (default 30000; 0 disables). The CLI
 *                              also holds pool.js's migration advisory lock
 * for the whole run.
 * pool.js's QODIQA_PG_USER/QODIQA_PG_PASSWORD are never read here — the
 * schema-modifying migration role and the request-serving application role
 * are intentionally distinct identities (migration 002 creates qodiqa_mig
 * with CREATE-on-schema/DDL rights that qodiqa_app does not have).
 */

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const { emit } = require('../../../services/logger');
const { resolvePgSslOptions } = require('./pgSsl');

const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

// ── File helpers ──────────────────────────────────────────────────────────────

function _sha256(content) {
  const normalized = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

function _loadMigrationFiles() {
  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => /^\d+_.+\.sql$/.test(f))
    .sort();  // lexicographic sort preserves NNN ordering

  return files.map(f => {
    const versionStr = f.split('_')[0];
    const version    = parseInt(versionStr, 10);
    const content    = fs.readFileSync(path.join(MIGRATIONS_DIR, f), 'utf8');
    return {
      version,
      name:     f.replace(/^\d+_/, '').replace(/\.sql$/, ''),
      filename: f,
      content,
      checksum: _sha256(content),
    };
  });
}

// OPS-01 (D1, loud-default option): migrations 001/002/018 structurally
// require a superuser (or the documented qodiqa_test bootstrap role) on a
// genuinely fresh cluster — qodiqa_mig doesn't exist until 002 creates it,
// and cannot self-grant BYPASSRLS at 018 (PostgreSQL only lets a role
// already holding BYPASSRLS grant it to another; CREATEROLE alone is not
// enough). See docs/operations/database-role-management.md. Detection is
// intentionally narrow — SQLSTATE 42501 (insufficient_privilege) AND the
// failing migration's own SQL contains a role-management statement — so an
// unrelated permission error (e.g. a missing table grant) is never
// misreported as this specific, well-understood bootstrap gap.
const ROLE_DDL_PATTERN = /\b(ALTER|CREATE|DROP)\s+ROLE\b/i;

// a second, structurally identical bootstrap-sequencing gap, same
// root cause (an object created before qodiqa_mig existed, so qodiqa_mig
// isn't its owner) but reachable via several different SQL shapes — not
// just ALTER TABLE, but any DDL PostgreSQL requires ownership (not just a
// GRANT) for: CREATE INDEX, ALTER TABLE ... OWNER TO, DROP INDEX, and more.
// Reproduced live: migrations 021 (CREATE INDEX ... ON audit_chain) and 039
// (ALTER TABLE audit_chain ADD COLUMN) both fail this way under the
// documented qodiqa_mig identity, against one of the 12 tables migration
// 001 creates before qodiqa_mig exists, until migration 055 transfers
// ownership. Deliberately matched on the PostgreSQL error message text
// ALONE, not a specific statement keyword in the migration's own content —
// "must be owner of relation/table/index/sequence X" is PostgreSQL's fixed,
// narrow wording for exactly this ownership-check failure class (never used
// for an unrelated permission error), so no additional content-pattern
// filter is needed to keep this narrow; an earlier version of this
// detection required ALSO matching ALTER TABLE/OWNER TO in the migration's
// SQL and silently missed the CREATE INDEX case (021) as a result — see
//
const OWNERSHIP_ERROR_PATTERN = /must be owner of/i;

function _wrapRolePrivilegeError(err, migration) {
  const isRoleDdlGap = err.code === '42501' && ROLE_DDL_PATTERN.test(migration.content);
  const isOwnershipGap = OWNERSHIP_ERROR_PATTERN.test(err.message);
  if (!isRoleDdlGap && !isOwnershipGap) {
    return err;
  }
  const connectedAs = process.env.QODIQA_PG_MIG_USER || 'qodiqa_mig';
  const message = isRoleDdlGap
    ? `PG_MIGRATE_ROLE_PRIVILEGE_DENIED: migration ${migration.version} (${migration.filename}) failed ` +
      `with insufficient privilege (SQLSTATE 42501) while running a role-management statement ` +
      `(CREATE/ALTER/DROP ROLE), connected as "${connectedAs}". This is expected on a genuinely fresh ` +
      `PostgreSQL cluster: role creation and privilege-attribute grants (e.g. BYPASSRLS) require a ` +
      `superuser or the documented "qodiqa_test" bootstrap role — the default migration identity never ` +
      `has this by design. Remedy: re-run this command with QODIQA_PG_MIG_USER set to a superuser (or ` +
      `qodiqa_test, once bootstrapped), e.g. ` +
      `"QODIQA_PG_MIG_USER=<superuser> QODIQA_PG_MIG_PASSWORD=<password> node src/infra/postgres/migrate.js", ` +
      `then continue with the default QODIQA_PG_MIG_USER for subsequent runs. See ` +
      `docs/operations/database-role-management.md ("Fresh-container bootstrap sequencing" and ` +
      `"Documented operator bootstrap exception") for the full explanation. Original error: ${err.message}`
    : `PG_MIGRATE_ROLE_PRIVILEGE_DENIED: migration ${migration.version} (${migration.filename}) failed ` +
      `with an ownership check (${err.message}), connected as "${connectedAs}". This means the target ` +
      `object was created before qodiqa_mig existed (or before migration 055 transferred ownership) and ` +
      `is still owned by whatever bootstrap identity created it — a GRANT does not confer the right to ` +
      `ALTER an object's structure, only ownership (or superuser) does. Remedy: re-run this command with ` +
      `QODIQA_PG_MIG_USER set to a superuser (or qodiqa_test, once bootstrapped), e.g. ` +
      `"QODIQA_PG_MIG_USER=<superuser> QODIQA_PG_MIG_PASSWORD=<password> node src/infra/postgres/migrate.js", ` +
      `then continue with the default QODIQA_PG_MIG_USER for subsequent runs. See ` +
      `docs/operations/database-role-management.md ("Fresh-container bootstrap sequencing") and migration ` +
      `055_mig_table_ownership_transfer.sql for the full explanation. Original error: ${err.message}`;
  emit('FATAL', 'PG_MIGRATE_ROLE_PRIVILEGE_DENIED', {
    version: migration.version, filename: migration.filename, connectedAs, message,
  });
  /** @type {any} */ const loud = new Error(message);
  loud.qodiqaRolePrivilegeGap = true;
  loud.cause = err;
  return loud;
}

// ── Operator-run safety ─────
//
// The same reserved advisory lock key as pool.js's MIGRATION_ADVISORY_LOCK_KEY (pinned equal by
// migrateCliSafety.test.js): the operator CLI path below takes it too, so a CLI run and a server
// auto-migrate (pool.runMigrations → withAdvisoryLock) can never apply DDL concurrently. Before this, a
// second concurrent CLI runner raced the first and failed mid-migration on a duplicate-key error.
const MIGRATION_ADVISORY_LOCK_KEY = 946812026;

// lock_timeout for the operator CLI path, set AFTER the advisory lock is held (waiting behind another
// migrator stays unbounded, as on the server path). Without it, a live writer holding a lock on e.g.
// audit_chain made migration 059 (CREATE INDEX) / 073 (LOCK TABLE) wait indefinitely while itself
// queueing every later writer behind it. Default 30 s; 0 disables; must be a non-negative integer (ms).
const DEFAULT_MIG_LOCK_TIMEOUT_MS = 30000;
function _migrationLockTimeoutMs(env = process.env) {
  const raw = env.QODIQA_PG_MIG_LOCK_TIMEOUT_MS;
  if (raw === undefined || raw === '') return DEFAULT_MIG_LOCK_TIMEOUT_MS;
  if (!/^\d+$/.test(String(raw).trim())) {
    throw new Error(`QODIQA_PG_MIG_LOCK_TIMEOUT_MS must be a non-negative integer number of milliseconds (0 disables); got "${raw}"`);
  }
  return Number(String(raw).trim());
}

// ── Migration runner ──────────────────────────────────────────────────────────

// the ONE operator-CLI pool factory, shared by runMigrations() and showStatus() so --status can never again
// drift from the migrate path (it previously omitted the port — OA3-F1 — and then TLS and the guard).
function _createCliPool(env = process.env) {
  const pool = new Pool({
    connectionString: env.QODIQA_PG_URL,
    host:     env.QODIQA_PG_HOST     || 'localhost',
    port:     parseInt(env.QODIQA_PG_PORT || '5432', 10),
    database: env.QODIQA_PG_DATABASE  || 'qodiqa',
    user:     env.QODIQA_PG_MIG_USER   || 'qodiqa_mig',
    password: env.QODIQA_PG_MIG_PASSWORD || env.QODIQA_PG_PASSWORD,
    // D-D: same TLS resolution as pool.js (on by default in production).
    ssl:      resolvePgSslOptions(env),
  });
  require('./clientErrorGuard').guardPool(pool, 'migrate'); // a client error must not crash the process
  return pool;
}

/** @param {{ dryRun?: boolean, pool?: any }} [opts] */
async function runMigrations({ dryRun = false, pool } = {}) {
  const ownPool = !pool;
  if (!pool) {
    pool = _createCliPool(process.env);
  }

  // When an external pool is supplied, every query below goes through
  // pool.query() (which checks out and releases its own connection per
  // call) — a separate client is neither used nor released in that case,
  // so only acquire one when this function owns (and must later close)
  // the pool itself.
  const lockTimeoutMs = ownPool ? _migrationLockTimeoutMs() : null; // validate before connecting
  const client = ownPool ? await pool.connect() : null;
  let advisoryLockHeld = false;

  try {
    if (ownPool) {
      // Operator CLI path only. An injected pool (server auto-migrate) is already serialised by
      // pool.runMigrations()'s withAdvisoryLock on the same key; it manages its own session settings.
      await client.query('SELECT pg_advisory_lock($1::bigint)', [MIGRATION_ADVISORY_LOCK_KEY]);
      advisoryLockHeld = true;
      await client.query(`SET lock_timeout = ${lockTimeoutMs}`); // integer, validated above
      emit('INFO', 'PG_MIGRATE_LOCK_ACQUIRED', { lockKey: MIGRATION_ADVISORY_LOCK_KEY, lockTimeoutMs });
    }

    // Ensure migration tracking table exists (bootstraps itself)
    await (ownPool ? client : pool).query(`
      CREATE TABLE IF NOT EXISTS qodiqa_migrations (
        id         SERIAL PRIMARY KEY,
        version    INTEGER      NOT NULL UNIQUE,
        name       VARCHAR(256) NOT NULL,
        applied_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        checksum   CHAR(64)     NOT NULL,
        applied_by VARCHAR(128) NOT NULL DEFAULT current_user
      )
    `);

    // Load applied migrations from DB
    const appliedResult = await (ownPool ? client : pool).query(
      'SELECT version, name, checksum FROM qodiqa_migrations ORDER BY version'
    );
    const applied = new Map(appliedResult.rows.map(r => [r.version, r]));

    // Load migration files from disk
    const files = _loadMigrationFiles();

    // Integrity check: verify checksums of already-applied migrations
    for (const file of files) {
      const existing = applied.get(file.version);
      if (existing && existing.checksum !== 'PLACEHOLDER_CHECKSUM' &&
          existing.checksum !== file.checksum) {
        throw new Error(
          `Migration integrity violation: version ${file.version} (${file.filename}) ` +
          `checksum changed after application. ` +
          `DB: ${existing.checksum}, File: ${file.checksum}. ` +
          `Do NOT modify applied migrations.`
        );
      }
    }

    // Find pending migrations
    const pending = files.filter(f => !applied.has(f.version));

    if (pending.length === 0) {
      emit('INFO', 'PG_MIGRATE_UP_TO_DATE', { appliedCount: applied.size });
      return { applied: [], skipped: files.length };
    }

    emit('INFO', 'PG_MIGRATE_PENDING', { count: pending.length });

    const appliedNow = [];
    for (const migration of pending) {
      emit('INFO', 'PG_MIGRATE_APPLYING', { version: migration.version, name: migration.name });

      if (dryRun) {
        appliedNow.push({ ...migration, dryRun: true });
        continue;
      }

      // Run the migration SQL as-is (it must be self-contained with BEGIN/COMMIT)
      try {
        await (ownPool ? client : pool).query(migration.content);
      } catch (err) {
        throw _wrapRolePrivilegeError(err, migration);
      }

      // Record in tracking table (upsert for idempotency)
      await (ownPool ? client : pool).query(`
        INSERT INTO qodiqa_migrations (version, name, checksum)
        VALUES ($1, $2, $3)
        ON CONFLICT (version) DO UPDATE SET checksum = EXCLUDED.checksum
      `, [migration.version, migration.name, migration.checksum]);

      emit('INFO', 'PG_MIGRATE_APPLIED', { version: migration.version, name: migration.name });
      appliedNow.push(migration);
    }

    return { applied: appliedNow, skipped: applied.size };
  } finally {
    if (ownPool) {
      if (advisoryLockHeld) {
        // A failed migration leaves the session in an aborted transaction; roll back first so the unlock
        // can run (closing the session below would release the lock regardless).
        await client.query('ROLLBACK').catch(() => {});
        await client.query('SELECT pg_advisory_unlock($1::bigint)', [MIGRATION_ADVISORY_LOCK_KEY]).catch(() => {});
      }
      client.release?.();
      await pool.end().catch(() => {});
    }
  }
}

async function showStatus() {
  // OA3-F1: the port was missing here, so --status silently queried the cluster on 5432 whatever
  // QODIQA_PG_PORT said. it also ignored TLS (QODIQA_PG_SSL*, on by default in production) and lacked the
  // client-error guard. Now built by the same factory as the migrate path.
  const pool = _createCliPool(process.env);

  try {
    const files   = _loadMigrationFiles();
    const applied = await pool.query('SELECT version, name, applied_at FROM qodiqa_migrations ORDER BY version');
    const appliedSet = new Set(applied.rows.map(r => r.version));

    console.log('\nQODIQA Migration Status\n' + '─'.repeat(60));
    for (const f of files) {
      const status = appliedSet.has(f.version) ? '✓ APPLIED  ' : '○ PENDING  ';
      const row    = applied.rows.find(r => r.version === f.version);
      const date   = row ? row.applied_at.toISOString().slice(0, 19) : '          ';
      console.log(`${status}  v${String(f.version).padStart(3, '0')}  ${date}  ${f.name}`);
    }
    console.log('─'.repeat(60));
    console.log(`Applied: ${applied.rows.length} / ${files.length} migrations\n`);
  } finally {
    await pool.end();
  }
}

// ── CLI entry point ───────────────────────────────────────────────────────────

if (require.main === module) {
  const args    = process.argv.slice(2);
  const dryRun  = args.includes('--dry-run');
  const status  = args.includes('--status');

  if (status) {
    showStatus().catch(e => { console.error(e); process.exit(1); });
  } else {
    runMigrations({ dryRun }).then(result => {
      if (dryRun) {
        console.log('DRY RUN — would apply:', result.applied.map(m => m.filename));
      } else {
        console.log('Migration complete. Applied:', result.applied.length);
      }
      process.exit(0);
    }).catch(e => {
      console.error('Migration FAILED:', e.message);
      process.exit(1);
    });
  }
}

module.exports = { runMigrations, showStatus, _createCliPool, _sha256, _migrationLockTimeoutMs, MIGRATION_ADVISORY_LOCK_KEY };
