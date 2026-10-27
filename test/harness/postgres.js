'use strict';

/**
 * Acceptance-test PostgreSQL database manager.
 *
 * No Docker: this repo's migrations (src/infra/postgres/migrations/002_
 * security_hardening.sql, 018_rls_tenant_isolation.sql) require an actual
 * Postgres SUPERUSER connection to run to completion — CREATE ROLE and
 * ALTER ROLE ... BYPASSRLS are both reserved operations only a superuser
 * may ever perform, no matter what other privileges a role holds. That
 * migration therefore runs exactly ONCE, out-of-band, against a local
 * Postgres 17 install ("Postgres
 * acceptance database setup", for the one-time bootstrap). This module
 * never touches the superuser again.
 *
 * From then on, the "qodiqa" database is PERSISTENT, not recreated per
 * run — every acceptance test that needs Postgres gets a clean slate via
 * TRUNCATE (run as qodiqa_mig, which has BYPASSRLS + ALL-privileges from
 * the one-time migration), never a DROP/CREATE DATABASE cycle. This is
 * still fully "automatically provisioned / automatically cleaned /
 * deterministic / reusable" per the requirement — it just achieves
 * isolation via table-level cleanup rather than database-level teardown,
 * which is both faster and avoids ever needing superuser access again.
 *
 * Credentials: qodiqa_mig's password is generated once during the local
 * bootstrap and stored in the gitignored test/acceptance/.local/
 * postgres-mig-role.json (or provided via QODIQA_ACCEPTANCE_PG_MIG_*
 * env vars in CI, set by .github/workflows/acceptance.yml against a
 * fresh-per-run service container). qodiqa_app's password is the fixed
 * placeholder migration 002 assigns on creation
 * ('REPLACE_WITH_VAULT_SECRET_APP') — acceptable because every table it
 * can reach is truncated between every acceptance run; it is never a
 * value used outside this throwaway local/CI database.
 */

const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const ACCEPTANCE_ROOT = path.join(__dirname, '..');
const CREDS_PATH = path.join(ACCEPTANCE_ROOT, '.local', 'postgres-mig-role.json');
// REL-01: this helper TRUNCATEs every table of the database it is pointed
// at. It used to be hard-wired to "qodiqa" — the LIVE database's name on the development machine — so a run against a
// fully-migrated LIVE database would have wiped it (it was spared on 2026-10-04 only because LIVE sat at 057 and the
// "fully migrated" check failed first). The acceptance database now has its own name, and "qodiqa" is refused outright.
const LIVE_DB_NAME = 'qodiqa';
const ACCEPTANCE_DB_PATTERN = /^qodiqa_acceptance(_[a-z0-9_]+)?$/;
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);
const DB_NAME = process.env.QODIQA_ACCEPTANCE_PG_DATABASE || 'qodiqa_acceptance';

// Placeholder password migration 002_security_hardening.sql assigns to
// qodiqa_app on creation — acceptable only because every table qodiqa_app
// can reach is truncated between every acceptance run (see module comment).
// On a machine whose role passwords have been rotated per
// docs/operations/database-role-management.md (mandatory since the
// 2026-08-25 machine migration), the placeholder no longer authenticates —
// QODIQA_ACCEPTANCE_PG_APP_PASSWORD overrides it, mirroring the existing
// QODIQA_ACCEPTANCE_PG_MIG_* env-var path CI already uses for qodiqa_mig.
const APP_PLACEHOLDER_PASSWORD = 'REPLACE_WITH_VAULT_SECRET_APP';

function resolveMigCredentials() {
  if (process.env.QODIQA_ACCEPTANCE_PG_MIG_PASSWORD) {
    return {
      host: process.env.QODIQA_ACCEPTANCE_PG_HOST || 'localhost',
      port: parseInt(process.env.QODIQA_ACCEPTANCE_PG_PORT || '5432', 10),
      user: process.env.QODIQA_ACCEPTANCE_PG_MIG_USER || 'qodiqa_mig',
      password: process.env.QODIQA_ACCEPTANCE_PG_MIG_PASSWORD,
    };
  }
  if (fs.existsSync(CREDS_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(CREDS_PATH, 'utf8'));
    } catch {
      return null;
    }
  }
  return null;
}

async function withDbClient(creds, database, fn) {
  const client = new Client({
    host: creds.host,
    port: creds.port,
    user: creds.user,
    password: creds.password,
    database,
  });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

/**
 * Truncates every user table qodiqa_mig actually has TRUNCATE privilege on
 * (except the migration tracking table itself), cascading to dependent
 * rows. Runs as qodiqa_mig (BYPASSRLS from the one-time migration, so RLS
 * never blocks the cleanup regardless of which tenant context last wrote a
 * row). Tables it lacks privilege on are skipped rather than failing the
 * whole cleanup — e.g. a handful of tables created by later migrations
 * that only grant qodiqa_app/qodiqa_read are simply not ones any
 * acceptance test currently needs cleaned; this keeps the helper robust
 * against that without requiring a superuser fix-up for every such gap.
 */
// Migration-seeded singleton rows (head pointers / scanner-verifier state)
// that the cleanup below wipes along with everything else. The chain writers
// REQUIRE these rows to exist — registrar.js derives previousEntryHash from
// transparency_log_head via SELECT ... FOR UPDATE and never INSERTs (042's
// documented contract), so a missing head row silently turns every append
// into a GENESIS entry and chain validation then fails on the second entry
// ("expected prev_hash=..., stored=null" — found live by AT-076, 2026-08-25).
// Each statement is copied verbatim from its migration (019/026/031/042);
// with the tables freshly emptied they reproduce the pristine seeded state.
const SEEDED_SINGLETON_RESEEDS = [
  `INSERT INTO gap_scanner_state (id) VALUES (1) ON CONFLICT DO NOTHING`,
  `INSERT INTO audit_chain_verifier_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`,
  `INSERT INTO audit_chain_head (id, tail_hash, tail_seq)
   SELECT TRUE,
     COALESCE((SELECT hash FROM audit_chain ORDER BY seq DESC LIMIT 1), 'GENESIS'),
     COALESCE((SELECT seq  FROM audit_chain ORDER BY seq DESC LIMIT 1), 0)
   ON CONFLICT (id) DO NOTHING`,
  `INSERT INTO evidence_chain_head (id, tail_hash, tail_id)
   SELECT TRUE,
     (SELECT evidence_hash FROM evidence_chain_records ORDER BY id DESC LIMIT 1),
     COALESCE((SELECT id FROM evidence_chain_records ORDER BY id DESC LIMIT 1), 0)
   ON CONFLICT (id) DO NOTHING`,
  `INSERT INTO transparency_log_head (id, tail_hash, tail_id)
   SELECT TRUE,
     (SELECT entry_hash FROM transparency_log_entries ORDER BY id DESC LIMIT 1),
     COALESCE((SELECT id FROM transparency_log_entries ORDER BY id DESC LIMIT 1), 0)
   ON CONFLICT (id) DO NOTHING`,
  `INSERT INTO transparency_roots_head (id, tail_hash, tail_id)
   SELECT TRUE,
     (SELECT root_hash FROM transparency_roots ORDER BY id DESC LIMIT 1),
     COALESCE((SELECT id FROM transparency_roots ORDER BY id DESC LIMIT 1), 0)
   ON CONFLICT (id) DO NOTHING`,
];

async function _reseedSingletons(client) {
  for (const sql of SEEDED_SINGLETON_RESEEDS) {
    try {
      await client.query(sql);
    } catch {
      // table absent on an older schema — nothing to re-seed; skip, matching
      // the tolerant per-table style of the cleanup itself.
    }
  }
}

async function truncateAllTables(creds) {
  await withDbClient(creds, DB_NAME, async (client) => {
    const { rows } = await client.query(`
      SELECT tablename FROM pg_tables
      WHERE schemaname = 'public' AND tablename <> 'qodiqa_migrations'
    `);
    if (rows.length === 0) return;
    // DB-05 (migration 076): the audit tables refuse cleanup without a declared maintenance intent. This is the
    // acceptance harness resetting its own qodiqa_acceptance database (REL-01 allowlist), i.e. a fixture reset.
    await client.query("SET qodiqa.audit_maintenance = 'fixture'");

    // Truncate all-at-once first (fast path; succeeds whenever qodiqa_mig
    // has privilege on every table). Falls back to one-by-one only if
    // that fails, so a handful of tables created by later migrations that
    // only grant qodiqa_app/qodiqa_read (and that no acceptance test
    // currently needs cleaned) don't block cleanup of everything else.
    const tableList = rows.map((r) => `"${r.tablename}"`).join(', ');
    try {
      await client.query(`TRUNCATE ${tableList} RESTART IDENTITY CASCADE`);
      await _reseedSingletons(client);
      return;
    } catch {
      // fall through to per-table cleanup below
    }

    const skipped = [];
    for (const { tablename } of rows) {
      try {
        await client.query(`TRUNCATE "${tablename}" RESTART IDENTITY CASCADE`);
      } catch {
        skipped.push(tablename);
      }
    }
    // ECS: a table this role cannot truncate is only harmless while it is EMPTY. A skipped table that
    // still holds rows leaks state into the next case (seen: AT-053's revoked consent made AT-054/057/058 fail when
    // the cleanup ran as qodiqa_mig, which has no privilege on the qodiqa_test-owned consent tables) — fail loudly.
    // audit_chain_mirror_count (migration 073) is a derived singleton counter that refuses TRUNCATE by design and is
    // maintained by audit_chain's own triggers (the audit_chain TRUNCATE above resets it) — structural, not case state.
    const STRUCTURAL = new Set(['audit_chain_mirror_count']);
    const dirty = [];
    for (const t of skipped.filter((x) => !STRUCTURAL.has(x))) {
      try {
        const r = await client.query(`SELECT EXISTS (SELECT 1 FROM "${t}") AS has_rows`);
        if (r.rows[0].has_rows) dirty.push(t);
      } catch { /* not even readable by this role: nothing it could have left behind either */ }
    }
    if (dirty.length) {
      throw new Error(`acceptance cleanup could not clear ${dirty.join(', ')} (no TRUNCATE privilege for ${creds.user}); ` +
        'run with QODIQA_ACCEPTANCE_PG_MIG_USER / _PASSWORD set to the role that owns the acceptance tables');
    }
    await _reseedSingletons(client);
  });
}

/**
 * Verifies the persistent "qodiqa" database exists and has every migration
 * applied — this should already be true after the one-time bootstrap and
 * is never created/migrated by this function itself (see module comment).
 */
async function verifyProvisioned(creds) {
  const migrationCount = await withDbClient(creds, DB_NAME, async (client) => {
    const { rows } = await client.query(
      "SELECT to_regclass('public.qodiqa_migrations') AS reg",
    );
    if (!rows[0].reg) return 0;
    const result = await client.query('SELECT COUNT(*) AS n FROM qodiqa_migrations');
    return parseInt(result.rows[0].n, 10);
  });
  const expected = fs
    .readdirSync(path.join(ACCEPTANCE_ROOT, '..', '..', 'src', 'infra', 'postgres', 'migrations'))
    .filter((f) => /^\d+_.+\.sql$/.test(f)).length;
  return migrationCount >= expected;
}

/**
 * Provides a clean, fully-migrated "qodiqa" database for one acceptance
 * test: truncates every table up front (so a prior run's data, or a crash
 * that skipped teardown, never leaks in), and truncates again at stop().
 *
 * @returns {Promise<{ available: true, host, port, database, appUser, appPassword, stop: () => Promise<void> } | { available: false, reason: string }>}
 */
async function startDisposableDatabase() {
  // a positive allowlist, not a one-name denylist — only a database NAMED as an acceptance target may be
  // truncated, and only on this machine unless CI says otherwise.
  if (DB_NAME === LIVE_DB_NAME || !ACCEPTANCE_DB_PATTERN.test(DB_NAME)) {
    return {
      available: false,
      reason: `REL-01: refusing to use the "${DB_NAME}" database for acceptance — this helper truncates every table ` +
        'of its target, so the name must match ' + ACCEPTANCE_DB_PATTERN + ' (default "qodiqa_acceptance"; never "qodiqa").',
    };
  }
  const creds = resolveMigCredentials();
  if (creds && !LOOPBACK_HOSTS.has(String(creds.host || 'localhost').toLowerCase()) && process.env.CI !== 'true') {
    return {
      available: false,
      reason: `REL-01: refusing to truncate a database on non-loopback host "${creds.host}" outside CI (CI=true).`,
    };
  }
  // phase 17: on the development machine 5432 is the cluster hosting LIVE (the .local credentials file names
  // exactly that, localhost:5432); acceptance may only truncate a database on a DISPOSABLE cluster there — name it with
  // QODIQA_ACCEPTANCE_PG_HOST/PORT. CI (CI=true, an ephemeral service container on 5432) is exempt.
  // eslint-disable-next-line global-require
  const liveGuard = require('../helpers/liveEndpointGuard');
  if (creds && !liveGuard.isExempt(process.env) && liveGuard.isLiveEndpoint(creds.host || 'localhost', creds.port || 5432)) {
    return {
      available: false,
      reason: `phase 17: refusing the acceptance database on ${creds.host || 'localhost'}:${creds.port || 5432} — a ` +
        'LIVE port on this machine. Point QODIQA_ACCEPTANCE_PG_HOST/PORT (+ _MIG_USER/_MIG_PASSWORD) at a disposable cluster.',
    };
  }
  if (!creds) {
    return {
      available: false,
      reason: 'No qodiqa_mig credentials found (neither QODIQA_ACCEPTANCE_PG_MIG_PASSWORD nor ' +
        `${path.relative(ACCEPTANCE_ROOT, CREDS_PATH)} exist). Run the one-time local bootstrap of the acceptance database first.`,
    };
  }

  try {
    const ready = await verifyProvisioned(creds);
    if (!ready) {
      return {
        available: false,
        reason: `The "${DB_NAME}" database exists but is missing one or more migrations. Re-run the ` +
          'one-time bootstrap of the acceptance database to complete it (requires the Postgres ' +
          'superuser — see src/infra/postgres/migrations/002_security_hardening.sql and 018_rls_' +
          'tenant_isolation.sql, both of which require superuser-only operations).',
      };
    }
    await truncateAllTables(creds);
  } catch (err) {
    return { available: false, reason: err.message };
  }

  return {
    available: true,
    host: creds.host,
    port: creds.port,
    database: DB_NAME,
    appUser: 'qodiqa_app',
    appPassword: process.env.QODIQA_ACCEPTANCE_PG_APP_PASSWORD || APP_PLACEHOLDER_PASSWORD,
    // Same rotation-compat override for the dedicated retention role
    // (migration 038's placeholder no longer authenticates on a machine
    // with rotated role passwords — see the APP_PLACEHOLDER_PASSWORD note).
    retentionPassword: process.env.QODIQA_ACCEPTANCE_PG_RETENTION_PASSWORD
      || 'REPLACE_WITH_VAULT_SECRET_RETENTION',
    async stop() {
      await truncateAllTables(creds).catch(() => {});
    },
  };
}

module.exports = { startDisposableDatabase, DB_NAME };
