'use strict';

/**
 * QODIQA Disaster Recovery — Table Registry
 *
 * Single source of truth for "every PostgreSQL table QODIQA backup/restore
 * must cover." Replaces the old hand-maintained allow-list that used to live
 * in scripts/dr/postgres.js (which covered only 8 of ~50+ application
 * tables — see CONFORMANCE_AUDIT_REPORT.md finding).
 *
 * Two independent ways to enumerate "every table", which must always agree:
 *
 *   - EXPECTED_TABLES  — parsed statically from the migration SQL files at
 *     require time. Needs no database connection, so it can run in any CI
 *     job (including one with no Postgres service container) and gives a
 *     stable, offline definition of the schema QODIQA ships.
 *
 *   - discoverTables(pool) — the LIVE, authoritative list, read directly
 *     from information_schema against a real database. This is what
 *     dumpPostgres() (scripts/dr/postgres.js) actually uses at backup time,
 *     so a newly created table is captured automatically, with no code
 *     change and no risk of an allow-list silently going stale.
 *
 * If a table exists in one source and not the other, that is schema drift
 * worth investigating — test/dr/backupCoverage.test.js asserts the static
 * list against migrations on every CI run, and test/dr/
 * postgresFullCoverage.integration.test.js asserts the live list against the
 * static one whenever a database is available.
 *
 * EXCLUDED_TABLES is the only mechanism to intentionally opt a real table
 * OUT of backup/restore coverage. Every entry requires a `reason` string,
 * and the exclusion list is meant to stay short and reviewed — see the
 * backupCoverage test, which fails if an entry has no reason.
 */

const fs = require('fs');
const path = require('path');

const MIGRATIONS_DIR = path.join(__dirname, '..', '..', 'src', 'infra', 'postgres', 'migrations');

// Tables intentionally excluded from PostgreSQL row-data backup/restore.
// Keep this empty unless there is a genuine, documented reason — anything
// left out here is a real data-loss risk in a disaster recovery scenario.
const EXCLUDED_TABLES = Object.freeze({
  // Every other application table discovered in the schema is protected by backup/restore. Add entries here only
  // with a `reason` that explains why the table is intentionally NOT part of the DR guarantee.
  audit_chain_mirror_count: {
    reason: 'S2 (migration 073): derived singleton (row_count = count(*) of audit_chain), not audit data. '
      + 'restorePostgres() restores audit_chain, then rebuilds it from the restored rows with '
      + 'the owner-only rebuild function (scripts/dr/auditChainMirrorCount.js) and fails unless it equals count(*). A dumped row could never be '
      + 'restored anyway: the table refuses direct writes (guard trigger).',
  },
});

/**
 * Ordering hints for deterministic dumps. Falls back to 'id' and, if that
 * column doesn't exist either, to no ORDER BY at all (see postgres.js).
 * This is a determinism nicety, not a correctness requirement — restore
 * correctness comes from dependency-ordering the TABLES themselves (see
 * getRestoreOrder), not from row order within a single table.
 */
const ORDER_BY_COLUMN = Object.freeze({
  audit_chain: 'seq',
  signing_keys: 'key_id',
  signing_key_legacy_map: 'old_key_id',
  consent_scopes: 'scope_name',
  investigation_artifacts: 'investigation_id',
});

/**
 * Safely quote a Postgres identifier for interpolation into a query string.
 * Only ever used with identifiers WE produced (table/column names read back
 * from information_schema or our own manifest) — never with raw user input —
 * but is still quoted properly since these names are interpolated (table/
 * column names cannot be bind parameters in Postgres).
 */
function quoteIdent(name) {
  return '"' + String(name).replace(/"/g, '""') + '"';
}

// comments are stripped first. Migration 055's header comment ("migration 001's own CREATE TABLE
// list") registered a phantom table named "list", so pg-backup.sh verify reported a coverage gap on every database
// migrated past 055 — its nightly verify could never pass.
function _stripSqlComments(sql) {
  return sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ');
}

function _parseTableNamesFromSql(sql) {
  sql = _stripSqlComments(sql);
  const names = new Set();
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?(\w+)"?/gi;
  let m;
  while ((m = re.exec(sql))) names.add(m[1]);
  return names;
}

/**
 * Statically parse every `CREATE TABLE [IF NOT EXISTS] <name>` from the
 * migration SQL files. No database connection required.
 * @returns {string[]} sorted, de-duplicated table names
 */
function parseExpectedTables() {
  const names = new Set();
  const files = fs.readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql'));
  for (const file of files) {
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf8');
    for (const name of _parseTableNamesFromSql(sql)) names.add(name);
  }
  return [...names].sort();
}

const EXPECTED_TABLES = Object.freeze(parseExpectedTables());

// The tables backup/restore is expected to actually cover: every expected
// table minus the (ideally empty) exclusion list.
const BACKED_UP_TABLES = Object.freeze(EXPECTED_TABLES.filter(t => !EXCLUDED_TABLES[t]));

/**
 * Live, authoritative table discovery against a real database.
 * @param {import('pg').Pool} pool
 * @returns {Promise<string[]>} sorted table names present in the `public` schema
 */
async function discoverTables(pool) {
  const { rows } = await pool.query(`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
    ORDER BY table_name
  `);
  return rows.map(r => r.table_name).filter(t => !EXCLUDED_TABLES[t]);
}

/**
 * Compute a foreign-key-safe insertion order for a set of tables: parents
 * (referenced tables) before children (referencing tables), via Kahn's
 * topological sort over the live FK graph. Tables with no ordering
 * constraint keep their (stable) alphabetical position among their peers.
 *
 * A cycle (mutual FKs) is not expected in this schema and is handled
 * defensively: any tables left over once no more zero-in-degree nodes exist
 * are appended in their original order rather than raising, since a stalled
 * topological sort must never turn into a lost backup.
 *
 * @param {import('pg').Pool} pool
 * @param {string[]} tables — the table set to order (e.g. from discoverTables)
 * @returns {Promise<string[]>}
 */
async function getRestoreOrder(pool, tables) {
  const tableSet = new Set(tables);
  // PL13-09: read the FK graph from pg_catalog, NOT information_schema.
  // information_schema.constraint_column_usage lists only constraints on tables OWNED by a currently enabled role, so
  // for the shipped dump identity qodiqa_backup it returned ZERO edges: the
  // "FK-safe" order silently degraded to alphabetical, and restorePostgres() failed on the first child table whose
  // name sorts before its parent's (consent_audit_log before consent_records — reproduced on a real disposable
  // cluster, DEPLOY-BACKUP.md §B). It only ever worked when the dump ran as a superuser/owner (CI). pg_constraint is
  // readable by every role.
  const { rows } = await pool.query(`
    SELECT ch.relname AS child, pa.relname AS parent
    FROM pg_catalog.pg_constraint c
    JOIN pg_catalog.pg_class ch ON ch.oid = c.conrelid
    JOIN pg_catalog.pg_class pa ON pa.oid = c.confrelid
    WHERE c.contype = 'f'
      AND ch.relnamespace = 'public'::regnamespace
      AND pa.relnamespace = 'public'::regnamespace
  `);

  const dependsOn = new Map(tables.map(t => [t, new Set()])); // child -> set(parent)
  for (const { child, parent } of rows) {
    if (!tableSet.has(child) || !tableSet.has(parent) || child === parent) continue;
    dependsOn.get(child).add(parent);
  }

  const ordered = [];
  const remaining = new Set(tables);
  // Kahn's algorithm, iterating in stable alphabetical order each pass so
  // output is deterministic across runs of an unchanged schema.
  while (remaining.size > 0) {
    const ready = [...remaining].filter(t => {
      const deps = dependsOn.get(t);
      return ![...deps].some(d => remaining.has(d));
    }).sort();

    if (ready.length === 0) {
      // Defensive fallback for an unexpected FK cycle: don't hang or throw —
      // append whatever remains in stable order so backup coverage never
      // regresses to "silently drop tables" because of a schema surprise.
      ordered.push(...[...remaining].sort());
      break;
    }

    for (const t of ready) {
      ordered.push(t);
      remaining.delete(t);
    }
  }

  return ordered;
}

/**
 * CLI: print the static expected-table inventory, one per line (--list) or
 * as JSON (--json). Used by scripts/pg-backup.sh so the shell-based
 * verification step can check full coverage without hand-maintaining its
 * own table list.
 */
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.includes('--json')) {
    console.log(JSON.stringify({
      expected: EXPECTED_TABLES,
      excluded: Object.keys(EXCLUDED_TABLES),
      backedUp: BACKED_UP_TABLES,
    }, null, 2));
  } else {
    for (const t of BACKED_UP_TABLES) console.log(t);
  }
}

module.exports = {
  MIGRATIONS_DIR,
  EXCLUDED_TABLES,
  ORDER_BY_COLUMN,
  EXPECTED_TABLES,
  BACKED_UP_TABLES,
  parseExpectedTables,
  discoverTables,
  getRestoreOrder,
  quoteIdent,
  _parseTableNamesFromSql,
};
