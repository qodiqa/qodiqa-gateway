'use strict';

/**
 * QODIQA Disaster Recovery — PostgreSQL component (best-effort, portable).
 *
 * Deliberately does NOT shell out to pg_dump/pg_restore — those binaries are
 * not guaranteed present wherever this script runs (the application
 * container may not bundle Postgres client tools). Instead this dumps/
 * restores rows as JSON via the same `pg` client library the application
 * itself already depends on, so a working `pg` connection is the only
 * requirement.
 *
 * This is a COMPLEMENT to, not a replacement for, scripts/pg-backup.sh
 * (which remains the recommended mechanism for a full physical/logical
 * Postgres backup in production — see docs/operations/backup-runbook.md).
 * This module exists so the end-to-end DR *validation* framework can run
 * anywhere a Postgres connection string is available (including CI service
 * containers and a local dev Postgres instance), without depending on the
 * postgres-client-tools package being installed on the runner.
 *
 * COVERAGE: table coverage is no longer a hand-maintained
 * allow-list. Every table is discovered LIVE from information_schema via
 * scripts/dr/table-registry.js's discoverTables(), so a newly created
 * production table (consent, investigation, compliance, audit, security,
 * whatever) is captured automatically the next time a backup runs — no code
 * change required. See table-registry.js's EXCLUDED_TABLES for the opt-out
 * mechanism (one entry: the derived audit_chain_mirror_count, rebuilt after
 * restore — S2), and test/dr/backupCoverage.test.js for the
 * regression guard that keeps that list honest.
 *
 * ORDERING: tables are dumped — and therefore later restored, since restore
 * simply replays manifest.postgres.tables in the order they were recorded —
 * in foreign-key-safe (parent-before-child) order, computed once via
 * table-registry.js's getRestoreOrder(). This matters because restore is a
 * plain per-row INSERT loop: inserting a child row before its parent exists
 * would violate the FK constraint and abort the restore.
 *
 * Tables are restored generically: each row's own JSON keys become the
 * INSERT column list, so no column list needs to be hardcoded/kept in sync
 * with migrations by hand.
 */

const fs   = require('fs');
const path = require('path');

const { ORDER_BY_COLUMN, discoverTables, getRestoreOrder, EXPECTED_TABLES, EXCLUDED_TABLES, quoteIdent } = require('./table-registry');
const { isChainHeadTable, verifyRestoredChainHeads, repairAuditChainHeadVersion } = require('./chainHeads');
const { readArchive } = require('./archiveCrypto');
const { verifyRestoredDefinerOwnership } = require('../../src/infra/postgres/definerOwnership'); //

function _orderByClause(table) {
  return ORDER_BY_COLUMN[table] || 'id';
}

/**
 * After restoring a table's rows via explicit-value INSERTs, any SERIAL /
 * BIGSERIAL / IDENTITY column's sequence is left wherever it was after
 * schema creation (explicit-value INSERTs never call nextval()) — NOT
 * advanced to cover the restored data. Left unfixed, the very next INSERT
 * that relies on the column's DEFAULT would collide with an existing
 * restored row and fail with a unique-constraint violation. Sync every
 * sequence-backed column on this table to MAX(column) + 1 so restored data
 * and future writes never collide. Safe to call on tables with no such
 * column (a no-op).
 */
async function _syncSequences(pool, table) {
  const { rows: cols } = await pool.query(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1 AND column_default LIKE 'nextval(%'`,
    [table],
  );
  for (const { column_name } of cols) {
    await pool.query(
      `SELECT setval(
                pg_get_serial_sequence($1, $2),
                COALESCE((SELECT MAX(${quoteIdent(column_name)}) FROM ${quoteIdent(table)}), 1),
                (SELECT MAX(${quoteIdent(column_name)}) FROM ${quoteIdent(table)}) IS NOT NULL
              )`,
      [table, column_name],
    );
  }
}

/**
 * SELECT a table's rows with the most deterministic ordering available.
 * Not every table has an 'id' column (e.g. investigation_artifacts has a
 * composite primary key) — fall back to an unordered SELECT rather than
 * fail the whole backup over a missing ordering column.
 */
/**
 * who is dumping, and can Row-Level Security hide rows from it? Read from the catalog in the dump's own
 * snapshot. A role that is neither superuser nor BYPASSRLS sees only the rows the RLS policies admit (for qodiqa_app
 * with no tenant context: the NULL-tenant rows) — the silent truncation the 2026-09-28 audit reproduced (A3-02).
 */
async function _backupRoleFacts(client, tables) {
  const { rows: [role] } = await client.query(
    `SELECT current_user AS name, r.rolsuper AS superuser, r.rolbypassrls AS bypass_rls,
            pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') AS read_all_data
       FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`);
  const { rows: rls } = await client.query(
    `SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relrowsecurity AND c.relname = ANY($1::text[])
      ORDER BY c.relname`, [tables]);
  const rlsTables = rls.map((r) => r.relname);
  return {
    role: { name: role.name, superuser: role.superuser, bypassRls: role.bypass_rls, readAllData: role.read_all_data },
    rlsTables,
    rlsExempt: role.superuser || role.bypass_rls,
  };
}

async function _selectAllRows(pool, table) {
  const orderCol = _orderByClause(table);
  // the dump runs inside ONE transaction, where a failed statement aborts every later one — so the ordering
  // column's existence is looked up first instead of trying the ORDER BY and catching 42703 (undefined_column).
  const { rows: has } = await pool.query(
    `SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`,
    [table, orderCol]);
  if (has.length > 0) {
    const result = await pool.query(`SELECT * FROM ${quoteIdent(table)} ORDER BY ${quoteIdent(orderCol)}`);
    return { rows: result.rows, ordered: true };
  }
  const result = await pool.query(`SELECT * FROM ${quoteIdent(table)}`);
  return { rows: result.rows, ordered: false };
}

/**
 * @param {string} targetDir  — directory to write pg_<table>.json files into
 * @param {{ connectionString?: string, writeArchive?: Function }} [opts] — writeArchive: archiveCrypto's
 *   makeArchiveWriter(); with encryption on it writes only pg_<table>.json.enc and returns its ciphertext sha256/size
 * @returns {Promise<{ dumpedAt: string, tables: object[], coverage: object }>}
 */
async function dumpPostgres(targetDir, opts = {}) {
  const { Pool } = require('pg');
  const connectionString = opts.connectionString || process.env.QODIQA_PG_URL || process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('dumpPostgres: no connection string — set QODIQA_PG_URL or pass { connectionString }');
  }

  const pool = new Pool({ connectionString, max: 1 });
  const tables = [];
  let access;
  let coverage;

  // ONE client, ONE read-only REPEATABLE READ snapshot for the whole dump, so every table's count and
  // rows describe the same instant (previously each table was read in its own snapshot).
  const client = await pool.connect();
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const discovered = await discoverTables(client);
    const restoreOrder = await getRestoreOrder(client, discovered);

    access = await _backupRoleFacts(client, restoreOrder);
    if (access.rlsTables.length > 0 && !access.rlsExempt) {
      const err = new Error(`dumpPostgres: role "${access.role.name}" is subject to Row-Level Security on ${access.rlsTables.length} table(s) `
        + `(${access.rlsTables.join(', ')}) — a dump would silently omit rows. Run the backup as qodiqa_backup (BYPASSRLS, migration 067).`);
      err.code = 'BACKUP_ROLE_NOT_RLS_EXEMPT';
      throw err;
    }
    // D-P: the backup role must also hold the predefined, read-only pg_read_all_data role
    // (migration 067 where the migrating identity may grant it; otherwise scripts/db/provision-backup-role.superuser.sql).
    if (!access.role.readAllData) {
      const err = new Error(`dumpPostgres: role "${access.role.name}" is not a pg_read_all_data member — run `
        + 'scripts/db/provision-backup-role.superuser.sql once (as a superuser) or back up as qodiqa_backup. Nothing was written.');
      err.code = 'BACKUP_ROLE_READ_ALL_DATA_MISSING';
      throw err;
    }

    const failed = [];
    for (const table of restoreOrder) {
      // A savepoint per table: a refused table (e.g. permission denied) must not abort the snapshot for the rest,
      // so the manifest names EVERY table that could not be dumped, not just the first.
      await client.query('SAVEPOINT w10_table');
      try {
        // Reconciliation count, taken separately in the same snapshot as the rows.
        const { rows: [{ n }] } = await client.query(`SELECT count(*)::bigint AS n FROM ${quoteIdent(table)}`);
        const sourceRowCount = Number(n);
        const { rows, ordered } = await _selectAllRows(client, table);
        if (rows.length !== sourceRowCount) {
          throw new Error(`dumped ${rows.length} rows but the snapshot count is ${sourceRowCount}`);
        }
        const fileName = `pg_${table}.json`;
        let written;
        if (opts.writeArchive) {
          written = opts.writeArchive(fileName, JSON.stringify(rows));
        } else {
          fs.writeFileSync(path.join(targetDir, fileName), JSON.stringify(rows), 'utf8');
          written = { archiveFile: fileName };
        }
        tables.push({ table, present: true, rowCount: rows.length, sourceRowCount, archiveFile: written.archiveFile, ordered,
          ...(written.sha256 ? { sha256: written.sha256, sizeBytes: written.sizeBytes } : {}) });
        await client.query('RELEASE SAVEPOINT w10_table');
      } catch (err) {
        await client.query('ROLLBACK TO SAVEPOINT w10_table');
        // inside one snapshot a table cannot vanish mid-dump, so any failure here — typically
        // "permission denied" — means an incomplete backup. It is recorded AND fails the dump (fail closed);
        // previously it was recorded as present:false and the backup still succeeded.
        tables.push({ table, present: false, reason: err.message });
        failed.push(`${table}: ${err.message}`);
      }
    }
    await client.query('COMMIT');

    // Coverage proof recorded directly in the manifest: how many tables this
    // deployment's schema actually has vs. how many the migrations ship in
    // total (the latter may exceed the former if not every migration has
    // been applied yet — that's a fact about this deployment, not a bug).
    coverage = {
      expectedTableCount: EXPECTED_TABLES.length,
      discoveredTableCount: discovered.length,
      dumpedTableCount: tables.filter(t => t.present).length,
    };

    if (failed.length > 0) {
      const err = new Error(`dumpPostgres: ${failed.length} table(s) could not be dumped completely — ${failed.join('; ')}`);
      err.code = 'BACKUP_INCOMPLETE';
      err.partial = { tables, coverage, access };
      throw err;
    }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
    await pool.end();
  }

  return { dumpedAt: new Date().toISOString(), snapshot: 'repeatable-read-read-only', ...access, tables, coverage };
}

/**
 * Restore rows dumped by dumpPostgres() into a target database.
 * Uses ON CONFLICT DO NOTHING — restore is additive/idempotent, matching
 * the append-only nature of audit_chain / transparency_log_entries (the
 * tables where re-running a restore must never duplicate or mutate existing
 * rows).
 *
 * Tables are restored in the exact order recorded in the manifest, which
 * dumpPostgres() already computed as a foreign-key-safe (parent-before-
 * child) order — restore does not need its own database connection to
 * re-derive that order.
 *
 * @param {string} backupDir           — directory containing pg_<table>.json files
 * @param {{ tables: object[] }} postgresManifest — the `postgres` field from manifest.json
 *the four singleton chain-head pointer tables (chainHeads.js — audit_chain_head,
 * evidence_chain_head, transparency_log_head, transparency_roots_head) are the exception: a migrated target already
 * holds their genesis seed row, so DO NOTHING silently kept genesis and the next append forked the chain. They are
 * restored with ON CONFLICT (id) DO UPDATE to the backed-up value, and after every table is restored the heads are
 * verified (= the backed-up row, and = the restored ledger's tail) before success is reported — fail closed.
 *
 * @param {{ connectionString?: string, encryption?: object|null, auditOrderingMode?: string }} [opts]
 * encryption: manifest.encryption — archives are then read via archiveCrypto.readArchive (checksum, decrypt)
 * @returns {Promise<{ restoredAt: string, tables: object[] }>}
 */
async function restorePostgres(backupDir, postgresManifest, opts = {}) {
  const { Pool } = require('pg');
  // Prefer a dedicated restore target (QODIQA_PG_RESTORE_URL) so a DR drill can
  // restore into a genuinely CLEAN, separate database rather than the live one
  // it was dumped from — matching the "never restore over a running instance"
  // requirement for the Postgres component too. Falls back to the dump URL
  // (idempotent no-op via ON CONFLICT) when no separate target is configured.
  // explicit target, never the source (was: fallback to QODIQA_PG_URL / DATABASE_URL).
  const connectionString = require('./restoreTargetGuard').assertSafeRestoreTarget(opts.connectionString, process.env);

  const pool = new Pool({ connectionString });
  const results = [];
  let auditChainMirrorCount = null;
  let chainHeads = null;
  let chainHeadGateError = null;
  let definerOwnership = null;
  const backedUpHeads = new Map();

  try {
    for (const entry of postgresManifest.tables || []) {
      if (!entry.present) { results.push({ table: entry.table, restored: 0, skipped: true }); continue; }
      // S2: derived state is never restored as data (EXCLUDED_TABLES); it is rebuilt after audit_chain below.
      if (EXCLUDED_TABLES[entry.table]) { results.push({ table: entry.table, restored: 0, skipped: true, derived: true }); continue; }

      const rows = JSON.parse(readArchive(backupDir, opts.encryption || null, entry).toString('utf8'));
      if (isChainHeadTable(entry.table)) backedUpHeads.set(entry.table, rows.length === 1 ? rows[0] : { invalidRowCount: rows.length });

      // (A3-15): count what was really inserted. ON CONFLICT DO NOTHING skips a row that conflicts with one
      // already in the target and reports rowCount 0; it used to be counted as restored, so a restore into a
      // non-empty target silently dropped rows while reporting full success.
      let restored = 0;
      let skipped = 0;
      for (const [index, row] of rows.entries()) {
        const columns = Object.keys(row);
        if (columns.length === 0) continue;
        const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
        const values = columns.map(c => row[c]);
        // a chain-head singleton takes the backed-up value; every other table stays additive (DO NOTHING).
        const onConflict = isChainHeadTable(entry.table)
          ? `ON CONFLICT (id) DO UPDATE SET ${columns.filter((c) => c !== 'id').map((c) => `${quoteIdent(c)} = EXCLUDED.${quoteIdent(c)}`).join(', ')}`
          : 'ON CONFLICT DO NOTHING';
        const sql = `INSERT INTO ${quoteIdent(entry.table)} (${columns.map(quoteIdent).join(', ')}) VALUES (${placeholders}) ${onConflict}`;
        let result;
        try {
          result = await pool.query(sql, values);
        } catch (err) {
          throw new Error(`restorePostgres: failed inserting ${entry.table} row ${index + 1}/${rows.length}: ${err.message}`);
        }
        if (result.rowCount === 1) restored++; else skipped++;
      }
      await _syncSequences(pool, entry.table);
      results.push({ table: entry.table, restored, skipped, expected: rows.length });
    }
    if (results.some((r) => r.table === 'audit_chain' && r.skipped !== true)) {
      auditChainMirrorCount = await require('./auditChainMirrorCount').rebuildAfterRestore(pool);   // S2
    }
    // the target's schema comes from the migration chain; verify (never change) its definer ownership.
    definerOwnership = await verifyRestoredDefinerOwnership(pool);
    // heads must be the backed-up values AND the tails of the restored ledgers, or the restore fails.
    // opts.deferChainHeadGate: runRestore raises a gate failure only AFTER its own audit-chain integrity
    // gate, so a backup that never captured audit_chain keeps its more specific AUDIT_CHAIN_INTEGRITY_FAILED diagnosis
    //. The gate stays mandatory either way; standalone callers keep the immediate throw.
    if (results.some((r) => r.table === 'audit_chain_head' && r.skipped !== true)) await repairAuditChainHeadVersion(pool);   //
    try {
      chainHeads = await verifyRestoredChainHeads(pool, backedUpHeads, { auditOrderingMode: opts.auditOrderingMode });
    } catch (err) {
      if (!opts.deferChainHeadGate) throw err;
      chainHeadGateError = err;
    }
  } finally {
    await pool.end();
  }

  const skippedRows = results.reduce((s, t) => s + (t.skipped === true ? 0 : (t.skipped || 0)), 0);
  const out = {
    restoredAt: new Date().toISOString(),
    tables: results,
    skippedRows,
    skippedByTable: results.filter((t) => typeof t.skipped === 'number' && t.skipped > 0).map((t) => ({ table: t.table, skipped: t.skipped })),
    auditChainMirrorCount,
    chainHeads,
    definerOwnership,
  };
  // non-enumerable: never serialised into restore reports; runRestore rethrows it after its integrity gate
  if (chainHeadGateError) Object.defineProperty(out, 'chainHeadGateError', { value: chainHeadGateError, enumerable: false });
  return out;
}

module.exports = { dumpPostgres, restorePostgres };
