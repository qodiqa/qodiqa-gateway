'use strict';

/**
 * PostgreSQL restore probe.
 *
 * Unlike the file-based probes (auditChainProbe.js, policyStoreProbe.js,
 * keyStoreProbe.js), this one is a plain importable async function rather
 * than a child-process script: there is no module-level singleton file path
 * cached at require-time to isolate here, and it needs to await a live `pg`
 * connection, which is naturally async anyway.
 *
 * Proves the things of the remediation require of a Postgres
 * restore, beyond "every row round-tripped without an error" (which
 * restorePostgres() itself already guarantees by failing closed on the
 * first insert error):
 *
 *   - every table recorded as present in the backup exists in the restore
 *     target with the SAME row count as was dumped (no silent data loss,
 *     no silent duplication)
 *   - every foreign key constraint in the target database is VALID (no
 *     dangling references introduced by out-of-order or partial restore)
 *   - every SERIAL/BIGSERIAL/IDENTITY sequence is at or ahead of the max
 *     value of the column it backs (a stale sequence is a live incident
 *     waiting to happen: the next INSERT using DEFAULT would collide with
 *     restored data and fail)
 */

const { quoteIdent } = require('../table-registry');
const { chainHeadReport } = require('../chainHeads');

/**
 * @param {{ tables: object[] }} postgresManifest — manifest.postgres from the backup that was restored
 * @param {{ connectionString?: string, auditOrderingMode?: string }} [opts]
 * @returns {Promise<object>}
 */
async function validatePostgresRestore(postgresManifest, opts = {}) {
  if (!postgresManifest) {
    return { valid: true, skipped: true, reason: 'NO_POSTGRES_COMPONENT_IN_BACKUP' };
  }

  const { Pool } = require('pg');
  // validating the SOURCE by accident would report a restore that never happened as valid.
  const connectionString = opts.connectionString || process.env.QODIQA_PG_RESTORE_URL;
  if (!connectionString) {
    return { valid: false, reason: 'NO_CONNECTION_STRING' };
  }

  const pool = new Pool({ connectionString });
  try {
    // ── 1. Row counts: every present table restored with its full row count ──
    const rowCountResults = [];
    for (const entry of postgresManifest.tables || []) {
      if (!entry.present) continue;
      let actual = null;
      let error = null;
      try {
        const { rows } = await pool.query(`SELECT count(*)::int AS c FROM ${quoteIdent(entry.table)}`);
        actual = rows[0].c;
      } catch (err) {
        error = err.message;
      }
      rowCountResults.push({
        table: entry.table,
        expectedRowCount: entry.rowCount,
        actualRowCount: actual,
        ok: error === null && actual === entry.rowCount,
        error,
      });
    }
    const rowCountMismatches = rowCountResults.filter(r => !r.ok);

    // ── 2. Foreign key validity: no NOT VALID / broken constraints ───────────
    const { rows: invalidFks } = await pool.query(`
      SELECT conname, conrelid::regclass::text AS "table"
      FROM pg_constraint
      WHERE contype = 'f' AND NOT convalidated
    `);

    // ── 3. Sequence sync: every SERIAL/BIGSERIAL/IDENTITY sequence must be
    //      at or ahead of MAX(owning column) — a lagging sequence means the
    //      next DEFAULT-driven INSERT will collide with restored data. ─────
    const { rows: seqOwners } = await pool.query(`
      SELECT c.relname AS table_name, a.attname AS column_name, s.relname AS seq_name
      FROM pg_depend d
      JOIN pg_class s      ON s.oid = d.objid AND s.relkind = 'S'
      JOIN pg_attribute a  ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
      JOIN pg_class c      ON c.oid = d.refobjid
      WHERE d.deptype = 'a'
        AND c.relnamespace = 'public'::regnamespace
    `);
    const sequenceIssues = [];
    for (const { table_name, column_name, seq_name } of seqOwners) {
      const { rows: mx } = await pool.query(`SELECT MAX(${quoteIdent(column_name)}) AS m FROM ${quoteIdent(table_name)}`);
      const { rows: sv } = await pool.query(`SELECT last_value FROM ${quoteIdent(seq_name)}`);
      const maxValue = mx[0].m;
      const seqValue = Number(sv[0].last_value);
      if (maxValue !== null && seqValue < Number(maxValue)) {
        sequenceIssues.push({ table: table_name, column: column_name, sequence: seq_name, maxValue, sequenceValue: seqValue });
      }
    }

    // ── 4.: every chain-head pointer row equals the tail of its restored ledger — a head left at
    //      genesis makes the next append fork the chain (scripts/dr/chainHeads.js). audit_chain_head is enforced only
    //      for a distributed-mode backup (the only mode that maintains it).
    const chainHeads = await chainHeadReport(pool, { auditOrderingMode: opts.auditOrderingMode });

    const valid = rowCountMismatches.length === 0 && invalidFks.length === 0 && sequenceIssues.length === 0
      && chainHeads.valid;

    return {
      valid,
      tablesChecked: rowCountResults.length,
      rowCountMismatches,
      fkViolations: invalidFks,
      sequenceIssues,
      chainHeads,
    };
  } finally {
    await pool.end();
  }
}

module.exports = { validatePostgresRestore };
