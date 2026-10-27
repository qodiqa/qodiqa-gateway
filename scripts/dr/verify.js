'use strict';

/**
 * QODIQA Disaster Recovery — Non-Destructive Backup Verification.
 *
 * Proves a backup produced by backup.js is intact and restorable WITHOUT
 * actually restoring it anywhere — the scheduled verification job this
 * supports must never write to a target directory or a database. It reuses
 * restore.js's own validation (loadManifest + validateComponents)
 * rather than re-implementing checksum/manifest checking a second time, so
 * "verified" and "restorable" can never quietly drift apart.
 *
 * For the PostgreSQL component (when present), this checks structural
 * integrity only — every table's archive file exists, parses as a JSON
 * array, and its row count matches what the manifest recorded at dump time.
 * It deliberately does NOT connect to any database (this must be safe to run
 * on a schedule with no live Postgres reachable, and must never touch a
 * production or restore-target database) — full functional restore proof
 * (actually loading rows into an isolated database) is scripts/dr/cycle.js's
 * job, run on its own, less frequent restore-validation schedule.
 *
 * Exit code is 0 iff every required component is present and every checked
 * component is structurally sound; 1 otherwise. Never throws past main() —
 * a verification job that crashes instead of reporting FAILED would be
 * exactly the "never silently succeed" gap this exists to close.
 */

const fs   = require('fs');
const path = require('path');

const { loadManifest, validateComponents, RestoreError } = require('./restore');
const { writeMetricsFile } = require('./metricsFile');
const { readArchive } = require('./archiveCrypto');
const { postAlert } = require('./alert');

/**
 * @param {string} backupDir — directory produced by runBackup()
 * @returns {{ valid: boolean, backupId: string|null, createdAt: string|null,
 *             componentsChecked: number, postgresTablesChecked: number,
 *             errors: string[] }}
 */
function verifyBackup(backupDir) {
  const errors = [];
  let manifest = null;

  try {
    manifest = loadManifest(backupDir);
  } catch (err) {
    return {
      valid: false,
      backupId: null,
      createdAt: null,
      componentsChecked: 0,
      postgresTablesChecked: 0,
      errors: [err instanceof RestoreError ? `${err.code}: ${err.message}` : err.message],
    };
  }

  try {
    validateComponents(backupDir, manifest);
  } catch (err) {
    errors.push(err instanceof RestoreError ? `${err.code}: ${err.message}` : err.message);
  }

  // step 6: the signed audit base record — signature, and that the backed-up log chains from it — in
  // both backup paths (the file companion and the pg_dump of audit_chain_prunes). Offline, like everything here.
  let auditBase = null;
  try {
    auditBase = require('./auditBaseCheck').verifyBackupAuditBase(backupDir, manifest);
    errors.push(...auditBase.errors);
  } catch (err) {
    errors.push(`AUDIT_BASE_CHECK_FAILED: ${err.message}`);
  }

  let postgresTablesChecked = 0;
  if (manifest.postgres && Array.isArray(manifest.postgres.tables)) {
    // reconcile, don't just re-read. A dump run by a role that Row-Level Security filters wrote
    // truncated archives AND recorded the truncated counts, so archive-vs-manifest alone passed (audit A3-02).
    // the dump records who dumped (and whether RLS could hide rows from it) and an independent per-table
    // count taken in the same snapshot; every one of those facts is checked here. Still no database connection.
    const pgm = manifest.postgres;
    if (typeof pgm.rlsExempt !== 'boolean' || !Array.isArray(pgm.rlsTables)) {
      errors.push('POSTGRES_BACKUP_NOT_RECONCILABLE: the manifest does not record the dumping role and its RLS exposure (backup made by an older release) — completeness cannot be proven');
    } else if (pgm.rlsTables.length > 0 && !pgm.rlsExempt) {
      errors.push(`POSTGRES_BACKUP_ROLE_NOT_RLS_EXEMPT: dumped as "${pgm.role && pgm.role.name}", which Row-Level Security filters on ${pgm.rlsTables.length} table(s) — rows may be missing`);
    }
    for (const entry of pgm.tables) {
      // a pg_dump-format backup has one archive (checksum- and size-checked by validateComponents above); its
      // per-table snapshot counts are reconciled at restore, and verifyBackupFull() lists its table of contents offline.
      if (pgm.format === 'pg_dump-custom') {
        if (!entry.present) errors.push(`POSTGRES_TABLE_NOT_DUMPED: table "${entry.table}" is missing from the backup (${entry.reason || 'no reason recorded'})`);
        else if (typeof entry.rowCount !== 'number' || entry.rowCount !== entry.sourceRowCount) errors.push(`POSTGRES_ROW_COUNT_UNRECONCILED: table "${entry.table}" has no snapshot row count`);
        else postgresTablesChecked++;
        continue;
      }
      if (!entry.present) {
        errors.push(`POSTGRES_TABLE_NOT_DUMPED: table "${entry.table}" is missing from the backup (${entry.reason || 'no reason recorded'})`);
        continue;
      }
      const archivePath = path.join(backupDir, entry.archiveFile);
      if (!fs.existsSync(archivePath)) {
        errors.push(`POSTGRES_ARCHIVE_MISSING: table "${entry.table}" archive file "${entry.archiveFile}" not found`);
        continue;
      }
      let rows;
      try {
        // an encrypted archive is checksum-verified against the sealed manifest, then decrypted.
        rows = JSON.parse(readArchive(backupDir, manifest.encryption || null, entry).toString('utf8'));
      } catch (err) {
        errors.push(`POSTGRES_ARCHIVE_CORRUPT: table "${entry.table}" is not valid JSON (${err.message})`);
        continue;
      }
      if (!Array.isArray(rows)) {
        errors.push(`POSTGRES_ARCHIVE_MALFORMED: table "${entry.table}" archive is not a JSON array`);
        continue;
      }
      if (typeof entry.rowCount === 'number' && rows.length !== entry.rowCount) {
        errors.push(
          `POSTGRES_ROW_COUNT_MISMATCH: table "${entry.table}" expected ${entry.rowCount} rows, archive has ${rows.length}`,
        );
        continue;
      }
      if (typeof pgm.rlsExempt === 'boolean' && entry.sourceRowCount !== rows.length) {
        errors.push(
          `POSTGRES_ROW_COUNT_UNRECONCILED: table "${entry.table}" archive has ${rows.length} rows, the snapshot count at dump time was ${entry.sourceRowCount}`,
        );
        continue;
      }
      postgresTablesChecked++;
    }
    const cov = pgm.coverage;
    if (cov && typeof cov.discoveredTableCount === 'number' && cov.dumpedTableCount !== cov.discoveredTableCount) {
      errors.push(`POSTGRES_TABLE_COVERAGE_MISMATCH: ${cov.dumpedTableCount} of ${cov.discoveredTableCount} discovered tables were dumped`);
    }
  }

  return {
    valid: errors.length === 0,
    backupId: manifest.backupId,
    createdAt: manifest.createdAt,
    componentsChecked: manifest.components.filter(c => c.present).length,
    postgresTablesChecked,
    auditBaseState: auditBase ? auditBase.state : null,
    errors,
  };
}

/**
 * verifyBackup() plus, for a pg_dump-format backup, the offline table-of-contents check (P-3): `pg_restore --list` of
 * the decrypted stream must hold TABLE DATA for every table the manifest recorded. Still no database connection.
 */
async function verifyBackupFull(backupDir) {
  const result = verifyBackup(backupDir);
  if (!result.backupId) return result;
  let manifest;
  try { manifest = loadManifest(backupDir); } catch { return result; }
  const pgm = manifest.postgres;
  if (pgm && pgm.format === 'pg_dump-custom' && !result.errors.some((e) => /^(CHECKSUM|SIZE|ARCHIVE)_/.test(e))) {
    try {
      const listed = await require('./pgDump').listArchiveTables(backupDir, pgm, manifest.encryption || null);
      const missing = pgm.tables.filter((t) => t.present && !listed.has(t.table)).map((t) => t.table);
      if (missing.length) result.errors.push(`POSTGRES_ARCHIVE_TABLE_MISSING: the pg_dump archive holds no data for ${missing.join(', ')}`);
      result.postgresArchiveTablesListed = listed.size;
    } catch (err) {
      result.errors.push(`POSTGRES_ARCHIVE_UNREADABLE: ${err.code || ''} ${err.message}`);
    }
    result.valid = result.errors.length === 0;
  }
  return result;
}

module.exports = { verifyBackup, verifyBackupFull };

if (require.main === module) {
  const backupDir = process.argv[2];
  if (!backupDir) {
    console.error('Usage: node verify.js <backupDir>');
    process.exit(2);
  }

  // verifyBackupFull adds the offline pg_dump table-of-contents check; a crash still reports FAILED.
  const report = (result) => {
    console.log(JSON.stringify({ event: result.valid ? 'BACKUP_VERIFY_OK' : 'BACKUP_VERIFY_FAILED', backupDir, ...result }, null, 2));

    writeMetricsFile(process.env.QODIQA_BACKUP_METRICS_FILE, {
      qodiqa_dr_backup_verify_success: result.valid ? 1 : 0,
      qodiqa_dr_backup_verify_last_run_timestamp_seconds: Math.floor(Date.now() / 1000),
      qodiqa_dr_backup_verify_components_checked: result.componentsChecked,
      qodiqa_dr_backup_verify_postgres_tables_checked: result.postgresTablesChecked,
    });

    if (!result.valid) {
      postAlert(process.env.ALERT_WEBHOOK_URL, `QODIQA DR backup verification FAILED for ${backupDir}: ${result.errors.join('; ')}`)
        .finally(() => { process.exitCode = 1; });
    } else {
      process.exitCode = 0;
    }
  };
  verifyBackupFull(backupDir).then(report, (err) => report({
    valid: false, backupId: null, createdAt: null, componentsChecked: 0, postgresTablesChecked: 0, errors: [`VERIFY_CRASHED: ${err.message}`],
  }));
}
