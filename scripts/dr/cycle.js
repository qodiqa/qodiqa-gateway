'use strict';

/**
 * QODIQA Disaster Recovery — full Backup -> Restore -> Validate cycle driver.
 *
 * Single deterministic entrypoint for CI and operator DR drills. Runs the
 * complete cycle against the LIVE (currently-configured) data set:
 *
 *   1. Backup every present component into a scratch backup directory.
 *   2. Restore that backup into a fresh, empty, clean target directory
 *      (never over the live instance — restore.js enforces this).
 *   3. Validate the restored state by exercising the real production
 *      modules (audit-log / policyStore / keyStore) against the restored
 *      files in isolated child processes.
 *
 * Exit code 0 iff every present required component restored AND every probe
 * reports valid:true — deterministic pass/fail with no manual intervention.
 *
 * Postgres is included automatically when QODIQA_PG_URL (or DATABASE_URL) is
 * set; otherwise the file-only cycle runs (still a complete DR proof for a
 * file-authoritative deployment — the audit chain, key store, and policy
 * store are all file-based and authoritative per
 * docs/protocol/AUDIT-SCHEMA-V8.md).
 *
 * Environment:
 *   DR_CYCLE_DIR   — base scratch dir (default: OS temp). Cleaned unless
 *                    DR_CYCLE_KEEP=1 is set (for post-mortem inspection).
 */

const fs   = require('fs');
const os   = require('os');
const path = require('path');

const { runBackup }             = require('./backup');
const { runRestore }            = require('./restore');
const { validateRestoredState } = require('./validate');
const { writeMetricsFile }      = require('./metricsFile');
const { postAlert }             = require('./alert');

function _log(event, extra) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...extra }));
}

async function runCycle(opts = {}) {
  const includePostgres = opts.includePostgres
    ?? !!(process.env.QODIQA_PG_URL || process.env.DATABASE_URL);
  const includeRedis = opts.includeRedis ?? !!process.env.REDIS_URL;

  const scratch = opts.scratchDir
    || fs.mkdtempSync(path.join(process.env.DR_CYCLE_DIR || os.tmpdir(), 'qodiqa-dr-cycle-'));
  const backupDir  = path.join(scratch, 'backup');
  const restoreDir = path.join(scratch, 'restored');

  _log('DR_CYCLE_START', { scratch, includePostgres, includeRedis });

  // ── 1. Backup ────────────────────────────────────────────────────────────────
  const { manifest } = await runBackup({ outDir: backupDir, includePostgres, includeRedis });
  const present = manifest.components.filter(c => c.present);
  _log('DR_BACKUP_COMPLETE', {
    backupId: manifest.backupId,
    componentsPresent: present.length,
    componentsTotal: manifest.components.length,
    postgres: manifest.postgres ? manifest.postgres.tables.filter(t => t.present).length : null,
    postgresFormat: manifest.postgres ? (manifest.postgres.format || 'json-rows') : null,           //
  });

  // ── 2. Restore into a clean target ───────────────────────────────────────────
  // Resolve the Postgres restore-target connection string ONCE here (same
  // precedence runRestore()/restorePostgres() use internally) and pass it
  // explicitly, so step 3's validation queries the exact same target step 2
  // actually restored into rather than re-deriving it independently (
  // two independent resolutions of "the same" env-var chain could diverge if
  // the process environment changed between calls).
  // explicit target only (QODIQA_PG_RESTORE_URL), never the source; runRestore() re-validates it.
  const postgresRestoreUrl = process.env.QODIQA_PG_RESTORE_URL || undefined;
  // a drill replays erasures from QODIQA_ERASURE_LEDGER_SOURCE when
  // configured; otherwise it records that only the restored ledger was replayed.
  const erasureLedger = process.env.QODIQA_ERASURE_LEDGER_SOURCE || null;
  if (!erasureLedger) _log('DR_ERASURE_LEDGER_SOURCE_ABSENT', { note: 'drill replays the restored ledger only (backup window accepted)' });
  const { restored, erasureReplay, postgres: pgRestore } = await runRestore({
    backupDir, targetRoot: restoreDir, pgConnectionString: postgresRestoreUrl, erasureLedger, allowNoErasureLedger: !erasureLedger,
  });
  _log('DR_RESTORE_COMPLETE', { restoredCount: restored.length,
    postgresSkippedRows: pgRestore ? pgRestore.skippedRows : null, postgresSkippedByTable: pgRestore ? pgRestore.skippedByTable : null, // (A3-15)
    erasureReplay: erasureReplay && { source: erasureReplay.source, ledgerRows: erasureReplay.ledgerRows, subjectsReErased: erasureReplay.subjectsReErased } });

  // ── 3. Validate restored state via the real production modules ───────────────
  // manifest.auditOrderingMode — recorded at backup time — decides
  // whether validation checks the restored audit.log file or the just-
  // restored audit_chain rows in PostgreSQL; see validate.js.
  const validation = await validateRestoredState(
    restored,
    manifest.postgres ? { manifest: manifest.postgres, connectionString: postgresRestoreUrl } : null,
    { auditOrderingMode: manifest.auditOrderingMode, controlPlaneBackend: manifest.controlPlaneBackend || 'memory' }, //
  );
  _log('DR_VALIDATE_COMPLETE', {
    overallValid: validation.overallValid,
    auditChainValid: validation.auditChain.valid,
    auditChainLength: validation.auditChain.chainLength,
    policyStoreValid: validation.policyStore.valid,
    keyStoreValid: validation.keyStore.valid,
    keyStoreCryptoRoundTrip: validation.keyStore.cryptoRoundTrip
      ? validation.keyStore.cryptoRoundTrip.ok
      : 'skipped (no KEK in env)',
    postgresValid: validation.postgres.valid,
    postgresTablesChecked: validation.postgres.tablesChecked || 0,
  });

  const passed = validation.overallValid;
  _log(passed ? 'DR_CYCLE_PASS' : 'DR_CYCLE_FAIL', { scratch });

  if (process.env.DR_CYCLE_KEEP !== '1' && !opts.keep) {
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best-effort cleanup */ }
  }

  return { passed, manifest, validation, scratch };
}

module.exports = { runCycle };

if (require.main === module) {
  const startedAtMs = Date.now();

  runCycle()
    .then(({ passed }) => {
      process.exitCode = passed ? 0 : 1;

      writeMetricsFile(process.env.QODIQA_BACKUP_METRICS_FILE, {
        qodiqa_dr_restore_validation_success: passed ? 1 : 0,
        [`qodiqa_dr_restore_validation_last_${passed ? 'success' : 'failure'}_timestamp_seconds`]: Math.floor(Date.now() / 1000),
        qodiqa_dr_restore_validation_duration_seconds: (Date.now() - startedAtMs) / 1000,
      }, { preserve: ['qodiqa_dr_restore_validation_last_success_timestamp_seconds', 'qodiqa_dr_restore_validation_last_failure_timestamp_seconds'] }); //

      if (!passed) {
        return postAlert(process.env.ALERT_WEBHOOK_URL, 'QODIQA scheduled DR restore validation FAILED — see cycle logs for the failing probe.');
      }
    })
    .catch(err => {
      _log('DR_CYCLE_ERROR', { error: err.message, code: err.code || null });
      writeMetricsFile(process.env.QODIQA_BACKUP_METRICS_FILE, {
        qodiqa_dr_restore_validation_success: 0,
        qodiqa_dr_restore_validation_last_failure_timestamp_seconds: Math.floor(Date.now() / 1000),
      }, { preserve: ['qodiqa_dr_restore_validation_last_success_timestamp_seconds'] }); //
      postAlert(process.env.ALERT_WEBHOOK_URL, `QODIQA scheduled DR restore validation ERRORED: ${err.message}`)
        .finally(() => { process.exitCode = 1; });
    });
}
