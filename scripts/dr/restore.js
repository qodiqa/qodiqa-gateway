'use strict';

/**
 * QODIQA Disaster Recovery — Restore
 *
 * Restores a backup produced by backup.js into a CLEAN target directory.
 *
 * Fail-closed, three-phase, all-or-nothing:
 * (validateComponents) — verify the manifest itself, then every
 *     present component's checksum against its archive file. Nothing is
 *     written to the target during this phase.
 * (restoreComponents) — only entered if raised nothing.
 *     Copies each present component to its original relative path under
 *     targetRoot.
 * runs the row
 *     restore for any Postgres component in the manifest BEFORE the
 *     audit-chain gate below, because a distributed-mode audit-chain check
 *     validates rows that were JUST restored, not whatever pre-existed in
 *     the target database.
 * (audit-chain integrity verification, extended for
 * distributed mode) — only entered if (and 2.5, when present)
 * completed. Restore is byte-level-validated (checksums match
 *     what was backed up), but a checksum match alone does NOT prove the
 *     restored audit chain's own hash-chain linkage is intact — a
 *     byte-identical copy of an already-inconsistent point-in-time snapshot
 * would pass and still be unusable. runRestore() therefore
 *     always runs the real production chain-integrity check
 *     (scripts/dr/validate.js's verifyAuditChainIntegrity(), the same probe
 *     validateRestoredState() uses) before resolving, and throws rather than
 *     returning if it fails — "restore -> integrity verification -> success"
 *     is enforced structurally here, not left to the caller to remember to
 *     run `dr:validate` as a separate step. Dispatches on
 *     manifest.auditOrderingMode (recorded at BACKUP time — see manifest.js
 *     and backup.js): single-node checks the restored audit.log file exactly
 * as; distributed checks the just-restored audit_chain
 *     rows (the actual hash-chain table loadChainFromPg()/
 *     qodiqa_audit_chain_full_read() read, NOT the differently-named
 *     platform_audit_events table) via the same production chain-walk
 *     function, since a genuinely fresh distributed deployment never
 * produces a local audit.log at all ('s finding — see
 *     components.js's auditLog entry for the full rationale).
 *
 * "Never restore over an existing running instance" (Requirement 2) is
 * enforced structurally: restore refuses to write into a targetRoot that
 * already contains files, unless the caller explicitly passes
 * `allowExisting: true` (which a human operator would only do after
 * confirming, e.g. via a confirmation prompt in a wrapper script — this
 * module itself never prompts, since it must also run non-interactively
 * in CI).
 */

const fs   = require('fs');
const path = require('path');

const { sha256File }          = require('./checksum');
const { assertSafeRestoreTarget } = require('./restoreTargetGuard');
const { verifyManifestChecksum } = require('./manifest');
const { verifyAuditChainIntegrity } = require('./validate');
const { verifyBackupSeal, readArchive, restoreArchiveToFile, BackupCryptoError } = require('./archiveCrypto');
const crypto = require('crypto');

class RestoreError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'RestoreError';
    this.code = code;
  }
}

/**
 * Load and validate the manifest's own integrity (JSON well-formedness +
 * self-checksum). Does NOT touch any component archive file yet.
 */
function loadManifest(backupDir) {
  const manifestPath = path.join(backupDir, 'manifest.json');

  if (!fs.existsSync(manifestPath)) {
    throw new RestoreError(`manifest.json not found in "${backupDir}"`, 'MANIFEST_MISSING');
  }

  let raw;
  try {
    raw = fs.readFileSync(manifestPath, 'utf8');
  } catch (err) {
    throw new RestoreError(`cannot read manifest.json: ${err.message}`, 'MANIFEST_UNREADABLE');
  }

  let manifest;
  try {
    manifest = JSON.parse(raw);
  } catch (err) {
    throw new RestoreError(`manifest.json is corrupted (invalid JSON): ${err.message}`, 'MANIFEST_CORRUPT');
  }

  if (!verifyManifestChecksum(manifest)) {
    throw new RestoreError(
      'manifest checksum mismatch — the manifest has been tampered with or corrupted; refusing to trust any checksum in it',
      'MANIFEST_CHECKSUM_MISMATCH',
    );
  }

  if (!Array.isArray(manifest.components)) {
    throw new RestoreError('manifest.components is missing or not an array', 'MANIFEST_MALFORMED');
  }

  // an encrypted backup's manifest must carry a valid HMAC seal (encrypt-then-MAC, the same
  // scheme as scripts/pg-backup.sh) before ANY checksum in it is trusted; a plaintext backup is refused when policy
  // requires encryption (QODIQA_BACKUP_REQUIRE_ENCRYPTION=true, or NODE_ENV=production without the explicit override).
  try {
    verifyBackupSeal(backupDir, raw, manifest);
  } catch (err) {
    if (err instanceof BackupCryptoError) throw new RestoreError(err.message, err.code);
    throw err;
  }

  return manifest;
}

/**
 * validate every present component's archive file exists and its
 * checksum matches, and that every REQUIRED component is present at all.
 * Throws RestoreError on the first violation. Writes nothing.
 */
function validateComponents(backupDir, manifest) {
  for (const comp of manifest.components) {
    if (typeof comp.name !== 'string' || typeof comp.relativePath !== 'string') {
      throw new RestoreError('manifest contains a malformed component entry', 'MANIFEST_MALFORMED');
    }

    if (!comp.present) {
      if (comp.required) {
        throw new RestoreError(
          `required component "${comp.name}" is missing from the backup`,
          'REQUIRED_COMPONENT_MISSING',
        );
      }
      continue;
    }

    if (typeof comp.archiveFile !== 'string' || typeof comp.sha256 !== 'string') {
      throw new RestoreError(`component "${comp.name}" is marked present but has no archive file / checksum recorded`, 'MANIFEST_MALFORMED');
    }

    const archivePath = path.join(backupDir, comp.archiveFile);
    if (!fs.existsSync(archivePath)) {
      throw new RestoreError(
        `archive file "${comp.archiveFile}" for component "${comp.name}" is missing`,
        'ARCHIVE_FILE_MISSING',
      );
    }

    let actual;
    try {
      actual = sha256File(archivePath);
    } catch (err) {
      throw new RestoreError(`cannot read archive file for "${comp.name}": ${err.message}`, 'ARCHIVE_FILE_UNREADABLE');
    }

    if (actual !== comp.sha256) {
      throw new RestoreError(
        `checksum mismatch for component "${comp.name}" — archive is corrupted (expected ${comp.sha256}, got ${actual})`,
        'CHECKSUM_MISMATCH',
      );
    }

    if (typeof comp.sizeBytes === 'number') {
      const actualSize = fs.statSync(archivePath).size;
      if (actualSize !== comp.sizeBytes) {
        throw new RestoreError(
          `size mismatch for component "${comp.name}" — archive is truncated or corrupted (expected ${comp.sizeBytes} bytes, got ${actualSize})`,
          'SIZE_MISMATCH',
        );
      }
    }
  }

  // a pg_dump-format database component (and its side archives) is checked here too, before anything is written.
  const pgm = manifest.postgres;
  if (pgm && pgm.format === 'pg_dump-custom') {
    for (const [label, e] of [['postgres', pgm], ['postgres chain heads', pgm.chainHeads], ['postgres latest prune', pgm.latestPrune]]) {
      if (!e) { if (label === 'postgres latest prune') continue; throw new RestoreError(`${label}: missing from the manifest`, 'MANIFEST_MALFORMED'); }
      const p = path.join(backupDir, e.archiveFile || '');
      if (typeof e.archiveFile !== 'string' || !fs.existsSync(p)) throw new RestoreError(`${label} archive "${e.archiveFile}" is missing`, 'ARCHIVE_FILE_MISSING');
      if (sha256File(p) !== e.sha256) throw new RestoreError(`checksum mismatch for ${label} archive "${e.archiveFile}" — corrupted or tampered`, 'CHECKSUM_MISMATCH');
      if (typeof e.sizeBytes === 'number' && fs.statSync(p).size !== e.sizeBytes) throw new RestoreError(`size mismatch for ${label} archive "${e.archiveFile}"`, 'SIZE_MISMATCH');
    }
  }
}

/** unpack a directory component bundle (NDJSON) into a NEW directory; every member is checksum-verified. */
function _restoreDirBundle(buf, destDir, comp) {
  fs.mkdirSync(destDir, { recursive: true, mode: 0o750 });
  const lines = buf.toString('utf8').split('\n').filter(Boolean);
  if (typeof comp.fileCount === 'number' && lines.length !== comp.fileCount) {
    throw new RestoreError(`component "${comp.name}": bundle holds ${lines.length} files, the manifest recorded ${comp.fileCount}`, 'BUNDLE_MALFORMED');
  }
  for (const line of lines) {
    let m;
    try { m = JSON.parse(line); } catch { throw new RestoreError(`component "${comp.name}": bundle line is not JSON`, 'BUNDLE_MALFORMED'); }
    if (typeof m.name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(m.name)) throw new RestoreError(`component "${comp.name}": unsafe member name`, 'BUNDLE_MALFORMED');
    const data = Buffer.from(String(m.data || ''), 'base64');
    if (data.length !== m.size || crypto.createHash('sha256').update(data).digest('hex') !== m.sha256) {
      throw new RestoreError(`component "${comp.name}": member "${m.name}" fails its checksum`, 'CHECKSUM_MISMATCH');
    }
    fs.writeFileSync(path.join(destDir, m.name), data, { mode: 0o600, flag: 'wx' });
  }
}

/**
 * copy every present, validated component to its restored location.
 * Only ever called after validateComponents() has raised nothing.
 */
function restoreComponents(backupDir, manifest, targetRoot) {
  const restored = [];
  for (const comp of manifest.components) {
    if (!comp.present) continue;
    const archivePath = path.join(backupDir, comp.archiveFile);
    const destPath     = path.join(targetRoot, comp.relativePath);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    try {
      if (comp.kind === 'dir') {
        _restoreDirBundle(readArchive(backupDir, manifest.encryption || null, comp), destPath, comp);   //
      } else if (manifest.encryption) {
        // decrypt (after re-checking the sealed ciphertext checksum) straight to the restored path —
        // chunked, never the whole component in memory.
        restoreArchiveToFile(backupDir, manifest.encryption, comp, destPath);
      } else {
        fs.copyFileSync(archivePath, destPath);
      }
    } catch (err) {
      if (err instanceof BackupCryptoError) throw new RestoreError(`component "${comp.name}": ${err.message}`, err.code);
      throw err;
    }
    restored.push({ name: comp.name, destPath });
  }
  return restored;
}

/**
 * @param {object} opts
 * @param {string} opts.backupDir             — directory produced by runBackup()
 * @param {string} opts.targetRoot            — clean directory to restore into
 * @param {boolean} [opts.allowExisting]      — permit restoring into a non-empty targetRoot
 * @param {string} [opts.pgConnectionString] — explicit Postgres restore-target
 *   connection string. Falls back to QODIQA_PG_RESTORE_URL / QODIQA_PG_URL /
 *   DATABASE_URL (same precedence restorePostgres() itself uses) when
 *   omitted — resolved ONCE here so the exact same target used for the
 *   Postgres row restore is also the one the distributed-mode audit-chain
 *   probe below queries; re-deriving it independently in two places could
 *   silently diverge.
 * @returns {Promise<{ manifest: object, restored: object[] }>}
 * @throws {RestoreError}
 */
async function runRestore({ backupDir, targetRoot, allowExisting = false, pgConnectionString, erasureLedger = null, allowNoErasureLedger = false } = {}) {
  if (typeof backupDir !== 'string' || !backupDir) {
    throw new RestoreError('backupDir is required', 'INVALID_ARGS');
  }
  if (typeof targetRoot !== 'string' || !targetRoot) {
    throw new RestoreError('targetRoot is required', 'INVALID_ARGS');
  }
  if (!fs.existsSync(backupDir) || !fs.statSync(backupDir).isDirectory()) {
    throw new RestoreError(`backupDir "${backupDir}" does not exist or is not a directory`, 'BACKUP_DIR_MISSING');
  }

  if (!allowExisting && fs.existsSync(targetRoot)) {
    const entries = fs.readdirSync(targetRoot);
    if (entries.length > 0) {
      throw new RestoreError(
        `targetRoot "${targetRoot}" already exists and is not empty — refusing to restore over a live/existing instance`,
        'TARGET_NOT_CLEAN',
      );
    }
  }

  const manifest = loadManifest(backupDir);
  validateComponents(backupDir, manifest);

  fs.mkdirSync(targetRoot, { recursive: true });
  const restored = restoreComponents(backupDir, manifest, targetRoot);
  const walReconciliation = manifest.auditOrderingMode === 'distributed' ? null : reconcileRestoredWal(restored);

  // Postgres row restore, REORDERED to run BEFORE
  // the audit-chain gate: a distributed-mode chain check must validate rows
  // that were JUST restored here, not whatever pre-existed in the target.
  let postgres = null;
  let resolvedPgConnectionString = null;
  if (manifest.postgres) {
    // the target must be explicit and must not be the backup source — no fallback to
    // QODIQA_PG_URL / DATABASE_URL (that restored OVER the source database).
    try { resolvedPgConnectionString = assertSafeRestoreTarget(pgConnectionString, process.env); }
    catch (e) { throw new RestoreError(e.message, e.code); }
  }
  if (manifest.postgres && manifest.postgres.format === 'pg_dump-custom') {
    // pg_restore of the snapshot dump, then the same gates (counts, chain heads, mirror count) — fail closed.
    const { restoreWithPgRestore, resolveConnection } = require('./pgDump');
    try {
      // (3.4) resolvedPgConnectionString was validated above (explicit, != source); PG* variables no longer name a target.
      postgres = await restoreWithPgRestore(backupDir, manifest.postgres, {
        connectionString: resolvedPgConnectionString,
        encryption: manifest.encryption || null,
        auditOrderingMode: manifest.auditOrderingMode === 'distributed' ? 'distributed' : 'single-node',
        deferChainHeadGate: true,
        readSide: (entry) => JSON.parse(readArchive(backupDir, manifest.encryption || null, entry).toString('utf8')),
      });
    } catch (err) {
      if (err instanceof BackupCryptoError || err.name === 'PgDumpError') throw new RestoreError(err.message, err.code);
      throw err;
    }
  } else if (manifest.postgres) {
    const { restorePostgres } = require('./postgres');
    postgres = await restorePostgres(backupDir, manifest.postgres, {
      connectionString: resolvedPgConnectionString,
      encryption: manifest.encryption || null,                                   //
      auditOrderingMode: manifest.auditOrderingMode === 'distributed' ? 'distributed' : 'single-node', //
      deferChainHeadGate: true, // raised below, right after the audit-chain integrity gate
    });
  }

  // mandatory audit-chain integrity gate.
  // Dispatches on manifest.auditOrderingMode — the ground truth recorded AT
  // BACKUP TIME (backup.js, via src/infra/config/deploymentMode.js) for
  // which source is authoritative for THIS backup's audit evidence:
  //
  //   single-node: auditLog is no longer a generically `critical`
  //     FILE_COMPONENTS entry (see components.js), so this branch explicitly
  //     requires it present here to preserve the exact fail-closed guarantee
  //     that existed, then verifies its hash-chain linkage
  //     exactly as before — a checksum match cannot prove that on
  //     its own.
  //
  //   distributed: the local file correctly does not exist for a genuinely
  //     fresh distributed deployment. Evidence instead
  //     comes from the audit_chain rows just restored above,
  //     verified via the SAME production chain-walk function
  //     (validateChainIntegrityFromDurableStoreChunked(), already
  //     mode-dispatching internally), cross-checked against the row count
  //     the backup itself recorded — failing closed if the manifest never
  //     captured a Postgres component at all, never captured the audit
  //     table specifically, or no restore-target connection string is
  //     available. This is the fix for's exact finding: a distributed
  //     backup can now restore to completion, but only with real,
  //     machine-verified proof of audit continuity from its own
  //     authoritative source — never a silent skip.
  const auditOrderingMode = manifest.auditOrderingMode === 'distributed' ? 'distributed' : 'single-node';
  let auditChainCheck;
  if (auditOrderingMode === 'distributed') {
    const auditTable = manifest.postgres && Array.isArray(manifest.postgres.tables)
      ? manifest.postgres.tables.find(t => t.table === 'audit_chain')
      : null;
    if (!manifest.postgres) {
      auditChainCheck = { valid: false, reason: 'DISTRIBUTED_MODE_BACKUP_MISSING_POSTGRES_COMPONENT' };
    } else if (!auditTable || auditTable.present !== true) {
      auditChainCheck = { valid: false, reason: 'DISTRIBUTED_MODE_BACKUP_MISSING_AUDIT_TABLE' };
    } else if (!resolvedPgConnectionString) {
      auditChainCheck = { valid: false, reason: 'PG_CONNECTION_STRING_NOT_AVAILABLE' };
    } else {
      auditChainCheck = verifyAuditChainIntegrity({
        mode: 'distributed',
        connectionString: resolvedPgConnectionString,
        expectedRowCount: auditTable.rowCount,
      });
    }
  } else {
    const auditLogRestored = restored.find(r => r.name === 'auditLog');
    const cpKeys = restored.find(r => r.name === 'checkpointKeys'); // M3: verifies a restored signed base record
    auditChainCheck = auditLogRestored
      ? verifyAuditChainIntegrity({ mode: 'single-node', auditLogPath: auditLogRestored.destPath, checkpointKeysPath: cpKeys ? cpKeys.destPath : undefined })
      : { valid: false, reason: 'AUDIT_LOG_NOT_RESTORED' };
  }

  if (auditChainCheck.valid !== true) {
    throw new RestoreError(
      `restored audit chain failed integrity verification — refusing to report restore success (mode: ${auditOrderingMode}, reason: ${auditChainCheck.reason || 'unknown'})`,
      'AUDIT_CHAIN_INTEGRITY_FAILED',
    );
  }
  // chain-head gate (deferred from restorePostgres so the integrity gate above reports first): mandatory.
  if (postgres && postgres.chainHeadGateError) throw postgres.chainHeadGateError;

  // GDPR erasure replay. A restored
  // backup must never resurrect a subject erased after it was taken, so a
  // PostgreSQL restore needs a SURVIVING ledger source (an off-host export from
  // scripts/dr/erasureLedger.js, or a surviving database), and fails closed
  // without one. allowNoErasureLedger (CLI --no-erasure-ledger) is the explicit,
  // recorded acceptance of the documented backup window instead
  // — never a silent default.
  let erasureReplay = null;
  if (manifest.postgres) {
    const source = erasureLedger || process.env.QODIQA_ERASURE_LEDGER_SOURCE || null;
    if (!source && !allowNoErasureLedger) {
      throw new RestoreError(
        'PostgreSQL restore needs a surviving erasure-ledger source (--erasure-ledger <export.jsonl|postgres-url> or '
        + 'QODIQA_ERASURE_LEDGER_SOURCE) so erasures made after this backup are replayed; pass --no-erasure-ledger '
        + 'to accept the documented backup window instead',
        'ERASURE_LEDGER_REQUIRED',
      );
    }
    if (!resolvedPgConnectionString) {
      throw new RestoreError('erasure replay needs the restore-target connection string', 'PG_CONNECTION_STRING_NOT_AVAILABLE');
    }
    try {
      const { replayErasures } = require('./erasureReplay');
      erasureReplay = await replayErasures({ connectionString: resolvedPgConnectionString, ledgerSource: source });
      erasureReplay.source = source ? 'restored-db+external' : 'restored-db-only (backup window accepted: --no-erasure-ledger)';
    } catch (e) {
      throw new RestoreError(`GDPR erasure replay failed — refusing to report restore success: ${e.code || ''} ${e.message}`, 'ERASURE_REPLAY_FAILED');
    }
  }

  return { manifest, restored, postgres, auditChainCheck, erasureReplay, walReconciliation };
}

/**
 *the restored audit WAL must belong with the RESTORED log — the same test as boot recovery,
 * re-checked here whatever the backup recorded (backups taken carry the WAL unconditionally, and a WAL
 * captured before the log was measured can hold a batch already committed inside it, which boot then refuses):
 *   continues / empty / torn → left for boot recovery (it replays, or discards a torn one)
 *   committed                → set aside as <wal>.committed-batch (renamed, never deleted): every entry is in the log
 *   anything else            → RESTORED_WAL_INCONSISTENT (fail closed; the target is left for inspection)
 */
function reconcileRestoredWal(restored) {
  const walR = restored.find((r) => r.name === 'auditLogWal');
  if (!walR || !fs.existsSync(walR.destPath)) return null;
  const logR = restored.find((r) => r.name === 'auditLog');
  const limit = logR && fs.existsSync(logR.destPath) ? fs.statSync(logR.destPath).size : 0;
  let fit;
  try { fit = require('../audit-log-backup-chain').walFit(logR ? logR.destPath : null, limit, walR.destPath); } catch (e) {
    throw new RestoreError(`the restored audit WAL does not belong with the restored audit log (${e.message}) — refusing to report restore success`, 'RESTORED_WAL_INCONSISTENT');
  }
  if (fit.disposition !== 'committed') return { action: 'kept', ...fit };
  const setAside = `${walR.destPath}.committed-batch`;
  if (fs.existsSync(setAside)) throw new RestoreError(`${setAside} already exists — refusing to overwrite it`, 'RESTORED_WAL_INCONSISTENT');
  fs.renameSync(walR.destPath, setAside);
  return { action: 'set-aside', setAside, ...fit };
}

module.exports = { runRestore, loadManifest, validateComponents, restoreComponents, reconcileRestoredWal, RestoreError };

if (require.main === module) {
  const args = process.argv.slice(2);
  const backupDir  = args[0];
  const targetRoot = args[1];
  const ledgerIdx = args.indexOf('--erasure-ledger');
  runRestore({
    backupDir, targetRoot, allowExisting: args.includes('--allow-existing'),
    erasureLedger: ledgerIdx >= 0 ? args[ledgerIdx + 1] : null,
    allowNoErasureLedger: args.includes('--no-erasure-ledger'),
  })
    .then(({ manifest, restored, erasureReplay, postgres, walReconciliation }) => {
      // (A3-15): rows ON CONFLICT DO NOTHING skipped because the target already held a conflicting row.
      if (postgres && postgres.skippedRows > 0) {
        console.error(JSON.stringify({ event: 'RESTORE_ROWS_SKIPPED', skippedRows: postgres.skippedRows, skippedByTable: postgres.skippedByTable }));
      }
      console.log(JSON.stringify({
        event: 'RESTORE_COMPLETE',
        backupId: manifest.backupId,
        restoredCount: restored.length,
        postgresSkippedRows: postgres ? postgres.skippedRows : null,
        postgresSkippedByTable: postgres ? postgres.skippedByTable : null,
        targetRoot,
        auditWal: walReconciliation,   // kept for boot recovery, or set aside (batch already in the log)
        erasureReplay: erasureReplay && { source: erasureReplay.source, ledgerRows: erasureReplay.ledgerRows, subjectsReErased: erasureReplay.subjectsReErased },
      }, null, 2));
    })
    .catch(err => {
      console.error(JSON.stringify({
        event: 'RESTORE_FAILED',
        code: err.code || 'UNKNOWN',
        error: err.message,
      }, null, 2));
      process.exitCode = 1;
    });
}
