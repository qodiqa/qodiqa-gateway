'use strict';

/**
 * QODIQA Disaster Recovery — Backup
 *
 * Backs up every file-based persistent component (Requirement: "Backup
 * Coverage") into a self-contained backup directory:
 *
 *   <targetDir>/
 *     manifest.json         — sealed manifest (see manifest.js)
 *     auditLog.dat           (present iff the source file exists)
 *     auditLogWal.dat
 *     auditLogSum.dat
 *     keyStore.dat
 *     keyArchive.dat
 *     policyStore.dat
 *     organizations.dat
 *     tenants.dat
 * anchorExport.dat, witnessLog.dat, macKeys.dat, transparencyKeys.dat, …
 * witnessPositions.bundle, prqJournal.bundle
 * postgres.dump
 *     pg_chain_heads.json, pg_audit_chain_prunes_latest.json   (same snapshot, small side archives)
 *     pg_<table>.json        (only with --postgres-format=json-rows, the earlier layer)
 * every archive gains .enc when encrypted, and is written and read in chunks
 *     redis_nonces.json      (only when --with-redis — DIAGNOSTIC ONLY, see redis.js)
 *
 * Determinism: the manifest's component list is always emitted in the fixed
 * order defined by components.js, and every checksum is a plain SHA-256 of
 * the copied file's bytes — running a backup twice against unchanged source
 * files produces byte-identical archive files (only backupId/createdAt/
 * manifestChecksum differ, as expected for two distinct backup events).
 *
 * A missing OPTIONAL component is recorded (present:false) and is not an
 * error. A missing file that is normally present but currently absent
 * (e.g. audit.log before the very first append) is likewise recorded, not
 * fabricated — restore later decides whether that's acceptable based on
 * each component's `required` flag.
 */

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const { FILE_COMPONENTS, isRequired } = require('./components');
const { sha256File, forEachChunkSync } = require('./checksum');
const { buildManifest }   = require('./manifest');
const { resolveBackupEncryption, makeArchiveWriter, encryptionManifestField, writeSeal, encryptFileToArchive } = require('./archiveCrypto');
const pkg = require('../../package.json');

// a directory component is bundled into one NDJSON archive ({ name, mode, size, sha256, data(base64) } per
// file). Its members are small claim/journal records; the cap keeps the bundle far below any whole-buffer limit and
// fails the backup loudly (never a partial bundle) if a directory ever grows past it.
const DIR_BUNDLE_MAX_BYTES = 128 * 1024 * 1024;
const DIR_MEMBER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

class BackupError extends Error {
  constructor(message, code) { super(message); this.name = 'BackupError'; this.code = code; }
}

/** Length of the prefix of filePath up to and including its last '\n' within the first `size` bytes. */
function _completeLinesPrefix(filePath, size) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const buf = Buffer.alloc(65536);
    let end = size;
    while (end > 0) {
      const start = Math.max(0, end - buf.length);
      const n = fs.readSync(fd, buf, 0, end - start, start);
      const nl = buf.subarray(0, n).lastIndexOf(0x0a);
      if (nl >= 0) return start + nl + 1;
      end = start;
    }
    return 0;
  } finally { fs.closeSync(fd); }
}

function _copyPrefix(srcPath, destPath, length) {
  const fd = fs.openSync(destPath, 'wx', 0o600);
  try {
    forEachChunkSync(srcPath, (b) => { let o = 0; while (o < b.length) o += fs.writeSync(fd, b, o, b.length - o); }, { length });
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
}

function _bundleDir(dirPath) {
  const lines = []; let total = 0; let count = 0;
  for (const name of fs.readdirSync(dirPath).sort()) {
    if (name.startsWith('.tmp-')) continue;                       // an in-flight witness claim (never a claim yet)
    const p = path.join(dirPath, name);
    const st = fs.statSync(p);
    if (!st.isFile()) continue;
    if (!DIR_MEMBER_NAME.test(name)) throw new BackupError(`directory component member "${name}" has an unsupported name`, 'BACKUP_DIR_MEMBER_INVALID');
    const data = fs.readFileSync(p);
    total += data.length;
    if (total > DIR_BUNDLE_MAX_BYTES) throw new BackupError(`directory ${dirPath} exceeds ${DIR_BUNDLE_MAX_BYTES} bytes — refusing a partial bundle`, 'BACKUP_DIR_TOO_LARGE');
    lines.push(JSON.stringify({ name, mode: st.mode & 0o777, size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex'), data: data.toString('base64') }));
    count++;
  }
  return { bundle: Buffer.from(lines.length ? `${lines.join('\n')}\n` : '', 'utf8'), fileCount: count };
}

function _backupOne(name, srcPath, targetDir, meta, components, enc, ctx) {
  const required = isRequired(meta, ctx);
  const base = { name, required, description: meta.description, relativePath: meta.restorePath };
  const isDir = meta.kind === 'dir';
  let st = null;
  try { st = srcPath ? fs.statSync(srcPath) : null; } catch { st = null; }
  const present = !!st && (isDir ? st.isDirectory() : st.isFile());
  if (!present) { components.push({ ...base, present: false }); return; }

  if (isDir) {
    const { bundle, fileCount } = _bundleDir(srcPath);
    const written = makeArchiveWriter(targetDir, enc)(`${name}.bundle`, bundle);
    const archivePath = path.join(targetDir, written.archiveFile);
    components.push({ ...base, present: true, kind: 'dir', fileCount, archiveFile: written.archiveFile,
      sha256: written.sha256 || sha256File(archivePath), sizeBytes: written.sizeBytes || fs.statSync(archivePath).size });
    return;
  }

  // C-3: an append-only NDJSON file is copied as the prefix up to its last complete line at the size seen now;
  // an append in flight is not yet acknowledged. A file replaced or shrunk while it was copied fails the backup.
  const length = meta.appendOnlyLines ? _completeLinesPrefix(srcPath, st.size) : null;
  const archiveFile = enc && enc.encrypt ? `${name}.dat.enc` : `${name}.dat`;
  const destPath = path.join(targetDir, archiveFile);
  let entry;
  // streamed, chunk by chunk (readFileSync failed every component above 2 GiB).
  if (enc && enc.encrypt) {
    const w = encryptFileToArchive(srcPath, destPath, enc.encKey, { length });
    entry = { archiveFile, sha256: w.sha256, sizeBytes: w.sizeBytes };
  } else {
    if (length === null) fs.copyFileSync(srcPath, destPath); else _copyPrefix(srcPath, destPath, length);
    entry = { archiveFile, sha256: sha256File(destPath), sizeBytes: fs.statSync(destPath).size };
  }
  if (meta.appendOnlyLines) {
    let after = null;
    try { after = fs.statSync(srcPath); } catch { after = null; }
    if (!after || after.ino !== st.ino || after.dev !== st.dev || after.size < st.size) {
      throw new BackupError(`${name}: ${srcPath} was replaced or shrunk while it was copied (a retention prune?) — this backup is not consistent; run it again`, 'BACKUP_SOURCE_REPLACED');
    }
    entry.sourceBytes = length;
  }
  components.push({ ...base, present: true, ...entry });
  return st;
}

// the audit WAL is captured (into memory, in its manifest slot) BEFORE the log, as C-3
// requires, but its fate is decided only AFTER the log's prefix is known. The WAL holds the batch being written at
// capture time; by the time the log is measured that batch is either (a) not yet — or only partly — in the prefix: it
// continues the prefix and boot recovery replays it (kept), or (b) wholly committed inside the prefix with later
// entries after it: restoring it makes boot refuse ("the WAL batch does not continue the log"), and omitting it loses
// nothing, every entry being in the log (omitted, recorded in the manifest). Anything else is a WAL that does not
// belong to this log: the backup fails closed. The same test as scripts/backup-audit-log.sh, on the exact
// bytes then archived; restore.js re-checks it against the restored log.
const WAL_CAPTURE_MAX_BYTES = 64 * 1024 * 1024;   // a WAL holds one batch (≤ 1 MiB); anything far larger is not a WAL

function _captureWal(meta, srcPath, ctx, components) {
  const slot = components.length;
  const base = { name: meta.name, required: isRequired(meta, ctx), description: meta.description, relativePath: meta.restorePath };
  components.push({ ...base, present: false });       // filled by _settleWal; stays absent if the file is
  let data = null;
  try {
    const st = srcPath ? fs.statSync(srcPath) : null;
    if (st && st.isFile()) {
      if (st.size > WAL_CAPTURE_MAX_BYTES) throw new BackupError(`${meta.name}: ${srcPath} is ${st.size} bytes — not a WAL batch; refusing`, 'BACKUP_WAL_INCONSISTENT');
      data = fs.readFileSync(srcPath);
    }
  } catch (e) { if (e instanceof BackupError) throw e; if (e.code !== 'ENOENT') throw e; data = null; }   // ENOENT: invalidated between stat and read
  return { meta, base, slot, data };
}

function _settleWal(wal, logPath, logName, logSt, targetDir, components, enc) {
  if (wal.data === null) return;                      // no WAL at capture time: recorded absent, as before
  const logEntry = components.find((c) => c.name === logName);
  const limit = logEntry && logEntry.present ? logEntry.sourceBytes : 0;
  // the check reads the SOURCE log's [0, limit) — the bytes just archived only while it is still the same file
  const sameFile = () => { try { const a = fs.statSync(logPath); return a.ino === logSt.ino && a.dev === logSt.dev && a.size >= limit; } catch { return false; } };
  if (limit > 0 && !sameFile()) throw new BackupError(`${logName}: ${logPath} was replaced or shrunk while it was backed up — this backup is not consistent; run it again`, 'BACKUP_SOURCE_REPLACED');
  let fit;
  try {
    fit = require('../audit-log-backup-chain').walFitText(logPath, limit, wal.data.toString('utf8'));
  } catch (e) {
    throw new BackupError(`${wal.meta.name}: the captured WAL does not belong with the backed-up log prefix (${e.message}) — nothing usable was written; run it again or investigate`, 'BACKUP_WAL_INCONSISTENT');
  }
  if (limit > 0 && !sameFile()) throw new BackupError(`${logName}: ${logPath} was replaced or shrunk while it was backed up — this backup is not consistent; run it again`, 'BACKUP_SOURCE_REPLACED');
  if (fit.disposition === 'committed') {
    components[wal.slot] = { ...wal.base, present: false, omitted: { reason: 'WAL_BATCH_COMMITTED_IN_LOG', entries: fit.entries, logOffset: fit.offset } };
    return;
  }
  const w = makeArchiveWriter(targetDir, enc)(`${wal.meta.name}.dat`, wal.data);
  const p = path.join(targetDir, w.archiveFile);
  if (!(enc && enc.encrypt)) fs.chmodSync(p, 0o600);   // owner-only, like every other plaintext archive copy
  components[wal.slot] = { ...wal.base, present: true, archiveFile: w.archiveFile, sha256: w.sha256 || sha256File(p),
    sizeBytes: w.sizeBytes || fs.statSync(p).size, walDisposition: fit.disposition };
}

// a small JSON document replaced by write-tmp-then-rename (the audit .sum). On POSIX the rename is atomic; on
// Windows a rename over a file another process has open fails and checksumAnchor falls back to a non-atomic copy, so a
// concurrent reader can see it empty or zero-filled (observed: 2 of 12 backups taken under load on Windows). It is read
// whole, must parse, and is re-read a few times if it does not; a document that never parses fails the backup closed.
const JSON_DOC_MAX_BYTES = 1024 * 1024;
const JSON_DOC_READ_ATTEMPTS = 5;

function _backupJsonDocument(name, srcPath, targetDir, meta, components, enc, ctx) {
  const base = { name, required: isRequired(meta, ctx), description: meta.description, relativePath: meta.restorePath };
  let data = null; let lastErr = null;
  for (let attempt = 0; attempt < JSON_DOC_READ_ATTEMPTS; attempt++) {
    let st = null;
    try { st = srcPath ? fs.statSync(srcPath) : null; } catch { st = null; }
    if (!st || !st.isFile()) { components.push({ ...base, present: false }); return; }
    if (st.size > JSON_DOC_MAX_BYTES) throw new BackupError(`${name}: ${srcPath} is ${st.size} bytes — not the expected small JSON document; refusing`, 'BACKUP_COMPONENT_INVALID');
    try { const buf = fs.readFileSync(srcPath); JSON.parse(buf.toString('utf8')); data = buf; break; } catch (e) { lastErr = e; }
    const until = Date.now() + 20 * (attempt + 1); while (Date.now() < until) { /* brief synchronous back-off: the writer finishes its copy */ }
  }
  if (data === null) throw new BackupError(`${name}: ${srcPath} did not parse as JSON after ${JSON_DOC_READ_ATTEMPTS} reads (${lastErr && lastErr.message}) — refusing to archive a torn checksum`, 'BACKUP_COMPONENT_INVALID');
  const w = makeArchiveWriter(targetDir, enc)(`${name}.dat`, data);
  const p = path.join(targetDir, w.archiveFile);
  if (!(enc && enc.encrypt)) fs.chmodSync(p, 0o600);   // owner-only, like every other plaintext archive copy
  components.push({ ...base, present: true, archiveFile: w.archiveFile, sha256: w.sha256 || sha256File(p), sizeBytes: w.sizeBytes || fs.statSync(p).size });
}

/**
 * @param {object} [opts]
 * @param {string} [opts.outDir]           — defaults to backups/qodiqa-backup-<timestamp>
 * @param {boolean} [opts.includePostgres] — also back up PostgreSQL (QODIQA_PG_URL / DATABASE_URL, or the libpq PG* variables)
 * @param {'pg_dump'|'json-rows'} [opts.postgresFormat] — pg_dump (default, every shipped schedule); json-rows
 *   only on explicit request (the earlier per-table JSON layer; fails on tables above ~512 MB)
 * @param {boolean} [opts.includeRedis]    — also snapshot nonce keys (diagnostic only)
 * @param {string}  [opts.rootDir]         — override the "relative to" root (tests only)
 * @returns {Promise<{ backupId: string, targetDir: string, manifestPath: string, manifest: object }>}
 */
async function runBackup(opts = {}) {
  const {
    outDir,
    includePostgres = false,
    postgresFormat = 'pg_dump',
    includeRedis = false,
    rootDir = require('./components').ROOT,
  } = opts;
  if (postgresFormat !== 'pg_dump' && postgresFormat !== 'json-rows') {
    throw new BackupError(`unknown postgres format "${postgresFormat}" (pg_dump | json-rows)`, 'INVALID_ARGS');
  }

  // resolve the encryption policy FIRST — a refused plaintext backup (encryption required by
  // QODIQA_BACKUP_REQUIRE_ENCRYPTION=true or NODE_ENV=production, no key) or an invalid key fails before anything is
  // written. See archiveCrypto.js for the scheme (identical to scripts/pg-backup.sh) and the plaintext policy.
  const enc = resolveBackupEncryption(process.env);
  // Pilot: backups are off-peak — refused outside QODIQA_BACKUP_WINDOW_UTC, before anything is written.
  require('./backupWindow').assertInBackupWindow(process.env);

  // the control plane decides where RBAC/identities/policies live. In 'pg' (always, in production) they are
  // only in PostgreSQL, so a backup without it would silently drop them — refused before anything is written.
  const ctx = { controlPlaneBackend: require('../../src/core/controlPlane').resolveBackend(process.env) };
  if (ctx.controlPlaneBackend === 'pg' && !includePostgres) {
    throw new BackupError('the control plane (RBAC, signing identities, tenants, policies) lives in PostgreSQL — a backup without --with-postgres would omit it; nothing was written', 'BACKUP_POSTGRES_REQUIRED');
  }
  // production requires anchoring; a backup job that does not point at the anchor export (and, for
  // a local witness, its log) would silently omit them.
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.QODIQA_ANCHOR_EXPORT_PATH) {
      throw new BackupError('QODIQA_ANCHOR_EXPORT_PATH is not set — production anchoring is mandatory and its export must be backed up; nothing was written', 'BACKUP_COMPONENT_UNCONFIGURED');
    }
    if (process.env.QODIQA_WITNESS_MODE === 'local' && !process.env.QODIQA_WITNESS_LOG_PATH) {
      throw new BackupError('QODIQA_WITNESS_MODE=local but QODIQA_WITNESS_LOG_PATH is not set — the witness state must be backed up; nothing was written', 'BACKUP_COMPONENT_UNCONFIGURED');
    }
  }

  const backupId  = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const targetDir = outDir || path.join(rootDir, 'backups', `qodiqa-backup-${createdAt.replace(/[:.]/g, '-')}`);

  // C-3: the database snapshot is taken FIRST (and held), so the files copied next are all at or after it.
  let snapshot = null;
  if (includePostgres && postgresFormat === 'pg_dump') {
    snapshot = await require('./pgDump').takeSnapshot();
  }

  let postgres = null;
  let components;
  try {
    // PL13-12: the backup directory is created owner-only (0700) — it holds every tenant's rows
    // and copies of the key stores.: with QODIQA_BACKUP_ENCRYPTION_KEY set, no plaintext archive is
    // written at all.
    fs.mkdirSync(targetDir, { recursive: true, mode: 0o700 });

    components = [];
    for (const comp of FILE_COMPONENTS) {
      const srcPath = comp.resolve();
      // C-3: companions (checkpoints, base, .wal, .sum) BEFORE the file they describe.
      let wal = null;
      for (const companion of comp.companions || []) {
        if (companion.walOf === comp.name) { wal = _captureWal(companion, srcPath ? srcPath + companion.suffix : null, ctx, components); continue; }
        if (companion.jsonDocument) { _backupJsonDocument(companion.name, srcPath ? srcPath + companion.suffix : null, targetDir, companion, components, enc, ctx); continue; }
        _backupOne(companion.name, srcPath ? srcPath + companion.suffix : null, targetDir, companion, components, enc, ctx);
      }
      const copied = _backupOne(comp.name, srcPath, targetDir, comp, components, enc, ctx);
      if (wal) _settleWal(wal, srcPath, comp.name, copied, targetDir, components, enc);
    }

    if (snapshot) {
      const snap = snapshot;
      const dumped = await snap.dump(targetDir, enc);   // ends the snapshot transaction (success or failure)
      snapshot = null;
      const side = makeArchiveWriter(targetDir, enc);
      const sideEntry = (fileName, value) => {
        const w = side(fileName, JSON.stringify(value));
        const p = path.join(targetDir, w.archiveFile);
        return { archiveFile: w.archiveFile, sha256: w.sha256 || sha256File(p), sizeBytes: w.sizeBytes || fs.statSync(p).size };
      };
      postgres = {
        ...snap.facts,
        archiveFile: dumped.archiveFile, sha256: dumped.sha256, sizeBytes: dumped.sizeBytes,
        // small side archives read in the same snapshot: the chain-head rows and the newest prune
        // row — so dr:verify and the gates need no pg_restore of the whole archive
        chainHeads: sideEntry('pg_chain_heads.json', snap.heads),
        latestPrune: snap.latestPrune ? sideEntry('pg_audit_chain_prunes_latest.json', snap.latestPrune) : null,
        dumpedAt: new Date().toISOString(),
      };
    } else if (includePostgres) {
      const { dumpPostgres } = require('./postgres');
      postgres = await dumpPostgres(targetDir, { writeArchive: makeArchiveWriter(targetDir, enc) });
    }
  } catch (e) {
    if (snapshot) await snapshot.abort();
    throw e;
  }

  let redis = null;
  if (includeRedis) {
    const { snapshotRedis } = require('./redis');
    redis = await snapshotRedis(targetDir);
  }

  // record which source is authoritative for THIS backup's audit
  // evidence, using the exact same resolution server/startup.js's own
  // DEPLOYMENT_MODE_RESOLVED boot log uses — not re-derived or guessed by
  // restore.js later, which may run on a different host/process entirely.
  const { auditOrderingMode } = require('../../src/infra/config/deploymentMode').getResolvedDeploymentConfig();

  const manifest = buildManifest({
    backupId,
    createdAt,
    appVersion: pkg.version,
    components,
    postgres,
    redis,
    auditOrderingMode,
    encryption: enc.encrypt ? encryptionManifestField() : null,
    controlPlaneBackend: ctx.controlPlaneBackend,           //
  });

  const manifestPath = path.join(targetDir, 'manifest.json');
  const manifestText = JSON.stringify(manifest, null, 2);
  fs.writeFileSync(manifestPath, manifestText, 'utf8');
  // encrypt-then-MAC — the manifest carries every ciphertext's sha256; its HMAC seal authenticates all of them.
  if (enc.encrypt) writeSeal(targetDir, Buffer.from(manifestText, 'utf8'), enc.hmacKey);

  return { backupId, targetDir, manifestPath, manifest };
}

module.exports = { runBackup, BackupError };

if (require.main === module) {
  const path2 = require('path');
  const { writeMetricsFile } = require('./metricsFile');
  const { postAlert }        = require('./alert');
  const { enforceRetention }  = require('./retention');

  const args = process.argv.slice(2);
  const outDir = args.find(a => !a.startsWith('--'));
  const startedAtMs = Date.now();

  runBackup({
    outDir,
    includePostgres: args.includes('--with-postgres'),
    // pg_dump unless the JSON-rows layer is asked for explicitly (never by a shipped schedule)
    postgresFormat:  args.includes('--postgres-format=json-rows') ? 'json-rows' : 'pg_dump',
    includeRedis:    args.includes('--with-redis'),
  })
    .then(({ targetDir, manifest }) => {
      console.log(JSON.stringify({
        event: 'BACKUP_COMPLETE',
        backupId: manifest.backupId,
        targetDir,
        componentCount: manifest.components.length,
        componentsPresent: manifest.components.filter(c => c.present).length,
      }, null, 2));

      writeMetricsFile(process.env.QODIQA_BACKUP_METRICS_FILE, {
        qodiqa_dr_backup_success: 1,
        qodiqa_dr_backup_last_success_timestamp_seconds: Math.floor(Date.now() / 1000),
        qodiqa_dr_backup_duration_seconds: (Date.now() - startedAtMs) / 1000,
        qodiqa_dr_backup_components_present: manifest.components.filter(c => c.present).length,
      });

      // --retain is opt-in: enforces tiered retention over the PARENT of
      // targetDir (the backups root each timestamped run lives under), not
      // just this one run's directory. Left off by default so existing
      // callers (tests, `npm run dr:backup`) keep today's behavior exactly.
      if (args.includes('--retain')) {
        const retentionResult = enforceRetention(path2.dirname(targetDir));
        console.log(JSON.stringify({ event: 'BACKUP_RETENTION_ENFORCED', ...retentionResult }, null, 2));
      }
    })
    .catch(err => {
      console.error(JSON.stringify({ event: 'BACKUP_FAILED', code: err.code || null, error: err.message }, null, 2));
      writeMetricsFile(process.env.QODIQA_BACKUP_METRICS_FILE, {
        qodiqa_dr_backup_success: 0,
        qodiqa_dr_backup_last_failure_timestamp_seconds: Math.floor(Date.now() / 1000),
      }, { preserve: ['qodiqa_dr_backup_last_success_timestamp_seconds'] }); // keep the last good run's time
      postAlert(process.env.ALERT_WEBHOOK_URL, `QODIQA DR backup FAILED: ${err.message}`)
        .finally(() => { process.exitCode = 1; });
    });
}
