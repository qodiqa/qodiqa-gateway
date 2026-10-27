'use strict';

/**
 * Persistence Recovery Journal — Component #13 (FAILOVER-1 remediation)
 *
 * Filesystem-backed durable fallback for the Persistence Recovery Queue.
 *
 * ROOT CAUSE (see docs/protocol/AUDIT-SCHEMA-V8.md, "Decision Update:
 * Durable Filesystem Journal for Persistence Recovery Queue (FAILOVER-1)"):
 * CHAIN-3 made PostgreSQL the recovery queue's sole durable store
 * (persistence_recovery_queue, migration 032), which correctly removed Redis
 * as a single point of failure. But it left one disclosed residual gap: if
 * PostgreSQL itself is unavailable at the exact moment a write AND the
 * recovery-queue INSERT for that write both fail, there is no third,
 * independent durable store — the operation is lost. For AUDIT_CHAIN_PG_SAVE
 * / EVIDENCE_CHAIN_SAVE this is harmless (the file-based audit-log.js chain
 * is already the mandatory primary store, unaffected by PG outages), but for
 * ATTESTATION_SAVE / CERTIFICATION_SAVE / PORTAL_VERIFICATION_SAVE /
 * WEBHOOK_DELIVERY there is no such file-based backstop anywhere else in the
 * platform.
 *
 * This module is that third, independent store: a local, disk-backed,
 * crash-safe journal that recoveryManager.enqueue() falls back to ONLY when
 * queue.enqueue() (the PostgreSQL INSERT) itself throws. It reuses the exact
 * durability idiom already proven by audit-log.js — atomic temp-file write,
 * fsync before rename, rename as the commit point — rather than introducing
 * a new persistence technology.
 *
 * LAYOUT:
 *   One file per operation, named by a SHA-256 hash of operationId (never
 *   the raw operationId itself, which may contain colons and other
 *   characters unsafe for a filename, e.g. "whd:<endpointId>:<eventId>").
 *   Re-journaling the same operationId overwrites its file deterministically
 *   — this is what makes duplicate journal-append attempts (e.g. a second
 *   dual-write failure for the same retry) naturally idempotent, mirroring
 *   queue.enqueue()'s own `ON CONFLICT (operation_id) DO UPDATE`.
 *
 * CRASH SAFETY:
 *   Write: JSON.stringify → write to "<file>.tmp" → fsync the tmp file →
 *   rename to "<file>.json" (atomic on both POSIX and NTFS for a same-
 *   directory rename). A crash before the rename leaves, at worst, an
 *   orphaned .tmp file (ignored by listEntries()); a crash after the rename
 *   leaves a fully-committed entry. There is no window where a reader can
 *   observe a partially-written entry.
 *
 *   Delete: plain fs.unlink after the caller has confirmed the entry was
 *   durably re-enqueued into PostgreSQL. If the process crashes between that
 *   confirmation and the unlink, the entry is simply replayed again on next
 *   scan — safe, because queue.enqueue() is idempotent per operationId.
 *
 * CORRUPTION HANDLING:
 *   Every entry carries a SHA-256 checksum over its own canonical payload.
 *   listEntries() verifies it on read; a checksum mismatch or JSON parse
 *   failure quarantines the file (renamed with a ".corrupt" suffix) rather
 *   than crashing the worker or silently dropping it — an operator can still
 *   recover the raw bytes for forensic inspection.
 */

const fs   = require('fs');
const fsp  = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { emit } = require('../../../services/logger');

const SOURCE = 'PERSISTENCE_RECOVERY_JOURNAL';

const JOURNAL_DIR = process.env.QODIQA_PRQ_JOURNAL_DIR
  || path.join(__dirname, '..', '..', '..', 'data', 'prq-journal');

// ── Directory bootstrap ────────────────────────────────────────────────────────

let _dirEnsured = false;
async function _ensureDir() {
  if (_dirEnsured) return;
  await fsp.mkdir(JOURNAL_DIR, { recursive: true });
  _dirEnsured = true;
}

function _ensureDirSync() {
  if (_dirEnsured) return;
  fs.mkdirSync(JOURNAL_DIR, { recursive: true });
  _dirEnsured = true;
}

// ── Filename derivation ────────────────────────────────────────────────────────

function _fileStem(operationId) {
  return crypto.createHash('sha256').update(String(operationId)).digest('hex');
}

function _entryPath(operationId) {
  return path.join(JOURNAL_DIR, `${_fileStem(operationId)}.json`);
}

// ── Checksum ────────────────────────────────────────────────────────────────────

function _checksumOf(record) {
  const { checksum, ...rest } = record;
  return crypto.createHash('sha256').update(JSON.stringify(rest)).digest('hex');
}

// ── fsync helpers (mirrors audit-log.js's proven idiom) ────────────────────────

async function _fsyncAsync(filePath) {
  const fh = await fsp.open(filePath, 'r+');
  try { await fh.sync(); } finally { await fh.close(); }
}

// Best-effort directory fsync so the rename's directory-entry update is
// itself durable, not just the file content. Not supported on all platforms
// (e.g. opening a directory handle for fsync fails on Windows) — swallowed
// deliberately since the file-level fsync above already guarantees the
// entry's own content survives a crash; this is defense in depth, not the
// primary durability guarantee.
async function _fsyncDirBestEffort(dirPath) {
  try {
    const fh = await fsp.open(dirPath, 'r');
    try { await fh.sync(); } finally { await fh.close(); }
  } catch { /* platform does not support directory fsync — ignore */ }
}

// ── Write ─────────────────────────────────────────────────────────────────────

/**
 * Durably append (or idempotently overwrite) one operation into the journal.
 *
 * @param {object} operation
 * @param {string} operation.operationId
 * @param {string} operation.operationType
 * @param {string} operation.service
 * @param {object} operation.payload
 * @param {string} [operation.createdAt]
 * @param {number} [operation.retryCount]
 * @param {string} [operation.lastError]
 * @param {Array}  [operation.errorHistory]
 * @param {string} [operation.originalError]  Human-readable reason PG enqueue failed
 * @returns {Promise<{ journalId: string }>}
 */
async function appendEntry(operation) {
  await _ensureDir();

  const {
    operationId,
    operationType,
    service,
    payload,
    createdAt    = new Date().toISOString(),
    retryCount   = 0,
    lastError    = null,
    errorHistory = [],
    originalError = null,
  } = operation;

  if (!operationId)   throw new Error(`${SOURCE}: operationId is required`);
  if (!operationType) throw new Error(`${SOURCE}: operationType is required`);

  const journalId = _fileStem(operationId);
  const finalPath = _entryPath(operationId);
  const tmpPath   = `${finalPath}.tmp`;

  const record = {
    operationId,
    operationType,
    service,
    payload,
    createdAt,
    retryCount,
    lastError,
    errorHistory,
    originalError,
    journaledAt: new Date().toISOString(),
  };
  record.checksum = _checksumOf(record);

  const body = JSON.stringify(record);

  await fsp.writeFile(tmpPath, body, 'utf8');
  await _fsyncAsync(tmpPath);

  try {
    await fsp.rename(tmpPath, finalPath);
  } catch {
    // Cross-device rename fallback (mirrors audit-log.js's checksum-save idiom).
    await fsp.copyFile(tmpPath, finalPath);
    await _fsyncAsync(finalPath);
    try { await fsp.unlink(tmpPath); } catch { /* best-effort cleanup */ }
  }

  await _fsyncDirBestEffort(JOURNAL_DIR);

  // O9: first N per window in full, the rest counted (src/observability/aggregatedEmit.js failureEmit)
  require('../../observability/aggregatedEmit').failureEmit(emit, 'WARN', 'JOURNAL_ENTRY_WRITTEN', {
    source: SOURCE, journalId, operationId, operationType, service,
  });

  return { journalId };
}

// ── Read ──────────────────────────────────────────────────────────────────────

/**
 * List every durable journal entry, oldest first (by journaledAt).
 * Corrupt entries (malformed JSON, checksum mismatch) are quarantined
 * (renamed with a ".corrupt" suffix) and excluded from the result rather
 * than thrown — a single damaged file must never block replay of the rest
 * of the journal.
 *
 * @returns {Promise<Array<{ journalId: string, operation: object, journaledAt: string }>>}
 */
async function listEntries() {
  await _ensureDir();

  let files;
  try {
    files = await fsp.readdir(JOURNAL_DIR);
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }

  const jsonFiles = files.filter(f => f.endsWith('.json'));
  const entries = [];

  for (const file of jsonFiles) {
    const filePath = path.join(JOURNAL_DIR, file);
    const journalId = file.slice(0, -'.json'.length);

    let record;
    try {
      const raw = await fsp.readFile(filePath, 'utf8');
      record = JSON.parse(raw);
    } catch (err) {
      await _quarantine(filePath, `parse_error: ${err.message}`);
      continue;
    }

    const expectedChecksum = _checksumOf(record);
    if (record.checksum !== expectedChecksum) {
      await _quarantine(filePath, 'checksum_mismatch');
      continue;
    }

    entries.push({
      journalId,
      operation: {
        operationId:   record.operationId,
        operationType: record.operationType,
        service:       record.service,
        payload:       record.payload,
        createdAt:     record.createdAt,
        retryCount:    record.retryCount,
        lastError:     record.lastError,
        errorHistory:  record.errorHistory,
      },
      originalError: record.originalError,
      journaledAt:   record.journaledAt,
    });
  }

  entries.sort((a, b) => new Date(a.journaledAt).getTime() - new Date(b.journaledAt).getTime());
  return entries;
}

async function _quarantine(filePath, reason) {
  const quarantinePath = `${filePath}.corrupt`;
  try {
    await fsp.rename(filePath, quarantinePath);
  } catch { /* best-effort — if even the rename fails, leave the file in place */ }

  emit('ERROR', 'JOURNAL_ENTRY_CORRUPT', {
    source: SOURCE, filePath, quarantinePath, reason,
  });
}

// ── Delete ────────────────────────────────────────────────────────────────────

/**
 * Remove a journal entry after its operation has been durably re-enqueued
 * into PostgreSQL. Never throws on a missing file — a concurrent/duplicate
 * cleanup attempt (e.g. after a crash between re-enqueue and unlink, then a
 * re-run that also succeeds) is a no-op, not an error.
 *
 * @param {string} journalId
 */
async function removeEntry(journalId) {
  const filePath = path.join(JOURNAL_DIR, `${journalId}.json`);
  try {
    await fsp.unlink(filePath);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

/**
 * @returns {Promise<{ depth: number, oldestEntryAgeMs: number, totalBytes: number }>}
 */
async function getStats() {
  const entries = await listEntries();
  if (entries.length === 0) return { depth: 0, oldestEntryAgeMs: 0, totalBytes: 0 };

  const oldest = entries[0];
  const oldestEntryAgeMs = Math.max(0, Date.now() - new Date(oldest.journaledAt).getTime());

  let totalBytes = 0;
  for (const entry of entries) {
    try {
      const stat = await fsp.stat(path.join(JOURNAL_DIR, `${entry.journalId}.json`));
      totalBytes += stat.size;
    } catch { /* file may have been replayed/removed concurrently — skip */ }
  }

  return { depth: entries.length, oldestEntryAgeMs, totalBytes };
}

/**
 * can the journal take a write right now? Creates the directory if needed, writes and fsyncs a small probe file, removes it.
 * @returns {Promise<boolean>}
 */
async function probeWritable() {
  try {
    await fsp.mkdir(JOURNAL_DIR, { recursive: true });
    const p = path.join(JOURNAL_DIR, '.probe-' + process.pid + '-' + Date.now());
    const fh = await fsp.open(p, 'w');
    try { await fh.write('probe'); await fh.sync(); } finally { await fh.close(); }
    await fsp.unlink(p);
    return true;
  } catch { return false; }
}

module.exports = {
  probeWritable,
  appendEntry,
  listEntries,
  removeEntry,
  getStats,
  JOURNAL_DIR,
  // Test-only exports
  _fileStem,
  _entryPath,
  _ensureDirSync,
};
