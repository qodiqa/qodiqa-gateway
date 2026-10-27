'use strict';

/**
 * step 6: "it is included in both backup paths and in dr:verify") — OFFLINE check of the signed audit
 * base record inside a backup directory. No database connection, no KEK: the checkpoint public keys are stored in
 * clear in the backed-up checkpoint key file (only private keys are encrypted).
 *
 * Fails (returns errors) when:
 *   · a base record is present but unreadable, its signature does not verify with a published non-revoked key from
 *     the backed-up checkpoint key store, or the key store is missing (AUDIT_BASE_UNVERIFIABLE);
 *   · the backed-up audit.log does not start at GENESIS and there is no base record (AUDIT_BASE_MISSING);
 *   · the log's first entry does not chain from the base record (AUDIT_BASE_MISMATCH);
 *   · the pg_dump path's newest audit_chain_prunes row (which carries the same base record) does not verify, or
 *     disagrees with the file base record (AUDIT_BASE_BACKUP_INCONSISTENT).
 * The same rules as audit-log.js _resolveStart(), applied to backup files.
 */

const fs = require('fs');
const path = require('path');
const { verifyCheckpoint } = require('../../src/core/audit/checkpoint/checkpoint');
const { readArchive, readArchiveFirstLine } = require('./archiveCrypto');

/** keyId → SPKI DER Buffer from a checkpoint key file's JSON (public keys only; revoked/unknown keys throw). */
function publicKeyResolverFromKeyFile(keyFileText) {
  const data = JSON.parse(keyFileText);
  const keys = (data && data.keys) || {};
  return (keyId) => {
    const k = keys[keyId];
    if (!k) throw new Error(`unknown checkpoint keyId "${keyId}"`);
    if (k.status === 'revoked') throw new Error(`checkpoint key "${keyId}" is revoked`);
    return Buffer.from(k.publicKeyDer, 'base64');
  };
}

function firstLine(filePath) {
  const fd = fs.openSync(filePath, 'r');
  try {
    const chunks = []; const buf = Buffer.alloc(65536); let pos = 0;
    for (;;) {
      const n = fs.readSync(fd, buf, 0, buf.length, pos);
      if (n <= 0) break;
      const nl = buf.subarray(0, n).indexOf(0x0a);
      if (nl >= 0) { chunks.push(Buffer.from(buf.subarray(0, nl))); break; }
      chunks.push(Buffer.from(buf.subarray(0, n))); pos += n;
    }
    const s = Buffer.concat(chunks).toString('utf8').trim();
    return s || null;
  } finally { fs.closeSync(fd); }
}

/** Classify a base record against the log's first line. Returns { state } or { error }. */
function classifyStart(base, firstLineText) {
  let first = null;
  if (firstLineText) { try { first = JSON.parse(firstLineText); } catch { return { error: 'AUDIT_BASE_UNVERIFIABLE: the first log line is not valid JSON' }; } }
  const legacy = !!first && (!('inputHash' in first) || first.inputHash == null);
  if (!base) {
    if (first && !legacy && first.prevHash !== 'GENESIS') return { error: `AUDIT_BASE_MISSING: the log's first entry chains from ${first.prevHash}, not GENESIS, and the backup holds no signed base record` };
    return { state: 'none' };
  }
  const head = base.checkpoint.payload.headHash;
  if (!first || (!legacy && first.prevHash === head)) return { state: 'rebased' };
  if (legacy || first.prevHash === 'GENESIS') return { state: 'full-file' };
  return { error: `AUDIT_BASE_MISMATCH: the log's first entry chains from ${first.prevHash}, the signed base record ends at ${head}` };
}

/**
 * @param {string} backupDir
 * @param {object} manifest  loaded backup manifest
 * @returns {{ errors: string[], state: string|null, checkpointId: string|null }}
 */
function verifyBackupAuditBase(backupDir, manifest) {
  const errors = [];
  const comp = Object.fromEntries((manifest.components || []).filter((c) => c.present).map((c) => [c.name, c]));
  const file = (name) => (comp[name] ? path.join(backupDir, comp[name].archiveFile) : null);
  // archive contents through readArchive (decrypts an encrypted backup; plaintext bytes otherwise).
  const text = (name) => readArchive(backupDir, manifest.encryption || null, comp[name]).toString('utf8');

  let resolvePublicKey = null;
  if (file('checkpointKeys')) {
    try { resolvePublicKey = publicKeyResolverFromKeyFile(text('checkpointKeys')); }
    catch (e) { errors.push(`AUDIT_BASE_UNVERIFIABLE: the backed-up checkpoint key store is unreadable (${e.message})`); }
  }
  const verify = (signed, where) => {
    if (!resolvePublicKey) { errors.push(`AUDIT_BASE_UNVERIFIABLE: ${where} holds a signed base record but the backup has no checkpoint key store to verify it`); return false; }
    const v = verifyCheckpoint(signed, { resolvePublicKey });
    if (!v.ok) { errors.push(`AUDIT_BASE_SIGNATURE_INVALID: ${where}: ${v.reason}`); return false; }
    return true;
  };

  let base = null;
  if (file('auditLogBase')) {
    try { base = JSON.parse(text('auditLogBase')); }
    catch (e) { errors.push(`AUDIT_BASE_UNREADABLE: ${e.message}`); }
    if (base && !verify(base.checkpoint, 'audit.log.base.json')) base = null;
  }
  let state = null;
  if (file('auditLog') && !errors.length) {
    // only the first line is decrypted — never the whole log (that failed above 2 GiB).
    const first = manifest.encryption
      ? readArchiveFirstLine(backupDir, manifest.encryption, comp.auditLog)
      : firstLine(file('auditLog'));
    const c = classifyStart(base, first);
    if (c.error) errors.push(c.error); else state = c.state;
  }

  // pg_dump path: the newest prune row carries the same base record.
  // a pg_dump-format backup carries the newest prune row as a side archive read in the dump's own snapshot.
  const pgDumpFormat = !!manifest.postgres && manifest.postgres.format === 'pg_dump-custom';
  const pgEntry = pgDumpFormat ? manifest.postgres.latestPrune
    : manifest.postgres && Array.isArray(manifest.postgres.tables)
      ? manifest.postgres.tables.find((t) => t.table === 'audit_chain_prunes' && t.present) : null;
  if (pgEntry) {
    let rows = [];
    try {
      const v = JSON.parse(readArchive(backupDir, manifest.encryption || null, pgEntry).toString('utf8'));
      rows = pgDumpFormat ? (v ? [v] : []) : v;
    } catch { rows = []; /* structural errors are reported by verify.js */ }
    const latest = rows.slice().sort((a, b) => Number(b.to_count) - Number(a.to_count))[0];
    if (latest) {
      const br = typeof latest.base_record === 'string' ? JSON.parse(latest.base_record) : latest.base_record;
      if (verify(br && br.checkpoint, 'audit_chain_prunes (pg_dump)') && base) {
        const a = base.checkpoint.payload; const b = br.checkpoint.payload;
        if (a.checkpointId !== b.checkpointId) {
          errors.push(`AUDIT_BASE_BACKUP_INCONSISTENT: the file base record is checkpoint ${a.checkpointId} (entry ${a.chainLength}), the newest pg prune row is ${b.checkpointId} (entry ${b.chainLength})${a.chainLength > b.chainLength ? ' — a prune was interrupted before its PG step; resume scripts/audit/prune.js' : ''}`);
        }
      }
    }
  }
  return { errors, state, checkpointId: base ? base.checkpoint.payload.checkpointId : null };
}

module.exports = { verifyBackupAuditBase, publicKeyResolverFromKeyFile, classifyStart, firstLine };
