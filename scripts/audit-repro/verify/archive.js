'use strict';

/**
 * Independent verifier — sealed audit archive exports (scripts/audit/archive-export.js) and their append-only index.
 * NO src/ import, Node built-ins and the sibling verifier modules only. Restated from the documented format:
 *
 *   <dir>/manifest.json, checkpoint.json, audit.log.segment [, prior-base.json]   a prune-compatible archive (checkpoint.verifyArchive)
 *   <dir>/seal.json  { v:1, manifestSha256, keyId, signature, sealedAt }
 *       signature = Ed25519( SHA-256( "QODIQA::AUDIT_ARCHIVE_SEAL::V1" || manifestSha256 ) ), base64, by an audit-checkpoint key
 *   <root>/archive-index.jsonl  { seq, exportedAt, checkpointId, from, to, manifestSha256, sealKeyId, prevEntryHash, entryHash } per export,
 *       entryHash = SHA-256( JSON of the record without entryHash, keys in this order ), prevEntryHash chains to the previous entry ("GENESIS" first)
 *
 * Codes: ARCHIVE_* (from checkpoint.verifyArchive), SEAL_MISSING, SEAL_MALFORMED, SEAL_MANIFEST_MISMATCH (the manifest changed after sealing),
 *        SEAL_KEY_UNKNOWN / SEAL_KEY_REVOKED, SEAL_SIGNATURE_INVALID, INDEX_MALFORMED, INDEX_SEQ, INDEX_LINK_BROKEN, INDEX_ENTRY_HASH,
 *        INDEX_ARCHIVE_INVALID, INDEX_ARCHIVE_MANIFEST_MISMATCH. An archive that is absent (moved to cold storage) is listed, not failed.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const checkpoint = require('./checkpoint');

const SEAL_DOMAIN = 'QODIQA::AUDIT_ARCHIVE_SEAL::V1';
const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;

function verifyExport(dir, resolve) {
  const r = checkpoint.verifyArchive(dir, resolve, null);
  if (!r.valid) return r;
  const fail = (reason) => Object.assign(r, { valid: false, reason });
  const sealPath = path.join(dir, 'seal.json');
  if (!fs.existsSync(sealPath)) return fail('SEAL_MISSING');
  let seal; try { seal = JSON.parse(fs.readFileSync(sealPath, 'utf8')); } catch { return fail('SEAL_MALFORMED'); }
  if (!seal || seal.v !== 1 || !HEX64.test(String(seal.manifestSha256)) || typeof seal.keyId !== 'string' || typeof seal.signature !== 'string') return fail('SEAL_MALFORMED');
  if (sha256(fs.readFileSync(path.join(dir, 'manifest.json'))) !== seal.manifestSha256) return fail('SEAL_MANIFEST_MISMATCH');
  let pub;
  try { pub = resolve(seal.keyId); } catch (e) { return fail(String(e.message).startsWith('KEY_REVOKED') ? 'SEAL_KEY_REVOKED' : 'SEAL_KEY_UNKNOWN'); }
  const sig = Buffer.from(seal.signature, 'base64');
  const digest = crypto.createHash('sha256').update(SEAL_DOMAIN, 'utf8').update(seal.manifestSha256, 'utf8').digest();
  let ok = false;
  try { ok = sig.length === 64 && crypto.verify(null, digest, crypto.createPublicKey({ key: pub, format: 'der', type: 'spki' }), sig); } catch { ok = false; }
  if (!ok) return fail('SEAL_SIGNATURE_INVALID');
  r.sealKeyId = seal.keyId; r.manifestSha256 = seal.manifestSha256;
  return r;
}

const entryHashOf = (rec) => sha256(JSON.stringify({ seq: rec.seq, exportedAt: rec.exportedAt, checkpointId: rec.checkpointId, from: rec.from, to: rec.to,
  manifestSha256: rec.manifestSha256, sealKeyId: rec.sealKeyId, prevEntryHash: rec.prevEntryHash }));

/** @returns {{ valid, findings: {seq, code, detail?}[], exports: number, missingArchives: string[] }} */
function verifyIndex(root, resolve) {
  const findings = []; const missing = [];
  const f = (seq, code, detail) => findings.push({ seq, code, ...(detail ? { detail } : {}) });
  const file = path.join(root, 'archive-index.jsonl');
  if (!fs.existsSync(file)) return { valid: true, findings, exports: 0, missingArchives: missing };
  const recs = [];
  for (const [i, line] of fs.readFileSync(file, 'utf8').split('\n').entries()) {
    if (!line) continue;
    try { recs.push(JSON.parse(line)); } catch { f(i + 1, 'INDEX_MALFORMED', `line ${i + 1} is not JSON`); }
  }
  let prev = 'GENESIS';
  recs.forEach((r, i) => {
    if (r.seq !== i + 1) f(r.seq, 'INDEX_SEQ', `entry ${i + 1} has seq ${r.seq}`);
    if (r.prevEntryHash !== prev) f(r.seq, 'INDEX_LINK_BROKEN');
    if (r.entryHash !== entryHashOf(r)) f(r.seq, 'INDEX_ENTRY_HASH');
    prev = r.entryHash;
    if (typeof r.checkpointId !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(r.checkpointId) || r.checkpointId.includes('..')) { f(r.seq, 'INDEX_MALFORMED', 'checkpointId is not a plain id'); return; }   // D-10: never a path
    const dir = path.join(root, `export-${r.checkpointId}`);
    if (!fs.existsSync(dir)) { missing.push(r.checkpointId); return; }
    const v = verifyExport(dir, resolve);
    if (!v.valid) f(r.seq, 'INDEX_ARCHIVE_INVALID', v.reason);
    else if (v.manifestSha256 !== r.manifestSha256) f(r.seq, 'INDEX_ARCHIVE_MANIFEST_MISMATCH');
    else if (!v.from || !v.to || r.from.count !== v.from.count || r.from.hash !== v.from.hash || r.to.count !== v.to.count || r.to.hash !== v.to.hash) f(r.seq, 'INDEX_ARCHIVE_RANGE_MISMATCH');   // D-10: the entry states the range the sealed archive really covers
  });
  return { valid: findings.length === 0, findings, exports: recs.length, missingArchives: missing };
}

module.exports = { SEAL_DOMAIN, verifyExport, verifyIndex, entryHashOf };
