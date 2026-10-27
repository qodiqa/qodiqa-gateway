'use strict';

/**
 * independent verifier — step 6 signed audit checkpoints, the signed base record, and prune archives
 *. Restated from the documented contract (src/core/audit/checkpoint/checkpoint.js header,
 *) — NO src/ import, Node built-ins only:
 *
 *   digest    = SHA-256( "QODIQA::AUDIT_CHECKPOINT::V1" || canonical(payload restricted to the 11 fields) )
 *   signature = Ed25519(digest), base64; public key = SPKI DER from the published checkpoint key set
 *   fields    = v, checkpointId, createdAt, chainLength, headHash, pgSeq, evidenceHead, transparencyAnchor,
 *               previousCheckpointHash, keyId, keyVersion     (absent → null; any other field → invalid)
 *
 * A prune archive directory (scripts/audit/prune.js) holds manifest.json (sha256 of every file), checkpoint.json
 * (the signed checkpoint C the prefix ends at), audit.log.segment (the removed NDJSON lines, in order) and, when the
 * log had been pruned before, prior-base.json (the signed base record the segment starts from).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { canonicalize } = require('./canonical');
const contract = require('./auditContract');

const CHECKPOINT_DOMAIN = 'QODIQA::AUDIT_CHECKPOINT::V1';
const FIELDS = ['v', 'checkpointId', 'createdAt', 'chainLength', 'headHash', 'pgSeq', 'evidenceHead', 'transparencyAnchor',
  'previousCheckpointHash', 'keyId', 'keyVersion'];
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Key set → resolver. Accepts the /.well-known/qodiqa/checkpoint-keys body ({keys:[{keyId, publicKey, status}]}),
 * a plain array of those, or a checkpoint key FILE ({keys:{<id>:{publicKeyDer, status}}}). Revoked keys never verify.
 */
function keyResolver(keySet) {
  const map = new Map();
  const list = Array.isArray(keySet) ? keySet : (keySet && keySet.keys);
  if (Array.isArray(list)) {
    for (const k of list) map.set(k.keyId, { pub: k.publicKey || k.publicKeySpkiDerB64, status: k.status });
  } else if (list && typeof list === 'object') {
    for (const [id, k] of Object.entries(list)) map.set(id, { pub: k.publicKeyDer, status: k.status });
  }
  return (keyId) => {
    const k = map.get(keyId);
    if (!k || !k.pub) throw new Error(`KEY_UNKNOWN:${keyId}`);
    if (String(k.status || '').toLowerCase() === 'revoked') throw new Error(`KEY_REVOKED:${keyId}`);
    const der = Buffer.from(k.pub, 'base64');
    if (der.toString('base64') !== k.pub) throw new Error(`KEY_UNKNOWN:${keyId}`);   // gate L-4: a non-canonical key encoding is no key
    return der;
  };
}

function digest(payload) {
  const c = {};
  for (const f of FIELDS) c[f] = payload[f] === undefined ? null : payload[f];
  return crypto.createHash('sha256').update(CHECKPOINT_DOMAIN, 'utf8').update(canonicalize(c), 'utf8').digest();
}

/** @returns {{ok:boolean, reason?:string}} */
function verifySignedCheckpoint(signed, resolve) {
  try {
    if (!signed || typeof signed !== 'object' || !signed.payload || typeof signed.signature !== 'string') return { ok: false, reason: 'CHECKPOINT_MALFORMED' };
    const p = signed.payload;
    if (p.v !== 1) return { ok: false, reason: 'CHECKPOINT_UNSUPPORTED_VERSION' };
    for (const f of FIELDS) if (!(f in p)) return { ok: false, reason: `CHECKPOINT_FIELD_MISSING:${f}` };
    if (Object.keys(p).some((k) => !FIELDS.includes(k))) return { ok: false, reason: 'CHECKPOINT_UNKNOWN_FIELD' };
    if (!Number.isInteger(p.chainLength) || p.chainLength < 1 || !HEX64.test(p.headHash || '')) return { ok: false, reason: 'CHECKPOINT_POSITION_INVALID' };
    const d = digest(p);
    if (signed.payloadHash !== d.toString('hex')) return { ok: false, reason: 'CHECKPOINT_PAYLOAD_HASH_MISMATCH' };
    let pub;
    try { pub = resolve(p.keyId); } catch (e) { return { ok: false, reason: `CHECKPOINT_${e.message}` }; }
    const sig = Buffer.from(signed.signature, 'base64');
    if (sig.toString('base64') !== signed.signature) return { ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' };   // gate L-4: canonical base64 only (as the Python verifier)
    if (sig.length !== 64) return { ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' };
    const ok = crypto.verify(null, d, crypto.createPublicKey({ key: pub, format: 'der', type: 'spki' }), sig);
    return ok ? { ok: true } : { ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' };
  } catch (e) {
    return { ok: false, reason: `CHECKPOINT_VERIFY_ERROR:${e.message}` };
  }
}

const sha256File = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

/**
 * Verify one prune archive. `expectStart` = {hash, count} the segment must start from (GENESIS/0 for the first).
 * @returns {{ valid, reason?, checkpointId, from:{hash,count}, to:{hash,count}, entries }}
 */
function verifyArchive(dir, resolve, expectStart) {
  const out = { dir: path.basename(dir), valid: false, checkpointId: null, from: expectStart, to: null, entries: 0 };
  const fail = (reason, extra = {}) => Object.assign(out, { valid: false, reason }, extra);
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')); } catch (e) { return fail(`ARCHIVE_MANIFEST_UNREADABLE:${e.message}`); }
  for (const [name, meta] of Object.entries(manifest.files || {})) {
    const f = path.join(dir, name);
    if (!fs.existsSync(f)) return fail(`ARCHIVE_FILE_MISSING:${name}`);
    if (sha256File(f) !== meta.sha256) return fail(`ARCHIVE_FILE_SHA256_MISMATCH:${name}`);
  }
  if (!manifest.files || !manifest.files['checkpoint.json'] || !manifest.files['audit.log.segment']) return fail('ARCHIVE_INCOMPLETE');
  const cp = JSON.parse(fs.readFileSync(path.join(dir, 'checkpoint.json'), 'utf8'));
  const v = verifySignedCheckpoint(cp, resolve);
  if (!v.ok) return fail(`ARCHIVE_${v.reason}`);
  out.checkpointId = cp.payload.checkpointId;
  // The segment's start: GENESIS, or the prior base record (itself signed) — and it must be where the caller expects.
  let start = { hash: contract.GENESIS, count: 0 };
  if (manifest.files['prior-base.json']) {
    const pb = JSON.parse(fs.readFileSync(path.join(dir, 'prior-base.json'), 'utf8'));
    const pv = verifySignedCheckpoint(pb && pb.checkpoint, resolve);
    if (!pv.ok) return fail(`ARCHIVE_PRIOR_BASE_${pv.reason}`);
    start = { hash: pb.checkpoint.payload.headHash, count: pb.checkpoint.payload.chainLength };
  }
  if (expectStart && (start.hash !== expectStart.hash || start.count !== expectStart.count)) {
    return fail('ARCHIVE_START_MISMATCH', { expectedStart: expectStart, actualStart: start });
  }
  out.from = start;
  const parsed = contract.parseNdjson(fs.readFileSync(path.join(dir, 'audit.log.segment'), 'utf8'));
  if (!parsed.ok) return fail('ARCHIVE_SEGMENT_MALFORMED_JSON', { line: parsed.line });
  const walk = contract.walkChain(parsed.entries, { startPrevHash: start.hash });
  out.entries = parsed.entries.length;
  if (!walk.valid) return fail(`ARCHIVE_SEGMENT_${walk.reason}`, { failure: walk.failure });
  if (start.count + parsed.entries.length !== cp.payload.chainLength) {
    return fail('ARCHIVE_SEGMENT_LENGTH_MISMATCH', { expected: cp.payload.chainLength - start.count, actual: parsed.entries.length });
  }
  if (walk.tail !== cp.payload.headHash) return fail('ARCHIVE_SEGMENT_DOES_NOT_END_AT_CHECKPOINT');
  out.to = { hash: cp.payload.headHash, count: cp.payload.chainLength };
  out.valid = true;
  return out;
}

module.exports = { CHECKPOINT_DOMAIN, FIELDS, keyResolver, digest, verifySignedCheckpoint, verifyArchive };
