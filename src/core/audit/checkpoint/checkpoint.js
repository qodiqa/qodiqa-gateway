'use strict';

/**
 * QODIQA signed audit-chain checkpoints — step 6.
 *
 * A checkpoint vouches for the audit chain up to and including entry `chainLength` (lifetime count of modern
 * entries), whose hash is `headHash`. It is signed with the dedicated checkpoint key (./checkpointKeyStore.js) over
 *
 *     SHA-256( "QODIQA::AUDIT_CHECKPOINT::V1" || stableStringify(canonical payload) )
 *
 * — the same construction the transparency log uses for its entries and roots (src/core/transparency/log.js), so an
 * independent verifier needs only node:crypto, the published public key (checkpointKeyStore.publishedKeys()) and
 * this documented field list. Checkpoints form their own chain (previousCheckpointHash = the payloadHash of the
 * previous checkpoint) and each is anchored as an AUDIT_CHECKPOINT entry in the transparency log (M2).
 *
 * Canonical payload fields (all present; absent values are null):
 *   v                       1
 *   checkpointId            UUID
 *   createdAt               ISO timestamp
 *   chainLength             lifetime modern-entry count covered (entries 1..chainLength)
 *   headHash                hash of entry chainLength
 *   pgSeq                   audit_chain seq of that entry (null in file-only deployments)
 *   evidenceHead            { id, hash } of the evidence chain at that point, or null
 *   transparencyAnchor      { rootId, rootHash, seqTo } — the latest signed transparency root BEFORE this checkpoint,
 *                           or null (the checkpoint's own AUDIT_CHECKPOINT leaf lands in a later root)
 *   previousCheckpointHash  payloadHash of the previous checkpoint, or null for the first
 *   keyId, keyVersion       the signing key
 */

const crypto = require('crypto');
const stableStringify = require('../../../utils/stableStringify');
const { sign: ed25519Sign, verify: ed25519Verify } = require('../../../infra/crypto/ed25519');

const CHECKPOINT_DOMAIN = 'QODIQA::AUDIT_CHECKPOINT::V1';
const CANONICAL_FIELDS = Object.freeze(['v', 'checkpointId', 'createdAt', 'chainLength', 'headHash', 'pgSeq', 'evidenceHead',
  'transparencyAnchor', 'previousCheckpointHash', 'keyId', 'keyVersion']);
const HASH_RE = /^[0-9a-f]{64}$/;

function canonicalPayload(p) {
  const c = {};
  for (const f of CANONICAL_FIELDS) c[f] = p[f] === undefined ? null : p[f];
  return c;
}

/** 32-byte signing digest. */
function checkpointDigest(payload) {
  return crypto.createHash('sha256').update(CHECKPOINT_DOMAIN, 'utf8').update(stableStringify(canonicalPayload(payload)), 'utf8').digest();
}

/**
 * Sign a checkpoint for chain position chainLength / headHash with the active checkpoint key.
 * @returns {{ payload: object, payloadHash: string, signature: string }}
 */
function signCheckpoint(fields, { keyStore = require('./checkpointKeyStore') } = {}) {
  if (!Number.isInteger(fields.chainLength) || fields.chainLength < 1) throw new Error('signCheckpoint: chainLength must be a positive integer');
  if (!HASH_RE.test(fields.headHash || '')) throw new Error('signCheckpoint: headHash must be a 64-hex hash');
  const key = keyStore.ensureActiveKey();
  const payload = canonicalPayload({
    v: 1,
    checkpointId: fields.checkpointId || crypto.randomUUID(),
    createdAt: fields.createdAt || new Date().toISOString(),
    chainLength: fields.chainLength,
    headHash: fields.headHash,
    pgSeq: fields.pgSeq ?? null,
    evidenceHead: fields.evidenceHead ?? null,
    transparencyAnchor: fields.transparencyAnchor ?? null,
    previousCheckpointHash: fields.previousCheckpointHash ?? null,
    keyId: key.keyId,
    keyVersion: key.version,
  });
  const digest = checkpointDigest(payload);
  return { payload, payloadHash: digest.toString('hex'), signature: ed25519Sign(digest, key.privDer) };
}

/**
 * Verify a signed checkpoint. Never throws.
 * @param {{ payload, payloadHash, signature }} signed
 * @param {{ resolvePublicKey?: (keyId) => Buffer|{pubDer, status?, retiredAt?} }} [opts]  default: the checkpoint key
 *        store (deprecated keys verify what they signed before retirement; revoked/unknown keys fail)
 * @returns {{ ok: boolean, reason?: string }}
 */
function verifyCheckpoint(signed, { resolvePublicKey } = {}) {
  try {
    if (!signed || typeof signed !== 'object' || !signed.payload || typeof signed.signature !== 'string') return { ok: false, reason: 'CHECKPOINT_MALFORMED' };
    const p = signed.payload;
    if (p.v !== 1) return { ok: false, reason: 'CHECKPOINT_UNSUPPORTED_VERSION' };
    for (const f of CANONICAL_FIELDS) if (!(f in p)) return { ok: false, reason: `CHECKPOINT_FIELD_MISSING:${f}` };
    if (Object.keys(p).some((k) => !CANONICAL_FIELDS.includes(k))) return { ok: false, reason: 'CHECKPOINT_UNKNOWN_FIELD' };
    if (!Number.isInteger(p.chainLength) || p.chainLength < 1 || !HASH_RE.test(p.headHash || '')) return { ok: false, reason: 'CHECKPOINT_POSITION_INVALID' };
    const digest = checkpointDigest(p);
    if (signed.payloadHash !== digest.toString('hex')) return { ok: false, reason: 'CHECKPOINT_PAYLOAD_HASH_MISMATCH' };
    let key;
    try {
      key = resolvePublicKey ? resolvePublicKey(p.keyId) : require('./checkpointKeyStore').getPublicKey(p.keyId);
    } catch (e) { return { ok: false, reason: `CHECKPOINT_KEY_UNAVAILABLE: ${e.message}` }; }
    // A resolver may return the bare public key (offline verifiers) or the key record { pubDer, status, retiredAt }.
    const pubDer = Buffer.isBuffer(key) ? key : key && key.pubDer;
    if (!ed25519Verify(digest, signed.signature, pubDer)) return { ok: false, reason: 'CHECKPOINT_SIGNATURE_INVALID' };
    // a deprecated (gracefully retired) key keeps verifying the checkpoints it signed
    // while it was active, but never one whose signed createdAt is after its retirement (same millisecond = signed while active) — before this a retired
    // key verified newly signed checkpoints forever. Historical semantics (keyLifecycle.checkHistorical), not the 65 s
    // execution window: an old checkpoint must stay verifiable for as long as its key is published.
    if (!Buffer.isBuffer(key) && key && key.status === 'deprecated') {
      const retired = Date.parse(key.retiredAt || '');
      const signedAt = Date.parse(p.createdAt || '');
      if (!Number.isFinite(retired)) return { ok: false, reason: 'CHECKPOINT_KEY_RETIRED: retirement time unknown' };
      // a genuine retirement is stamped at rotation
      // time, so it is never in the future beyond clock skew. A far-future retiredAt is injected public metadata that
      // would let a 'deprecated' key verify newly forged checkpoints indefinitely — refused.
      if (retired > Date.now() + 5000) return { ok: false, reason: 'CHECKPOINT_KEY_RETIRED: retirement time is in the future' };
      if (!Number.isFinite(signedAt) || signedAt > retired) return { ok: false, reason: 'CHECKPOINT_KEY_RETIRED: signed after the key was retired' };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `CHECKPOINT_VERIFY_ERROR: ${e.message}` };
  }
}

module.exports = { CHECKPOINT_DOMAIN, CANONICAL_FIELDS, canonicalPayload, checkpointDigest, signCheckpoint, verifyCheckpoint };
