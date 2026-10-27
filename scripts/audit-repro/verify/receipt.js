'use strict';

/**
 * Independent receipt verifier. Imports nothing from src/ and no npm
 * package: Node built-ins only, like its siblings in this directory. The rules are restated from the document, so the
 * differential test holds it and production to one verdict.
 *
 *   receipt = { v: 1, requestId, decision, issuedAt, entryHash, leafHash, keyId, signature }
 *   signature = base64( Ed25519.sign( SHA-256( "QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature) ) ) )
 *
 * A receipt proves that the gateway RECORDED a decision (the audit DECISION entry named by entryHash and the transparency
 * leaf named by leafHash), nothing about whether the decision was right. A receipt signed by a revoked key verifies only
 * in the timed mode: pass `trustedAt` (ms, from an independent authority) and the key's `revokedAt`.
 */

const crypto = require('crypto');

const DOMAIN = 'QODIQA::RECEIPT::V1';
const FIELDS = ['v', 'requestId', 'decision', 'issuedAt', 'entryHash', 'leafHash', 'keyId', 'signature'];
const HEX64 = /^[0-9a-f]{64}$/;

/** JCS-P1 for the receipt: only strings and one non-negative integer, so RFC 8785 reduces to sorted keys and JSON strings. */
function canonicalUnsigned(r) {
  const o = {};
  for (const k of Object.keys(r).filter((x) => x !== 'signature').sort()) o[k] = r[k];
  return JSON.stringify(o);
}

function digestOf(r) {
  return crypto.createHash('sha256').update(DOMAIN, 'utf8').update(canonicalUnsigned(r), 'utf8').digest();
}

function keyList(keys) {
  return Array.isArray(keys) ? keys : (keys && Array.isArray(keys.keys) ? keys.keys : []);
}

/**
 * @param {object} receipt
 * @param {object|Array} keys   body of GET /.well-known/qodiqa/transparency-keys: [{ keyId, publicKey (base64 SPKI DER), status, revokedAt? }]
 * @param {{ trustedAt?: number }} [opts]
 * @returns {{ ok: boolean, reason: string|null }}
 */
function verifyReceiptDocument(receipt, keys, opts = {}) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return { ok: false, reason: 'NOT_AN_OBJECT' };
  if (Object.keys(receipt).sort().join(',') !== [...FIELDS].sort().join(',')) return { ok: false, reason: 'FIELD_SET' };
  if (receipt.v !== 1) return { ok: false, reason: 'UNSUPPORTED_VERSION' };
  const bad = typeof receipt.requestId !== 'string' || !receipt.requestId
    || !['ALLOW', 'BLOCK'].includes(receipt.decision)
    || !Number.isSafeInteger(receipt.issuedAt) || receipt.issuedAt < 0
    || !HEX64.test(String(receipt.entryHash)) || !HEX64.test(String(receipt.leafHash))
    || typeof receipt.keyId !== 'string' || !receipt.keyId || typeof receipt.signature !== 'string' || !receipt.signature;
  if (bad) return { ok: false, reason: 'INVALID_FIELD' };
  const key = keyList(keys).find((k) => k && k.keyId === receipt.keyId);
  if (!key) return { ok: false, reason: 'UNKNOWN_KEY' };
  const sig = Buffer.from(receipt.signature, 'base64');
  if (sig.length !== 64 || sig.toString('base64') !== receipt.signature) return { ok: false, reason: 'BAD_SIGNATURE' };
  let good = false;
  try {
    const pub = crypto.createPublicKey({ key: Buffer.from(String(key.publicKey), 'base64'), format: 'der', type: 'spki' });
    good = crypto.verify(null, digestOf(receipt), pub, sig);
  } catch { good = false; }
  if (!good) return { ok: false, reason: 'BAD_SIGNATURE' };
  if (String(key.status || '').toLowerCase() === 'revoked') {
    const revokedAt = Number.isFinite(key.revokedAt) ? key.revokedAt : (key.revokedAt ? Date.parse(key.revokedAt) : NaN);
    if (!Number.isFinite(opts.trustedAt) || !Number.isFinite(revokedAt) || !(opts.trustedAt < revokedAt)) return { ok: false, reason: 'REVOKED_KEY' };
  }
  return { ok: true, reason: null };
}

/** Optional cross-check against evidence the verifier already holds: the receipt must name exactly that audit entry / leaf. */
function bindsTo(receipt, { entryHash, leafHash, requestId, decision } = {}) {
  const mismatches = [];
  if (entryHash !== undefined && receipt.entryHash !== entryHash) mismatches.push('entryHash');
  if (leafHash !== undefined && receipt.leafHash !== leafHash) mismatches.push('leafHash');
  if (requestId !== undefined && receipt.requestId !== requestId) mismatches.push('requestId');
  if (decision !== undefined && receipt.decision !== decision) mismatches.push('decision');
  return { ok: mismatches.length === 0, mismatches };
}

module.exports = { DOMAIN, FIELDS, digestOf, canonicalUnsigned, verifyReceiptDocument, bindsTo };
