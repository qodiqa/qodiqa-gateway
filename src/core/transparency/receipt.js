'use strict';

/**
 * Signed receipt.
 *
 *   receipt = { v: 1, requestId, decision, issuedAt, entryHash, leafHash, keyId, signature }
 *
 * A receipt proves that the gateway RECORDED a decision (an audit DECISION entry and its transparency leaf), not that the
 * decision was correct. It carries nothing but the outcome: no tenantId, no reason (the unauthenticated retrieval
 * endpoint returns it to anyone who knows the requestId).
 *
 *   entryHash  hash of the audit DECISION entry of that request          (64 hex)
 *   leafHash   RFC 6962 leaf hash of the transparency leaf registered for it (64 hex)
 *   keyId      a TRANSPARENCY key (never an artifact key)
 *   signature  base64( Ed25519.sign( SHA-256( "QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature) ) ) )
 *
 * Issued once, when the response is produced, and never re-signed. It exists only for a PERSISTED leaf: the callers pass
 * no receipt for a pending / unpersisted one (the field is then absent from the response, never null).
 */

const { domainSeparatedHash, ARTIFACT_DOMAINS } = require('../../infra/crypto/hashing');
const { canonicalJcsP1 } = require('../../validation/jcsP1');
const { getTransparencySigner } = require('./transparencySigner');

const RECEIPT_VERSION = 1;
const HEX64 = /^[0-9a-f]{64}$/;
const DECISIONS = Object.freeze(['ALLOW', 'BLOCK']);
const FIELDS = Object.freeze(['v', 'requestId', 'decision', 'issuedAt', 'entryHash', 'leafHash', 'keyId', 'signature']);

class ReceiptError extends Error {
  constructor(code, message) { super(message); this.name = 'ReceiptError'; this.code = code; }
}

/** The 32-byte digest that is signed: domain-separated, over the JCS-P1 form of the receipt without its signature. */
function receiptDigest(doc) {
  const { signature: _omit, ...unsigned } = doc;
  return domainSeparatedHash(ARTIFACT_DOMAINS.RECEIPT, canonicalJcsP1(unsigned));
}

function _validateUnsigned({ requestId, decision, issuedAt, entryHash, leafHash }) {
  if (typeof requestId !== 'string' || !requestId) throw new ReceiptError('RECEIPT_INVALID', 'requestId must be a non-empty string');
  if (!DECISIONS.includes(decision)) throw new ReceiptError('RECEIPT_INVALID', 'decision must be ALLOW or BLOCK');
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) throw new ReceiptError('RECEIPT_INVALID', 'issuedAt must be a non-negative integer (ms)');
  if (typeof entryHash !== 'string' || !HEX64.test(entryHash)) throw new ReceiptError('RECEIPT_INVALID', 'entryHash must be 64 lowercase hex');
  if (typeof leafHash !== 'string' || !HEX64.test(leafHash)) throw new ReceiptError('RECEIPT_INVALID', 'leafHash must be 64 lowercase hex');
}

/**
 * Sign a receipt with the active transparency key.
 *
 * @param {{ requestId: string, decision: 'ALLOW'|'BLOCK', entryHash: string, leafHash: string, now?: number }} f
 * @returns {Promise<object>} the receipt (all eight fields)
 * @throws {ReceiptError} RECEIPT_INVALID for a malformed field; any signer failure propagates (no key, signing error)
 */
async function issueReceipt({ requestId, decision, entryHash, leafHash, now = Date.now() }) {
  _validateUnsigned({ requestId, decision, issuedAt: now, entryHash, leafHash });
  const signer = getTransparencySigner();
  // keyId is part of the signed document, so it must be known before signing; if the active key rotates in between,
  // the signer reports the key it actually used and the document is rebuilt once with that key.
  let keyId = signer.getActiveKeyInfo().keyId;
  for (let attempt = 0; attempt < 2; attempt++) {
    const doc = { v: RECEIPT_VERSION, requestId, decision, issuedAt: now, entryHash, leafHash, keyId };
    const signed = await signer.sign(receiptDigest(doc));
    if (signed.keyId === keyId) return { ...doc, signature: signed.signature };
    keyId = signed.keyId;
  }
  throw new ReceiptError('RECEIPT_SIGNING_KEY_UNSTABLE', 'the active transparency key changed twice while signing a receipt');
}

/**
 * Verify a receipt against the transparency key store. Never throws.
 * @returns {{ ok: boolean, reason: string|null }}
 */
function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) return { ok: false, reason: 'NOT_AN_OBJECT' };
  const keys = Object.keys(receipt).sort();
  if (keys.join(',') !== [...FIELDS].sort().join(',')) return { ok: false, reason: 'FIELD_SET' };
  if (receipt.v !== RECEIPT_VERSION) return { ok: false, reason: 'UNSUPPORTED_VERSION' };
  try { _validateUnsigned(receipt); } catch { return { ok: false, reason: 'INVALID_FIELD' }; }
  if (typeof receipt.keyId !== 'string' || !receipt.keyId || typeof receipt.signature !== 'string' || !receipt.signature) return { ok: false, reason: 'INVALID_FIELD' };
  // one spelling per signature: padding, alphabet, whitespace and trailing bits are exactly those of a canonical base64 encoding
  if (Buffer.from(receipt.signature, 'base64').toString('base64') !== receipt.signature) return { ok: false, reason: 'BAD_SIGNATURE' };
  let digest;
  try { digest = receiptDigest(receipt); } catch { return { ok: false, reason: 'INVALID_FIELD' }; }
  return getTransparencySigner().verify(digest, receipt.signature, receipt.keyId) ? { ok: true, reason: null } : { ok: false, reason: 'BAD_SIGNATURE' };
}

module.exports = { issueReceipt, verifyReceipt, receiptDigest, ReceiptError, RECEIPT_VERSION, FIELDS };
