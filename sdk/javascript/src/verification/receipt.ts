/**
 * Offline verification of a signed receipt.
 *
 * A receipt `{ v, requestId, decision, issuedAt, entryHash, leafHash, keyId, signature }` proves that the gateway RECORDED a decision (the audit
 * DECISION entry named by `entryHash` and the transparency leaf named by `leafHash`) — not that the decision was correct. `signature` is
 * `base64(Ed25519.sign(SHA-256("QODIQA::RECEIPT::V1" || JCS-P1(receipt without signature))))` by a TRANSPARENCY key. The receipt carries only strings
 * and one integer, so its JCS-P1 form is the sorted-key compact JSON this SDK's canonicalizer produces.
 *
 * Fully offline: no network, no dependence on the server's own verdict. A receipt signed by a key that is now revoked verifies only in the timed
 * mode (`trustedAt` from an independent authority, before the key's `revokedAt`).
 *
 * @module
 */

import { stableStringify } from './canonicalJson.js';
import { domainSeparatedHash } from './domainHash.js';
import { verifyEd25519 } from './ed25519.js';
import type { Receipt } from '../types.js';

export const RECEIPT_DOMAIN = 'QODIQA::RECEIPT::V1';
const FIELDS = ['v', 'requestId', 'decision', 'issuedAt', 'entryHash', 'leafHash', 'keyId', 'signature'] as const;
const HEX64 = /^[0-9a-f]{64}$/;

/** One transparency key as served by `GET /.well-known/qodiqa/transparency-keys` (`publicKey` = base64 SPKI DER). */
export interface ReceiptKey {
  keyId: string;
  publicKey: string;
  status?: string;
  /** When the key was revoked (ms since epoch or an ISO date); needed for the timed mode. */
  revokedAt?: number | string | null;
}

export type ReceiptVerifyReason =
  | 'NOT_AN_OBJECT' | 'FIELD_SET' | 'UNSUPPORTED_VERSION' | 'INVALID_FIELD' | 'UNKNOWN_KEY' | 'BAD_SIGNATURE' | 'REVOKED_KEY';

export interface ReceiptVerifyResult {
  ok: boolean;
  reason: ReceiptVerifyReason | null;
}

export interface ReceiptVerifyOptions {
  /** Timed mode for a receipt signed by a since-revoked key: a time (ms) attested by an independent authority; accepted only before `revokedAt`. */
  trustedAt?: number;
}

export interface ReceiptBinding {
  entryHash?: string;
  leafHash?: string;
  requestId?: string;
  decision?: 'ALLOW' | 'BLOCK';
}

/** The 32-byte digest that is signed. Throws `CanonicalizationError` only for a value that cannot be a receipt. */
export function receiptDigest(receipt: Omit<Receipt, 'signature'> | Receipt): Buffer {
  const unsigned: Record<string, unknown> = { ...(receipt as Receipt) };
  delete unsigned.signature;
  return domainSeparatedHash(RECEIPT_DOMAIN, stableStringify(unsigned));
}

function keyList(keys: ReceiptKey[] | { keys: ReceiptKey[] }): ReceiptKey[] {
  return Array.isArray(keys) ? keys : keys && Array.isArray(keys.keys) ? keys.keys : [];
}

/**
 * Verify a receipt against transparency keys. Never throws; fails closed (an unknown key, a malformed receipt or a bad signature is `ok: false`).
 */
export function verifyReceipt(
  receipt: unknown,
  keys: ReceiptKey[] | { keys: ReceiptKey[] },
  options: ReceiptVerifyOptions = {},
): ReceiptVerifyResult {
  if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) return { ok: false, reason: 'NOT_AN_OBJECT' };
  const r = receipt as Record<string, unknown>;
  if (Object.keys(r).sort().join(',') !== [...FIELDS].sort().join(',')) return { ok: false, reason: 'FIELD_SET' };
  if (r.v !== 1) return { ok: false, reason: 'UNSUPPORTED_VERSION' };
  const invalid =
    typeof r.requestId !== 'string' || r.requestId === '' ||
    (r.decision !== 'ALLOW' && r.decision !== 'BLOCK') ||
    typeof r.issuedAt !== 'number' || !Number.isSafeInteger(r.issuedAt) || r.issuedAt < 0 ||
    typeof r.entryHash !== 'string' || !HEX64.test(r.entryHash) ||
    typeof r.leafHash !== 'string' || !HEX64.test(r.leafHash) ||
    typeof r.keyId !== 'string' || r.keyId === '' ||
    typeof r.signature !== 'string' || r.signature === '';
  if (invalid) return { ok: false, reason: 'INVALID_FIELD' };

  const key = keyList(keys).find((k) => k && k.keyId === r.keyId);
  if (!key) return { ok: false, reason: 'UNKNOWN_KEY' };
  let good = false;
  // one spelling per signature: only the canonical base64 encoding of the 64 signature bytes is accepted
  const canonicalSig = Buffer.from(r.signature as string, 'base64').toString('base64') === r.signature;
  try { good = canonicalSig && verifyEd25519(receiptDigest(r as unknown as Receipt), r.signature as string, Buffer.from(String(key.publicKey), 'base64')); } catch { good = false; }
  if (!good) return { ok: false, reason: 'BAD_SIGNATURE' };

  if (String(key.status ?? '').toLowerCase() === 'revoked') {
    const revokedAt = typeof key.revokedAt === 'number' ? key.revokedAt : key.revokedAt ? Date.parse(String(key.revokedAt)) : NaN;
    if (typeof options.trustedAt !== 'number' || !Number.isFinite(options.trustedAt) || !Number.isFinite(revokedAt) || !(options.trustedAt < revokedAt)) {
      return { ok: false, reason: 'REVOKED_KEY' };
    }
  }
  return { ok: true, reason: null };
}

/** Does the receipt name exactly the audit entry / leaf / request / decision the caller already holds? Lists the fields that differ. */
export function receiptBindsTo(receipt: Receipt, expected: ReceiptBinding): { ok: boolean; mismatches: string[] } {
  const mismatches: string[] = [];
  for (const f of ['entryHash', 'leafHash', 'requestId', 'decision'] as const) {
    if (expected[f] !== undefined && receipt[f] !== expected[f]) mismatches.push(f);
  }
  return { ok: mismatches.length === 0, mismatches };
}
